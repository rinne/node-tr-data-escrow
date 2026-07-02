import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createReadStream, readFileSync, readdirSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { promisify } from 'node:util';
import { decrypt as jweDecrypt } from 'tr-jwe';
import { cipherKeyGen, type Jwk } from 'tr-jwk';
import { DataEscrow } from '../src/index';
import {
  DataEscrowDecrypt,
  EscrowIntegrityError,
  UnknownEscrowKeyError,
  UnknownFileIdError,
  type DataEscrowDecryptOperation,
} from '../src/decrypt';
import { encryptTrde } from '../src/trde-encrypt';
import { decryptTrdeToBuffer, decryptTrdeToFile, decryptTrdeToStream } from '../src/trde-decrypt';
import { makeVaultDir, ecEscrowKeys, rsaEscrowKeys, escrowDir, readManifest } from './helpers';

const execFileAsync = promisify(execFile);

/** RSA secret keys from the test helper carry the signing alg; the decrypt
 * class accepts RSA keys only with alg absent or "RSA-OAEP". */
function rsaSecret(secretKey: Jwk): Jwk {
  return { ...secretKey, alg: 'RSA-OAEP' };
}

async function collect(stream: Readable): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

interface BuiltEscrow {
  vaultDir: string;
  dir: string;
  manifest: ReturnType<typeof readManifest>;
  dataId: string;
  fileId: string;
  fileContent: Buffer;
}

/** One escrow with a referenced data item and a referenced file. */
async function buildEscrow(publicKey: Jwk, fileContent?: Buffer): Promise<BuiltEscrow> {
  const vaultDir = makeVaultDir();
  const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
  const op = await esc.createEscrow({
    reference: 'escrow-ref',
    encryptedReference: 'escrow-cref',
    expiresAfter: 3600,
  });
  const dataId = await op.addData(
    { hello: 'world' },
    { reference: 'Data42', encryptedReference: 'sealed-data' },
  );
  const content = fileContent ?? randomBytes(4096);
  const fileId = await op.addFileBuffer(content, {
    name: 'blob.bin',
    reference: 'Image1',
    encryptedReference: 'sealed-file',
  });
  const id = await op.commit();
  const dir = escrowDir(vaultDir, id);
  return { vaultDir, dir, manifest: readManifest(dir), dataId, fileId, fileContent: content };
}

function blobPath(built: BuiltEscrow): string {
  return join(built.dir, 'files', built.fileId);
}

describe('DataEscrowDecrypt constructor', () => {
  const { publicKey, secretKey } = ecEscrowKeys();

  it('accepts a single secret key and an array of them', () => {
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: secretKey })).not.toThrow();
    const other = ecEscrowKeys('P-384').secretKey;
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: [secretKey, other] })).not.toThrow();
  });

  it('rejects invalid configurations', () => {
    // @ts-expect-error options missing
    expect(() => new DataEscrowDecrypt()).toThrow(TypeError);
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: [] })).toThrow(TypeError);
    // public key (no private material) cannot decrypt anything
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: publicKey })).toThrow(TypeError);
    const noKid = { ...secretKey };
    delete (noKid as Record<string, unknown>).kid;
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: noKid })).toThrow(TypeError);
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: [secretKey, secretKey] })).toThrow(
      TypeError,
    );
    expect(
      () => new DataEscrowDecrypt({ escrowSecretKey: { kty: 'oct', k: 'AAAA', kid: 'x', d: 'x' } }),
    ).toThrow(TypeError);
    const { secretKey: rsaRaw } = rsaEscrowKeys(); // alg RS384 present => rejected
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: rsaRaw })).toThrow(TypeError);
    const { secretKey: weak } = rsaEscrowKeys('RS256'); // 1024-bit modulus
    expect(() => new DataEscrowDecrypt({ escrowSecretKey: rsaSecret(weak) })).toThrow(TypeError);
  });
});

describe('decrypt() round-trip', () => {
  for (const [label, keys] of [
    ['EC', () => ecEscrowKeys('P-521')],
    ['RSA', () => rsaEscrowKeys()],
  ] as const) {
    it(`opens a real escrow and augments every payload (${label})`, async () => {
      const { publicKey, secretKey } = keys();
      const built = await buildEscrow(publicKey);
      const dec = new DataEscrowDecrypt({
        escrowSecretKey: label === 'RSA' ? rsaSecret(secretKey) : secretKey,
      });

      const input = JSON.parse(JSON.stringify(built.manifest));
      const snapshot = JSON.parse(JSON.stringify(input));
      const op = await dec.decrypt(input);

      // the input object is never mutated
      expect(input).toEqual(snapshot);
      // originalData(): deep-equal to the input, but a different object
      const original = op.originalData();
      expect(original).toEqual(snapshot);
      expect(original).not.toBe(input);

      const m = op.data();
      // sealed metadata matches the cleartext manifest and carries the extras
      expect(m.metadata.payloadData.id).toBe(built.manifest.metadata.id);
      expect(m.metadata.payloadData.kid).toBe(built.manifest.metadata.kid);
      expect(m.metadata.payloadData.iat).toBe(built.manifest.metadata.iat);
      expect(m.metadata.payloadData.exp).toBe(built.manifest.metadata.exp);
      expect(m.metadata.payloadData.ref).toBe('escrow-ref');
      expect(m.metadata.payloadData.cref).toBe('escrow-cref');
      expect(m.metadata.payloadData.key).toBeTypeOf('object');

      const dataEntry = m.data![built.dataId]!;
      expect(dataEntry.payloadData.data).toEqual({ hello: 'world' });
      expect(dataEntry.payloadData.ref).toBe('Data42');
      expect(dataEntry.payloadData.cref).toBe('sealed-data');
      const fileEntry = m.file![built.fileId]!;
      expect(fileEntry.payloadData.name).toBe('blob.bin');
      expect(fileEntry.payloadData.ref).toBe('Image1');
      expect(fileEntry.payloadData.cref).toBe('sealed-file');
      expect(fileEntry.payloadData.key).toBeTypeOf('object');

      // every payloadContentKey independently re-decrypts its payload token
      for (const entry of [m.metadata, dataEntry, fileEntry]) {
        expect(jweDecrypt(entry.payload, entry.payloadContentKey)).toEqual(entry.payloadData);
      }

      // data() hands out fresh copies
      (m.metadata.payloadData as Record<string, unknown>).id = 'tampered';
      expect(op.data().metadata.payloadData.id).toBe(built.manifest.metadata.id);
    });
  }
});

describe('key selection and decrypt() arguments', () => {
  it('picks the right key by kid from several', async () => {
    const right = ecEscrowKeys();
    const others = [ecEscrowKeys('P-384').secretKey, rsaSecret(rsaEscrowKeys().secretKey)];
    const built = await buildEscrow(right.publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: [...others, right.secretKey] });
    const op = await dec.decrypt(built.manifest);
    expect(op.data().metadata.payloadData.id).toBe(built.manifest.metadata.id);
  });

  it('throws UnknownEscrowKeyError (carrying the kid) when no key matches', async () => {
    const { publicKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: ecEscrowKeys().secretKey });
    const err = await dec.decrypt(built.manifest).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnknownEscrowKeyError);
    expect((err as UnknownEscrowKeyError).kid).toBe(built.manifest.metadata.kid);
  });

  it('rejects malformed manifests and unknown options', async () => {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    await expect(dec.decrypt(null)).rejects.toThrow(TypeError);
    await expect(dec.decrypt('nope')).rejects.toThrow(TypeError);
    await expect(dec.decrypt({})).rejects.toThrow(TypeError);
    await expect(dec.decrypt({ metadata: { kid: 'k' } })).rejects.toThrow(TypeError);
    // @ts-expect-error unknown option key
    await expect(dec.decrypt(built.manifest, { verify: false })).rejects.toThrow(TypeError);
    // @ts-expect-error options must be an object
    await expect(dec.decrypt(built.manifest, 42)).rejects.toThrow(TypeError);
    await expect(dec.decrypt(built.manifest, {})).resolves.toBeTruthy();
  });

  it('rejects a corrupted payload token', async () => {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    const tampered = JSON.parse(JSON.stringify(built.manifest));
    tampered.metadata.payload = tampered.metadata.payload.slice(0, -8) + 'AAAAAAAA';
    await expect(dec.decrypt(tampered)).rejects.toThrow(/metadata payload/);
  });
});

describe('tamper-binding verification', () => {
  async function tamper(
    mutate: (m: ReturnType<typeof readManifest>) => void,
    extraKids: Jwk[] = [],
  ): Promise<unknown> {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: [secretKey, ...extraKids] });
    const m = JSON.parse(JSON.stringify(built.manifest));
    mutate(m);
    return dec.decrypt(m).catch((e: unknown) => e);
  }

  it('detects a tampered metadata id / iat / exp / ref', async () => {
    for (const mutate of [
      (m: any) => { m.metadata.id = '00000000-0000-4000-8000-000000000000'; },
      (m: any) => { m.metadata.iat += 1; },
      (m: any) => { delete m.metadata.exp; },
      (m: any) => { m.metadata.exp += 60; },
      (m: any) => { m.metadata.ref = 'evil'; },
      (m: any) => { delete m.metadata.ref; },
    ]) {
      expect(await tamper(mutate)).toBeInstanceOf(EscrowIntegrityError);
    }
  });

  it('detects a tampered kid (same key registered under the forged kid)', async () => {
    const { publicKey, secretKey: right } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const alias = { ...right, kid: 'forged-kid' };
    const dec = new DataEscrowDecrypt({ escrowSecretKey: [right, alias] });
    const m = JSON.parse(JSON.stringify(built.manifest));
    m.metadata.kid = 'forged-kid';
    const err = await dec.decrypt(m).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EscrowIntegrityError);
    expect((err as EscrowIntegrityError).field).toBe('metadata.kid');
  });

  it('detects a tampered item map key and item ref', async () => {
    const rekey = await tamper((m: any) => {
      const [id, entry] = Object.entries(m.data)[0]!;
      delete m.data[id];
      m.data['11111111-1111-4111-8111-111111111111'] = entry;
    });
    expect(rekey).toBeInstanceOf(EscrowIntegrityError);

    for (const mutate of [
      (m: any) => { Object.values(m.data)[0]!.ref = 'evil'; },
      (m: any) => { delete Object.values(m.data)[0]!.ref; },
      (m: any) => { Object.values(m.file)[0]!.ref = 'evil'; },
    ]) {
      expect(await tamper(mutate)).toBeInstanceOf(EscrowIntegrityError);
    }
  });
});

describe('file decryption via the operation', () => {
  async function opened(fileContent?: Buffer): Promise<{ built: BuiltEscrow; op: DataEscrowDecryptOperation }> {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey, fileContent);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    return { built, op: await dec.decrypt(built.manifest) };
  }

  it('decrypts from all three source forms to a buffer', async () => {
    const { built, op } = await opened();
    const path = blobPath(built);
    expect(await op.decryptFileToBuffer(built.fileId, path)).toEqual(built.fileContent);
    expect(await op.decryptFileToBuffer(built.fileId, readFileSync(path))).toEqual(
      built.fileContent,
    );
    expect(await op.decryptFileToBuffer(built.fileId, createReadStream(path))).toEqual(
      built.fileContent,
    );
  });

  it('decrypts to a stream', async () => {
    const { built, op } = await opened();
    const stream = await op.decryptFileToStream(built.fileId, blobPath(built));
    expect(await collect(stream)).toEqual(built.fileContent);
  });

  it('decrypts atomically to a destination path', async () => {
    const { built, op } = await opened();
    const outDir = join(built.vaultDir, 'out');
    mkdirSync(outDir);
    const dest = join(outDir, 'restored.bin');
    await expect(op.decryptFile(built.fileId, blobPath(built), dest)).resolves.toBe(true);
    expect(readFileSync(dest)).toEqual(built.fileContent);
  });

  it('round-trips every compression mode', async () => {
    const compressible = Buffer.from('abcdefgh'.repeat(8192));
    for (const compression of ['none', 'deflate', 'gzip', 'brotli'] as const) {
      const vaultDir = makeVaultDir();
      const { publicKey, secretKey } = ecEscrowKeys();
      const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
      const wop = await esc.createEscrow();
      const fid = await wop.addFileBuffer(compressible, { name: 'c.bin', compression });
      const id = await wop.commit();
      const dir = escrowDir(vaultDir, id);
      const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
      const op = await dec.decrypt(readManifest(dir));
      expect(await op.decryptFileToBuffer(fid, join(dir, 'files', fid))).toEqual(compressible);
    }
  });

  it('rejects an unknown or non-string fileId with UnknownFileIdError', async () => {
    const { built, op } = await opened();
    const path = blobPath(built);
    const err = await op.decryptFileToBuffer('not-a-file-id', path).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(UnknownFileIdError);
    expect((err as UnknownFileIdError).fileId).toBe('not-a-file-id');
    // @ts-expect-error non-string file id
    await expect(op.decryptFile(42, path, '/dev/null')).rejects.toBeInstanceOf(UnknownFileIdError);
    // @ts-expect-error data ids are not file ids
    await expect(op.decryptFileToStream(built.dataId, path)).rejects.toBeInstanceOf(
      UnknownFileIdError,
    );
  });

  it('a corrupted container rejects everywhere and leaves no destination residue', async () => {
    const { built, op } = await opened();
    const corrupt = readFileSync(blobPath(built));
    corrupt[corrupt.length - 20] ^= 0xff; // flip one ciphertext byte

    await expect(op.decryptFileToBuffer(built.fileId, corrupt)).rejects.toThrow();

    const outDir = join(built.vaultDir, 'out');
    mkdirSync(outDir);
    const dest = join(outDir, 'x.bin');
    await expect(op.decryptFile(built.fileId, corrupt, dest)).rejects.toThrow();
    expect(readdirSync(outDir)).toEqual([]); // no destination, no temp file

    // stream form: header is fine, so the promise resolves; the failure
    // surfaces as a stream error while reading
    const stream = await op.decryptFileToStream(built.fileId, corrupt);
    await expect(collect(stream)).rejects.toThrow();
  });

  it('rejects truncated containers and reserved / unknown compression codes', async () => {
    const { built, op } = await opened();
    const container = readFileSync(blobPath(built));

    await expect(op.decryptFileToBuffer(built.fileId, container.subarray(0, 6))).rejects.toThrow(
      /truncated/,
    );
    await expect(
      op.decryptFileToBuffer(built.fileId, container.subarray(0, container.length - 4)),
    ).rejects.toThrow();

    const zstd = Buffer.from(container);
    zstd[6] = 4;
    await expect(op.decryptFileToBuffer(built.fileId, zstd)).rejects.toThrow(/zstd/);

    const unknownComp = Buffer.from(container);
    unknownComp[6] = 9;
    await expect(op.decryptFileToBuffer(built.fileId, unknownComp)).rejects.toThrow(
      /compression code/,
    );

    const badMagic = Buffer.from(container);
    badMagic[0] = 0x58;
    await expect(op.decryptFileToBuffer(built.fileId, badMagic)).rejects.toThrow(/magic/);
  });
});

describe('destroy() semantics', () => {
  it('operation destroy clears everything and is idempotent', async () => {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    const op = await dec.decrypt(built.manifest);
    op.destroy();
    op.destroy(); // idempotent
    expect(() => op.originalData()).toThrow(TypeError);
    expect(() => op.data()).toThrow(TypeError);
    await expect(op.decryptFileToBuffer(built.fileId, blobPath(built))).rejects.toThrow(TypeError);
    // the parent decryptor is unaffected
    const op2 = await dec.decrypt(built.manifest);
    expect(op2.data().metadata.payloadData.id).toBe(built.manifest.metadata.id);
  });

  it('decryptor destroy blocks decrypt() but not already-returned operations', async () => {
    const { publicKey, secretKey } = ecEscrowKeys();
    const built = await buildEscrow(publicKey);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    const op = await dec.decrypt(built.manifest);
    dec.destroy();
    dec.destroy(); // idempotent
    await expect(dec.decrypt(built.manifest)).rejects.toThrow(TypeError);
    // the operation holds its own key material and keeps working
    expect(op.data().metadata.payloadData.id).toBe(built.manifest.metadata.id);
    expect(await op.decryptFileToBuffer(built.fileId, blobPath(built))).toEqual(built.fileContent);
  });
});

describe('TRDE codec (class-independent)', () => {
  const key = cipherKeyGen('A256GCM');

  it('encryptTrde -> decryptTrdeTo* round-trips for every compression mode', async () => {
    const content = Buffer.concat([Buffer.from('codec '.repeat(1000)), randomBytes(500)]);
    for (const compression of ['none', 'deflate', 'gzip', 'brotli'] as const) {
      const container = await collect(encryptTrde(Readable.from(content), key, compression));
      expect(container.subarray(0, 4).toString('ascii')).toBe('TRDE');
      expect(await decryptTrdeToBuffer(container, key)).toEqual(content);
      expect(await collect(await decryptTrdeToStream(container, key))).toEqual(content);
    }
  });

  it('decryptTrdeToFile writes atomically; a wrong key never produces output', async () => {
    const dir = makeVaultDir();
    const content = randomBytes(2048);
    const container = await collect(encryptTrde(Readable.from(content), key, 'gzip'));
    const dest = join(dir, 'plain.bin');
    await expect(decryptTrdeToFile(container, key, dest)).resolves.toBe(true);
    expect(readFileSync(dest)).toEqual(content);

    const wrongKey = cipherKeyGen('A256GCM');
    const dest2 = join(dir, 'never.bin');
    await expect(decryptTrdeToFile(container, wrongKey, dest2)).rejects.toThrow();
    expect(readdirSync(dir).sort()).toEqual(['plain.bin']);
    await expect(decryptTrdeToBuffer(container, wrongKey)).rejects.toThrow();
  });

  it('handles empty plaintext', async () => {
    const container = await collect(encryptTrde(Readable.from(Buffer.alloc(0)), key, 'none'));
    expect(await decryptTrdeToBuffer(container, key)).toEqual(Buffer.alloc(0));
  });

  it('validates the content key JWK', async () => {
    const container = await collect(encryptTrde(Readable.from(Buffer.from('x')), key, 'none'));
    await expect(decryptTrdeToBuffer(container, {})).rejects.toThrow(TypeError);
    await expect(decryptTrdeToBuffer(container, { k: 'AAAA' })).rejects.toThrow(TypeError);
  });
});

describe('writer / decrypt module separation', () => {
  it('require("tr-data-escrow") loads zero decrypt code', async () => {
    const indexJs = resolve(__dirname, '..', 'dist', 'index.js');
    const script =
      `require(${JSON.stringify(indexJs)});` +
      `const bad = Object.keys(require.cache).filter((p) => /decrypt/.test(p));` +
      `if (bad.length) { console.error(bad.join('\\n')); process.exit(1); }`;
    await expect(execFileAsync(process.execPath, ['-e', script])).resolves.toBeTruthy();
  });

  it('the decrypt subpath entry exposes the reader API', async () => {
    const decryptJs = resolve(__dirname, '..', 'dist', 'decrypt.js');
    const script =
      `const d = require(${JSON.stringify(decryptJs)});` +
      `if (typeof d.DataEscrowDecrypt !== 'function') process.exit(1);` +
      `if (typeof d.UnknownEscrowKeyError !== 'function') process.exit(1);` +
      `if (typeof d.UnknownFileIdError !== 'function') process.exit(1);` +
      `if (typeof d.EscrowIntegrityError !== 'function') process.exit(1);`;
    await expect(execFileAsync(process.execPath, ['-e', script])).resolves.toBeTruthy();
  });
});
