import { describe, expect, it } from 'vitest';
import { existsSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { randomBytes } from 'node:crypto';
import { DataEscrow, ReferenceConflictError } from '../src/index';
import {
  makeVaultDir,
  ecEscrowKeys,
  rsaEscrowKeys,
  mlKemEscrowKeys,
  escrowDir,
  readManifest,
  openEscrow,
  readVaultFileHeader,
} from './helpers';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('escrow() one-shot + full round-trip', () => {
  it('stores a single data item that decrypts with the private key (EC)', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const value = { secret: 'foo', arr: [1, 2, 3], n: null };
    const before = Math.floor(Date.now() / 1000);
    const id = await esc.escrow(value, { reference: 'one-shot-1' });
    expect(id).toMatch(UUID_RE);

    const dir = escrowDir(vaultDir, id);
    const m = readManifest(dir);
    expect(m.metadata.id).toBe(id);
    expect(m.metadata.kid).toBe(publicKey.kid);
    expect(m.metadata.ref).toBe('one-shot-1');
    expect(m.metadata.iat).toBeGreaterThanOrEqual(before);
    expect(m.metadata.exp).toBeUndefined();

    const opened = openEscrow(dir, secretKey);
    // sealed metadata binds the cleartext fields
    expect(opened.metadata.id).toBe(id);
    expect(opened.metadata.kid).toBe(publicKey.kid);
    expect(opened.metadata.iat).toBe(m.metadata.iat);
    expect(opened.metadata.ref).toBe('one-shot-1');
    expect(opened.data.map((d) => d.data)).toEqual([value]);
    expect(opened.files).toEqual([]);
  });

  it('accepts any JSON-serializable value including null', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    for (const v of [null, true, 42, 'hi', [1, 2]]) {
      const id = await esc.escrow(v);
      expect(openEscrow(escrowDir(vaultDir, id), secretKey).data.map((d) => d.data)).toEqual([v]);
    }
  });

  it('rejects undefined / non-serializable data and leaves .tmp empty', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.escrow(undefined)).rejects.toThrow(TypeError);
    await expect(esc.escrow(10n)).rejects.toThrow(TypeError);
    await expect(esc.escrow(() => 1)).rejects.toThrow(TypeError);
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
  });
});

describe('createEscrow() builder + files', () => {
  it('round-trips data items and files (path, stream, buffer) with refs and crefs — EC', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = ecEscrowKeys('P-521');
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const op = await esc.createEscrow({
      reference: 'case-7',
      encryptedReference: 'hidden-escrow-ref',
    });
    expect(op.state).toBe('pending');
    expect(op.id).toMatch(UUID_RE);

    const d1 = await op.addData({ a: 1 }, { reference: 'Data42', encryptedReference: 'sealed-1' });
    const d2 = await op.addData({ b: 2 });
    expect(d1).toMatch(UUID_RE);
    expect(d1).not.toBe(d2);

    const bufContent = randomBytes(2048);
    const f1 = await op.addFileBuffer(bufContent, { name: 'buf.bin', reference: 'Image1' });

    const pathContent = randomBytes(4096);
    const srcPath = join(vaultDir, 'src-plain.dat');
    writeFileSync(srcPath, pathContent);
    const f2 = await op.addFile(srcPath); // name defaults to basename

    const streamContent = Buffer.from('streamed contents ☃');
    const f3 = await op.addFileStream(Readable.from(streamContent), {
      name: 'stream.txt',
      encryptedReference: 'sealed-file-ref',
    });

    const id = await op.commit();
    expect(id).toBe(op.id);
    expect(op.state).toBe('committed');

    const dir = escrowDir(vaultDir, id);
    const m = readManifest(dir);
    expect(Object.keys(m.data ?? {}).sort()).toEqual([d1, d2].sort());
    expect(Object.keys(m.file ?? {}).sort()).toEqual([f1, f2, f3].sort());
    expect(m.data?.[d1]?.ref).toBe('Data42');
    expect(m.data?.[d2]?.ref).toBeUndefined();
    expect(m.file?.[f1]?.ref).toBe('Image1');
    // encryptedReference never appears in the cleartext manifest
    expect(JSON.stringify(m)).not.toContain('sealed-');
    expect(JSON.stringify(m)).not.toContain('hidden-escrow-ref');

    const opened = openEscrow(dir, secretKey);
    expect(opened.metadata.ref).toBe('case-7');
    expect(opened.metadata.cref).toBe('hidden-escrow-ref');

    const dataById = new Map(opened.data.map((d) => [d.id, d]));
    expect(dataById.get(d1)?.data).toEqual({ a: 1 });
    expect(dataById.get(d1)?.claims.ref).toBe('Data42');
    expect(dataById.get(d1)?.claims.cref).toBe('sealed-1');
    expect(dataById.get(d1)?.claims.id).toBe(d1);
    expect(dataById.get(d2)?.data).toEqual({ b: 2 });
    expect(dataById.get(d2)?.claims.ref).toBeUndefined();

    const filesById = new Map(opened.files.map((f) => [f.id, f]));
    expect(filesById.get(f1)?.bytes).toEqual(bufContent);
    expect(filesById.get(f1)?.name).toBe('buf.bin');
    expect(filesById.get(f1)?.claims.ref).toBe('Image1');
    expect(filesById.get(f2)?.bytes).toEqual(pathContent);
    expect(filesById.get(f2)?.name).toBe('src-plain.dat');
    expect(filesById.get(f3)?.bytes).toEqual(streamContent);
    expect(filesById.get(f3)?.claims.cref).toBe('sealed-file-ref');
  });

  it('round-trips with an RSA-OAEP escrow key', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = rsaEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const op = await esc.createEscrow();
    await op.addData({ rsa: true });
    const content = randomBytes(1000);
    await op.addFileBuffer(content, { name: 'r.bin' });
    const id = await op.commit();

    const opened = openEscrow(escrowDir(vaultDir, id), secretKey);
    expect(opened.data.map((d) => d.data)).toEqual([{ rsa: true }]);
    expect(opened.files[0]?.bytes).toEqual(content);
  });

  for (const variant of ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024']) {
    it(`round-trips with an ${variant} escrow key`, async () => {
      const vaultDir = makeVaultDir();
      const { publicKey, secretKey } = mlKemEscrowKeys(variant);
      const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

      const op = await esc.createEscrow();
      await op.addData({ pq: variant });
      const content = randomBytes(1000);
      await op.addFileBuffer(content, { name: 'q.bin' });
      const id = await op.commit();

      // The metadata is sealed under the SUFFIXED JWE algorithm while the
      // escrow key JWK itself carries the unsuffixed variant.
      const m = readManifest(escrowDir(vaultDir, id));
      const header = JSON.parse(
        Buffer.from((m.metadata.payload as string).split('.')[0]!, 'base64url').toString('utf8'),
      ) as Record<string, unknown>;
      expect(header.alg).toBe(`${variant}@spinium.com`);
      expect(header.enc).toBe('A256GCM');

      const opened = openEscrow(escrowDir(vaultDir, id), secretKey);
      expect(opened.data.map((d) => d.data)).toEqual([{ pq: variant }]);
      expect(opened.files[0]?.bytes).toEqual(content);
    });
  }
});

describe('vault layout', () => {
  it('places the escrow at <vault>/<prefix>/<id>, files/ only when files exist', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const dataOnly = await esc.escrow({ x: 1 });
    const dirA = escrowDir(vaultDir, dataOnly);
    expect(existsSync(join(dirA, 'escrow.json'))).toBe(true);
    expect(existsSync(join(dirA, 'files'))).toBe(false);
    const mA = readManifest(dirA);
    expect(mA.file).toBeUndefined(); // empty sections omitted

    const op = await esc.createEscrow();
    const fid = await op.addFileBuffer(Buffer.from('abc'), { name: 'a' });
    const withFile = await op.commit();
    const dirB = escrowDir(vaultDir, withFile);
    expect(existsSync(join(dirB, 'files', fid))).toBe(true);
    const mB = readManifest(dirB);
    expect(mB.data).toBeUndefined();

    // staging area is empty after commits
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
  });
});

describe('builder semantics', () => {
  it('rejects mutators after commit; destroy after commit is a no-op', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await op.addData({ x: 1 });
    const id = await op.commit();
    await expect(op.addData({ y: 2 })).rejects.toThrow(TypeError);
    await expect(op.commit()).rejects.toThrow(TypeError);
    await op.destroy(); // no-op
    expect(existsSync(join(escrowDir(vaultDir, id), 'escrow.json'))).toBe(true);
  });

  it('throws on empty commit and cleans the staging directory', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await expect(op.commit()).rejects.toThrow(TypeError);
    expect(op.state).toBe('destroyed');
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
  });

  it('auto-destroys on a failing add (bad path) and removes the whole staging dir', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await op.addData({ keep: 'me?' });
    await op.addFileBuffer(Buffer.from('good'), { name: 'g' });
    await expect(op.addFile('/no/such/file/really')).rejects.toBeInstanceOf(Error);
    expect(op.state).toBe('destroyed');
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
    // nothing was committed
    expect(existsSync(escrowDir(vaultDir, op.id))).toBe(false);
    await expect(op.addData({ x: 1 })).rejects.toThrow(TypeError);
  });

  it('destroy() removes the staging directory and blocks further use', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await op.addFileBuffer(Buffer.from('x'), { name: 'x' });
    await op.destroy();
    expect(op.state).toBe('destroyed');
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
    await expect(op.commit()).rejects.toThrow(TypeError);
  });
});

describe('references', () => {
  it('rejects a duplicate item reference (shared scope across data and files)', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await op.addData({ a: 1 }, { reference: 'shared' });
    await expect(
      op.addFileBuffer(Buffer.from('x'), { name: 'x', reference: 'shared' }),
    ).rejects.toBeInstanceOf(ReferenceConflictError);
    expect(op.state).toBe('destroyed');
    expect(readdirSync(join(vaultDir, '.tmp'))).toEqual([]);
  });

  it('rejects a duplicate encryptedReference (its own scope)', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await op.addData({ a: 1 }, { encryptedReference: 'sealed' });
    // same value as a cleartext reference is fine — different scope
    await op.addData({ b: 2 }, { reference: 'sealed' });
    await expect(op.addData({ c: 3 }, { encryptedReference: 'sealed' })).rejects.toBeInstanceOf(
      ReferenceConflictError,
    );
    expect(op.state).toBe('destroyed');
  });

  it('escrow-level reference is outside the item scope; other escrows may repeat refs', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const op = await esc.createEscrow({ reference: 'same' });
    await op.addData({ a: 1 }, { reference: 'same' }); // no conflict with escrow-level ref
    await op.commit();

    // an entirely different escrow may reuse any references
    const op2 = await esc.createEscrow({ reference: 'same' });
    await op2.addData({ b: 2 }, { reference: 'same' });
    await op2.commit();
  });

  it('validates reference shapes', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ reference: '' })).rejects.toThrow(TypeError);
    // @ts-expect-error non-string reference
    await expect(esc.createEscrow({ reference: 42 })).rejects.toThrow(TypeError);
    await expect(esc.createEscrow({ encryptedReference: 'x'.repeat(1025) })).rejects.toThrow(
      TypeError,
    );
  });
});

describe('expiry (unix seconds)', () => {
  const { publicKey } = ecEscrowKeys();

  it('stores an absolute expiresAt (Date and ISO string) floored to seconds', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });

    const d = new Date(Date.now() + 3_600_000);
    const id1 = await esc.escrow({ x: 1 }, { expiresAt: d });
    expect(readManifest(escrowDir(vaultDir, id1)).metadata.exp).toBe(
      Math.floor(d.getTime() / 1000),
    );

    const iso = new Date(Date.now() + 7_200_000).toISOString();
    const id2 = await esc.escrow({ x: 2 }, { expiresAt: iso });
    expect(readManifest(escrowDir(vaultDir, id2)).metadata.exp).toBe(
      Math.floor(new Date(iso).getTime() / 1000),
    );
  });

  it('stores a relative expiresAfter as iat + seconds', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const id = await esc.escrow({ x: 1 }, { expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id)).metadata;
    expect(m.exp).toBe(m.iat + 3600);
  });

  it('applies the constructor default expiresAfter; explicit null overrides it', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, expiresAfter: 86_400 });

    const idDefault = await esc.escrow({ x: 1 });
    const mDefault = readManifest(escrowDir(vaultDir, idDefault)).metadata;
    expect(mDefault.exp).toBe(mDefault.iat + 86_400);

    const idNullAfter = await esc.escrow({ x: 2 }, { expiresAfter: null });
    expect(readManifest(escrowDir(vaultDir, idNullAfter)).metadata.exp).toBeUndefined();

    const idNullAt = await esc.escrow({ x: 3 }, { expiresAt: null });
    expect(readManifest(escrowDir(vaultDir, idNullAt)).metadata.exp).toBeUndefined();
  });

  it('binds exp inside the sealed metadata payload', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey: pub, secretKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: pub });
    const id = await esc.escrow({ x: 1 }, { expiresAfter: 3600 });
    const dir = escrowDir(vaultDir, id);
    const opened = openEscrow(dir, secretKey);
    expect(opened.metadata.exp).toBe(readManifest(dir).metadata.exp);
  });

  it('rejects both expiresAt and expiresAfter together', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(
      esc.createEscrow({ expiresAt: new Date(), expiresAfter: 1000 }),
    ).rejects.toThrow(TypeError);
  });

  it('rejects invalid expiry values and expiresAt on the constructor', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ expiresAt: 'not-a-date' })).rejects.toThrow(TypeError);
    await expect(esc.createEscrow({ expiresAfter: -1 })).rejects.toThrow(TypeError);
    expect(
      () =>
        new DataEscrow({
          vaultDir,
          escrowKey: publicKey,
          // @ts-expect-error expiresAt is not a constructor option
          expiresAt: new Date(),
        }),
    ).toThrow(TypeError);
  });
});

describe('configuration validation', () => {
  it('requires a usable vaultDir', () => {
    const { publicKey } = ecEscrowKeys();
    // @ts-expect-error vaultDir missing
    expect(() => new DataEscrow({ escrowKey: publicKey })).toThrow(TypeError);
    expect(() => new DataEscrow({ vaultDir: '', escrowKey: publicKey })).toThrow(TypeError);
  });

  it('rejects private keys, weak RSA, bad curves, and missing kid', () => {
    const vaultDir = makeVaultDir();
    const { secretKey: ecPriv } = ecEscrowKeys();
    expect(() => new DataEscrow({ vaultDir, escrowKey: ecPriv })).toThrow(TypeError);

    const { publicKey: ecPub } = ecEscrowKeys();
    const noKid = { ...ecPub };
    delete (noKid as Record<string, unknown>).kid;
    expect(() => new DataEscrow({ vaultDir, escrowKey: noKid })).toThrow(TypeError);

    const { publicKey: weak } = rsaEscrowKeys('RS256'); // 1024-bit
    expect(() => new DataEscrow({ vaultDir, escrowKey: weak })).toThrow(TypeError);

    const badCrv = { ...ecPub, crv: 'P-192' };
    expect(() => new DataEscrow({ vaultDir, escrowKey: badCrv })).toThrow(TypeError);

    expect(
      () => new DataEscrow({ vaultDir, escrowKey: { kty: 'oct', k: 'AAAA', kid: 'x' } }),
    ).toThrow(TypeError);
  });

  it('validates name rules on file adds', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op = await esc.createEscrow();
    await expect(op.addFileBuffer(Buffer.from('x'), { name: 'a/b' })).rejects.toThrow(TypeError);
    expect(op.state).toBe('destroyed');

    // <= 255 characters but > 255 bytes of UTF-8
    const opBytes = await esc.createEscrow();
    await expect(
      opBytes.addFileBuffer(Buffer.from('x'), { name: 'ä'.repeat(200) }),
    ).rejects.toThrow(/bytes of UTF-8/);
    expect(opBytes.state).toBe('destroyed');

    const op2 = await esc.createEscrow();
    // @ts-expect-error name missing for buffer input
    await expect(op2.addFileBuffer(Buffer.from('x'), {})).rejects.toThrow(TypeError);
  });
});

describe('file compression', () => {
  const COMP_CODES = { none: 0, deflate: 1, gzip: 2, brotli: 3 } as const;
  // Highly compressible so we can also assert the stored blob actually shrank.
  const compressible = Buffer.from('abcdefgh'.repeat(8192));

  function blobPath(vaultDir: string, escrowId: string, fileId: string): string {
    return join(escrowDir(vaultDir, escrowId), 'files', fileId);
  }

  for (const [name, code] of Object.entries(COMP_CODES)) {
    it(`round-trips a ${name}-compressed file and flags the container header`, async () => {
      const vaultDir = makeVaultDir();
      const { publicKey, secretKey } = ecEscrowKeys();
      const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
      const op = await esc.createEscrow();
      const fid = await op.addFileBuffer(compressible, {
        name: 'c.bin',
        compression: name as 'none' | 'deflate' | 'gzip' | 'brotli',
      });
      const id = await op.commit();

      const path = blobPath(vaultDir, id, fid);
      expect(readVaultFileHeader(path).comp).toBe(code);
      if (name !== 'none') {
        expect(statSync(path).size).toBeLessThan(compressible.length / 2);
      }
      const opened = openEscrow(escrowDir(vaultDir, id), secretKey);
      expect(opened.files[0]?.bytes).toEqual(compressible);
    });
  }

  it('compression is not recorded in the manifest or payload claims', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, compression: 'gzip' });
    const op = await esc.createEscrow();
    await op.addFileBuffer(compressible, { name: 'c.bin' });
    const id = await op.commit();
    const dir = escrowDir(vaultDir, id);
    expect(JSON.stringify(readManifest(dir))).not.toContain('compression');
    const claims = openEscrow(dir, secretKey).files[0]?.claims as Record<string, unknown>;
    expect(claims.compression).toBeUndefined();
    expect(claims.comp).toBeUndefined();
  });

  it('applies the constructor default and the createEscrow / addFile overrides', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, compression: 'deflate' });

    // constructor default
    const op1 = await esc.createEscrow();
    const f1 = await op1.addFileBuffer(compressible, { name: 'a' });
    const id1 = await op1.commit();
    expect(readVaultFileHeader(blobPath(vaultDir, id1, f1)).comp).toBe(1);

    // createEscrow override, plus per-file overrides both ways
    const op2 = await esc.createEscrow({ compression: 'brotli' });
    const f2 = await op2.addFileBuffer(compressible, { name: 'b' });
    const f3 = await op2.addFileBuffer(compressible, { name: 'c', compression: 'gzip' });
    const f4 = await op2.addFileBuffer(compressible, { name: 'd', compression: 'none' });
    const id2 = await op2.commit();
    expect(readVaultFileHeader(blobPath(vaultDir, id2, f2)).comp).toBe(3);
    expect(readVaultFileHeader(blobPath(vaultDir, id2, f3)).comp).toBe(2);
    expect(readVaultFileHeader(blobPath(vaultDir, id2, f4)).comp).toBe(0);
  });

  it('rejects zstd (reserved) and unknown compression names everywhere', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    // @ts-expect-error zstd is reserved
    expect(() => new DataEscrow({ vaultDir, escrowKey: publicKey, compression: 'zstd' }))
      .toThrow(TypeError);
    expect(
      // @ts-expect-error unknown name
      () => new DataEscrow({ vaultDir, escrowKey: publicKey, compression: 'lzma' }),
    ).toThrow(TypeError);

    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ compression: 'zstd' })).rejects.toThrow(TypeError);

    const op = await esc.createEscrow();
    await expect(
      op.addFileBuffer(compressible, { name: 'x', compression: 'zstd' }),
    ).rejects.toThrow(TypeError);
    expect(op.state).toBe('destroyed');
  });
});
