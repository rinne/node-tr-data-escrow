import { describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { DataEscrow } from '../src/index';
import {
  DataEscrowDecrypt,
  EscrowIntegrityError,
  UnknownEscrowKeyError,
} from '../src/decrypt';
import { makeVaultDir, ecEscrowKeys, escrowDir, readManifest, openEscrow } from './helpers';

const AUTO_KID_RE = /^auto:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface AutoKeyFile {
  kid: string;
  iat: number;
  exp?: number;
  payload: string;
}

function readAutoKeyFile(dir: string): AutoKeyFile {
  return JSON.parse(readFileSync(join(dir, 'auto-key.json'), 'utf8')) as AutoKeyFile;
}

describe('auto key — option validation', () => {
  it('constructor requires escrowKey unless autoKey/kvKey is true', () => {
    const vaultDir = makeVaultDir();
    expect(() => new DataEscrow({ vaultDir } as never)).toThrow(/escrowKey is required/);
    expect(() => new DataEscrow({ vaultDir, escrowKey: null })).toThrow(/escrowKey is required/);
    expect(() => new DataEscrow({ vaultDir, autoKey: false, escrowKey: null })).toThrow(TypeError);
    expect(new DataEscrow({ vaultDir, autoKey: true })).toBeInstanceOf(DataEscrow);
    expect(new DataEscrow({ vaultDir, escrowKey: null, autoKey: true })).toBeInstanceOf(DataEscrow);
  });

  it('escrowKid getter is null without a constructor key', () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    expect(new DataEscrow({ vaultDir, autoKey: true }).escrowKid).toBeNull();
    expect(new DataEscrow({ vaultDir, escrowKey: publicKey }).escrowKid).toBe(publicKey.kid);
  });

  it('validates autoKey / algorithm / crv / length eagerly, even when unused', () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const base = { vaultDir, escrowKey: publicKey };
    for (const autoKey of ['yes', 1, {}, []]) {
      expect(() => new DataEscrow({ ...base, autoKey: autoKey as never })).toThrow(
        /autoKey must be a boolean/,
      );
    }
    // curves are no longer algorithm values
    for (const alg of ['P-256', 'P-521', 'RSA', 'rsa-oaep', '', 42]) {
      expect(() => new DataEscrow({ ...base, autoKeyAlgorithm: alg as never })).toThrow(
        /autoKeyAlgorithm/,
      );
    }
    for (const crv of ['P-192', 'ECDH-ES', '', 42]) {
      expect(() => new DataEscrow({ ...base, autoKeyCrv: crv as never })).toThrow(/autoKeyCrv/);
    }
    for (const bits of [2047, 16385, 4096.5, '4096', NaN]) {
      expect(() => new DataEscrow({ ...base, autoKeyLength: bits as never })).toThrow(
        /autoKeyLength/,
      );
    }
    // valid but unused (autoKey stays off): accepted
    expect(
      new DataEscrow({
        ...base,
        autoKeyAlgorithm: 'RSA-OAEP-256',
        autoKeyCrv: 'P-256',
        autoKeyLength: 2048,
      }),
    ).toBeInstanceOf(DataEscrow);
    // null means "not set" for all
    expect(
      new DataEscrow({
        ...base,
        autoKey: null,
        autoKeyAlgorithm: null,
        autoKeyCrv: null,
        autoKeyLength: null,
      }),
    ).toBeInstanceOf(DataEscrow);
  });

  it('validates the same options per operation in createEscrow', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ autoKey: 'on' as never })).rejects.toThrow(
      /autoKey must be a boolean/,
    );
    await expect(esc.createEscrow({ autoKeyAlgorithm: 'P-256' as never })).rejects.toThrow(
      /autoKeyAlgorithm/,
    );
    await expect(esc.createEscrow({ autoKeyCrv: 'P-192' as never })).rejects.toThrow(/autoKeyCrv/);
    await expect(esc.createEscrow({ autoKeyLength: 1024 })).rejects.toThrow(/autoKeyLength/);
  });

  it('rejects per-op escrowKey null unless effective autoKey/kvKey is true', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ escrowKey: null })).rejects.toThrow(
      /requires autoKey or kvKey/,
    );
    // constructor-level autoKey off + per-op off, constructor key inherited: fine
    const op = await esc.createEscrow({ autoKey: false });
    await op.destroy();
    // per-op autoKey false with an autoKey-only constructor: no key from anywhere
    const esc2 = new DataEscrow({ vaultDir, autoKey: true });
    await expect(esc2.createEscrow({ autoKey: false })).rejects.toThrow(/requires autoKey or kvKey/);
  });

  it('validates a per-op escrowKey JWK with the constructor rules', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey, secretKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ escrowKey: { kty: 'EC' } })).rejects.toThrow(TypeError);
    // private material rejected as for the constructor
    await expect(esc.createEscrow({ escrowKey: secretKey })).rejects.toThrow(/public key/);
  });

  it('rejects the reserved "auto:" kid prefix on escrow keys, everywhere', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const autoKidKey = { ...publicKey, kid: 'auto:not-really' };
    expect(() => new DataEscrow({ vaultDir, escrowKey: autoKidKey })).toThrow(/reserved/);
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey });
    await expect(esc.createEscrow({ escrowKey: autoKidKey })).rejects.toThrow(/reserved/);
  });
});

describe('auto key — round-trip per algorithm', () => {
  const cases = [
    { name: 'ECDH-ES P-256', algorithm: 'ECDH-ES', crv: 'P-256' },
    { name: 'ECDH-ES P-384', algorithm: 'ECDH-ES', crv: 'P-384' },
    { name: 'ECDH-ES P-521', algorithm: 'ECDH-ES', crv: 'P-521' },
    { name: 'RSA-OAEP', algorithm: 'RSA-OAEP', crv: undefined },
    { name: 'RSA-OAEP-256', algorithm: 'RSA-OAEP-256', crv: undefined },
    { name: 'ML-KEM-512', algorithm: 'ML-KEM-512@spinium.com', crv: undefined },
    { name: 'ML-KEM-768', algorithm: 'ML-KEM-768@spinium.com', crv: undefined },
    { name: 'ML-KEM-1024', algorithm: 'ML-KEM-1024@spinium.com', crv: undefined },
  ] as const;
  for (const c of cases) {
    it(`escrows and decrypts with a ${c.name} auto key`, async () => {
      const vaultDir = makeVaultDir();
      const { publicKey } = ecEscrowKeys();
      const esc = new DataEscrow({
        vaultDir,
        escrowKey: publicKey,
        autoKey: true,
        autoKeyAlgorithm: c.algorithm,
        ...(c.crv !== undefined ? { autoKeyCrv: c.crv } : {}),
        autoKeyLength: 2048, // non-default; only consulted for RSA
      });
      const op = await esc.createEscrow({ reference: 'auto-rt', expiresAfter: 3600 });
      expect(op.autoKid).toMatch(AUTO_KID_RE);
      const pair = op.autoKeyPair();
      expect(pair.secretKey.kid).toBe(op.autoKid);
      expect(pair.publicKey.kid).toBe(op.autoKid);
      if (c.algorithm.startsWith('RSA')) {
        expect(pair.secretKey.kty).toBe('RSA');
        expect(pair.secretKey.alg).toBe(c.algorithm);
        expect(pair.publicKey.alg).toBe(c.algorithm);
        expect(Buffer.from(pair.publicKey.n as string, 'base64url')).toHaveLength(2048 / 8);
      } else if (c.algorithm.startsWith('ML-KEM')) {
        // AKP JWKs carry the unsuffixed variant; the JWE alg is suffixed.
        expect(pair.secretKey.kty).toBe('AKP');
        expect(pair.secretKey.alg).toBe(c.algorithm.replace('@spinium.com', ''));
        expect(pair.publicKey.alg).toBe(c.algorithm.replace('@spinium.com', ''));
        expect(typeof pair.secretKey.priv).toBe('string');
        expect(pair.publicKey.priv).toBeUndefined();
      } else {
        expect(pair.secretKey.kty).toBe('EC');
        expect(pair.secretKey.crv).toBe(c.crv);
      }

      const content = randomBytes(1024);
      await op.addData({ v: 42 }, { reference: 'd1' });
      await op.addFileBuffer(content, { name: 'blob.bin' });
      const id = await op.commit();

      const dir = escrowDir(vaultDir, id);
      const m = readManifest(dir);
      expect(m.metadata.kid).toBe(op.autoKid);

      const dec = new DataEscrowDecrypt({ escrowSecretKey: pair.secretKey });
      const opened = await dec.decrypt(m);
      const data = opened.data();
      expect(data.metadata.payloadData.id).toBe(id);
      expect(data.metadata.payloadData.kid).toBe(op.autoKid);
      const items = Object.values(data.data!).map((e) => e.payloadData.data);
      expect(items).toEqual([{ v: 42 }]);
      const [fileId] = Object.keys(data.file!);
      expect(await opened.decryptFileToBuffer(fileId!, join(dir, 'files', fileId!))).toEqual(
        content,
      );

      expect(openEscrow(dir, pair.secretKey).files[0]?.bytes).toEqual(content);
    });
  }

  it('defaults to an ECDH-ES P-521 auto key', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true });
    const op = await esc.createEscrow();
    const secret = op.autoKeyPair().secretKey;
    expect(secret.kty).toBe('EC');
    expect(secret.crv).toBe('P-521');
    await op.destroy();
  });

  it('per-operation options override the constructor defaults', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, autoKeyCrv: 'P-256' });
    // autoKey enabled per op only; curve inherited from the constructor
    const op = await esc.createEscrow({ autoKey: true });
    expect(op.autoKeyPair().secretKey.crv).toBe('P-256');
    await op.destroy();
    // per-op curve beats the constructor's
    const op2 = await esc.createEscrow({ autoKey: true, autoKeyCrv: 'P-384' });
    expect(op2.autoKeyPair().secretKey.crv).toBe('P-384');
    await op2.destroy();
    // null inherits
    const op3 = await esc.createEscrow({ autoKey: true, autoKeyCrv: null });
    expect(op3.autoKeyPair().secretKey.crv).toBe('P-256');
    await op3.destroy();
  });
});

describe('auto key — auto-key.json', () => {
  async function committedAutoEscrow(expiresAfter?: number) {
    const vaultDir = makeVaultDir();
    const keys = ecEscrowKeys('P-384');
    const esc = new DataEscrow({
      vaultDir,
      escrowKey: keys.publicKey,
      autoKey: true,
      autoKeyCrv: 'P-256',
    });
    const op = await esc.createEscrow(expiresAfter !== undefined ? { expiresAfter } : {});
    const pair = op.autoKeyPair();
    await op.addData('payload');
    const id = await op.commit();
    return { dir: escrowDir(vaultDir, id), id, keys, pair };
  }

  it('is written iff the operation has both the auto key and an escrow key', async () => {
    const { dir } = await committedAutoEscrow();
    expect(existsSync(join(dir, 'auto-key.json'))).toBe(true);

    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true, autoKeyCrv: 'P-256' });
    const op = await esc.createEscrow();
    op.autoKeyPair();
    await op.addData('x');
    const id = await op.commit();
    expect(existsSync(join(escrowDir(vaultDir, id), 'auto-key.json'))).toBe(false);

    const { publicKey } = ecEscrowKeys();
    const esc2 = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const id2 = await esc2.escrow('y');
    expect(existsSync(join(escrowDir(vaultDir, id2), 'auto-key.json'))).toBe(false);
  });

  it('cleartext kid/iat/exp match escrow.json; exp absent without expiry', async () => {
    const { dir } = await committedAutoEscrow(7200);
    const m = readManifest(dir);
    const ak = readAutoKeyFile(dir);
    expect(Object.keys(ak).sort()).toEqual(['exp', 'iat', 'kid', 'payload']);
    expect(ak.kid).toBe(m.metadata.kid);
    expect(ak.iat).toBe(m.metadata.iat);
    expect(ak.exp).toBe(m.metadata.exp);

    const { dir: dir2 } = await committedAutoEscrow();
    const ak2 = readAutoKeyFile(dir2);
    expect(Object.keys(ak2).sort()).toEqual(['iat', 'kid', 'payload']);
  });

  it('decryptAutoKey recovers the pair that opens escrow.json', async () => {
    const { dir, id, keys, pair } = await committedAutoEscrow(3600);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: keys.secretKey });
    const recovered = await dec.decryptAutoKey(readAutoKeyFile(dir));
    expect(recovered.secretKey).toEqual(pair.secretKey);
    expect(recovered.publicKey.d).toBeUndefined();
    expect(recovered.publicKey.kid).toBe(pair.secretKey.kid);

    const autoDec = new DataEscrowDecrypt({ escrowSecretKey: recovered.secretKey });
    const opened = await autoDec.decrypt(readManifest(dir));
    expect(opened.data().metadata.payloadData.id).toBe(id);
  });

  it('detects cleartext tampering of kid/iat/exp', async () => {
    const { dir, keys } = await committedAutoEscrow(3600);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: keys.secretKey });
    const ak = readAutoKeyFile(dir);
    await expect(
      dec.decryptAutoKey({ ...ak, kid: 'auto:00000000-0000-4000-8000-000000000000' }),
    ).rejects.toThrow(EscrowIntegrityError);
    await expect(dec.decryptAutoKey({ ...ak, iat: ak.iat + 1 })).rejects.toThrow(
      EscrowIntegrityError,
    );
    await expect(dec.decryptAutoKey({ ...ak, exp: ak.exp! + 1 })).rejects.toThrow(
      EscrowIntegrityError,
    );
    const { exp: _exp, ...noExp } = ak;
    await expect(dec.decryptAutoKey(noExp)).rejects.toThrow(EscrowIntegrityError);
  });

  it('needs the right escrow secret key and a sane object shape', async () => {
    const { dir } = await committedAutoEscrow();
    const ak = readAutoKeyFile(dir);
    const wrong = ecEscrowKeys('P-384');
    const dec = new DataEscrowDecrypt({ escrowSecretKey: wrong.secretKey });
    await expect(dec.decryptAutoKey(ak)).rejects.toThrow(UnknownEscrowKeyError);

    for (const bad of [
      null,
      'x',
      [],
      {},
      { ...ak, kid: 'not-auto-prefixed' },
      { ...ak, kid: 'auto:' },
      { ...ak, iat: 'soon' },
      { ...ak, exp: 1.5 },
      { ...ak, payload: '' },
    ]) {
      await expect(dec.decryptAutoKey(bad)).rejects.toThrow(TypeError);
    }

    dec.destroy();
    await expect(dec.decryptAutoKey(ak)).rejects.toThrow(/destroyed/);
  });

  it('a per-op escrowKey override seals auto-key.json to the override key', async () => {
    const vaultDir = makeVaultDir();
    const ctorKeys = ecEscrowKeys('P-256');
    const opKeys = ecEscrowKeys('P-384');
    const esc = new DataEscrow({ vaultDir, escrowKey: ctorKeys.publicKey, autoKey: true });
    const op = await esc.createEscrow({ escrowKey: opKeys.publicKey });
    await op.addData(1);
    const id = await op.commit();
    const ak = readAutoKeyFile(escrowDir(vaultDir, id));

    const rightDec = new DataEscrowDecrypt({ escrowSecretKey: opKeys.secretKey });
    await expect(rightDec.decryptAutoKey(ak)).resolves.toBeDefined();
    const wrongDec = new DataEscrowDecrypt({ escrowSecretKey: ctorKeys.secretKey });
    await expect(wrongDec.decryptAutoKey(ak)).rejects.toThrow(UnknownEscrowKeyError);
  });
});

describe('auto key — autoKeyPair() and the commit guard', () => {
  it('returns fresh deep copies and throws when not enabled', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, autoKey: true });
    const op = await esc.createEscrow();
    const a = op.autoKeyPair();
    const b = op.autoKeyPair();
    expect(a).toEqual(b);
    expect(a).not.toBe(b);
    expect(a.secretKey).not.toBe(b.secretKey);
    a.secretKey.d = 'mutated';
    expect(op.autoKeyPair().secretKey.d).not.toBe('mutated');
    await op.destroy();

    const esc2 = new DataEscrow({ vaultDir, escrowKey: publicKey });
    const op2 = await esc2.createEscrow();
    expect(op2.autoKid).toBeNull();
    expect(() => op2.autoKeyPair()).toThrow(/auto key is not enabled/);
    expect(op2.state).toBe('pending');
    await op2.destroy();
  });

  it('is unavailable after commit and destroy', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, autoKey: true });
    const op = await esc.createEscrow();
    await op.addData(1);
    await op.commit();
    expect(() => op.autoKeyPair()).toThrow(/not pending/);
    const op2 = await esc.createEscrow();
    await op2.destroy();
    expect(() => op2.autoKeyPair()).toThrow(/not pending/);
  });

  it('commit refuses, without destroying, when the auto key was never collected', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true, autoKeyCrv: 'P-256' });
    const op = await esc.createEscrow();
    await op.addData('precious');
    await expect(op.commit()).rejects.toThrow(/unrecoverable/);
    expect(op.state).toBe('pending');
    const pair = op.autoKeyPair();
    const id = await op.commit();
    expect(op.state).toBe('committed');

    const dec = new DataEscrowDecrypt({ escrowSecretKey: pair.secretKey });
    const opened = await dec.decrypt(readManifest(escrowDir(vaultDir, id)));
    const items = Object.values(opened.data().data!).map((e) => e.payloadData.data);
    expect(items).toEqual(['precious']);
  });

  it('with an escrow key the guard does not apply', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, autoKey: true });
    const op = await esc.createEscrow();
    await op.addData(1);
    await expect(op.commit()).resolves.toBeDefined();
  });

  it('one-shot escrow() rejects an effective-null escrow key eagerly', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true, autoKeyCrv: 'P-256' });
    await expect(esc.escrow('data')).rejects.toThrow(/one-shot/);
    const { publicKey, secretKey } = ecEscrowKeys();
    const esc2 = new DataEscrow({ vaultDir, escrowKey: publicKey, autoKey: true });
    const id = await esc2.escrow('fine', { autoKeyCrv: 'P-256' });
    const dir = escrowDir(vaultDir, id);
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    const { secretKey: autoSecret } = await dec.decryptAutoKey(readAutoKeyFile(dir));
    expect(openEscrow(dir, autoSecret).data.map((d) => d.data)).toEqual(['fine']);
  });

  it('destroy() removes the staging directory of an uncommitted auto escrow', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true, autoKeyCrv: 'P-256' });
    const op = await esc.createEscrow();
    await op.addData(1);
    await op.destroy();
    expect(existsSync(join(vaultDir, '.tmp', op.id))).toBe(false);
    expect(() => op.autoKeyPair()).toThrow(/not pending/);
  });
});
