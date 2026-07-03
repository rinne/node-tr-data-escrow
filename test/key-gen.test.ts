import { describe, expect, it } from 'vitest';
import { decrypt, encrypt } from 'tr-jwe';
import { cipherKeyGen, ecKeyPairGen, rsaKeyPairGen } from '../src/key-gen';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

describe('cipherKeyGen', () => {
  it('produces exactly the tr-jwk-compatible member set', () => {
    for (const [alg, bytes, ops] of [
      ['A256GCM', 32, ['encrypt', 'decrypt']],
      ['A256GCMKW', 32, ['wrapKey', 'unwrapKey']],
      ['A128GCM', 16, ['encrypt', 'decrypt']],
      ['A192GCMKW', 24, ['wrapKey', 'unwrapKey']],
    ] as const) {
      const key = cipherKeyGen(alg);
      // Exactly these members: the JWK is embedded verbatim in sealed
      // payloads, so the shape must not drift.
      expect(Object.keys(key).sort()).toEqual(['alg', 'k', 'key_ops', 'kid', 'kty', 'use']);
      expect(key.kty).toBe('oct');
      expect(key.alg).toBe(alg);
      expect(key.use).toBe('enc');
      expect(key.key_ops).toEqual([...ops]);
      expect(key.kid).toMatch(UUID_RE);
      expect(Buffer.from(key.k as string, 'base64url')).toHaveLength(bytes);
    }
  });

  it('generates a fresh key and kid every call', () => {
    const a = cipherKeyGen('A256GCM');
    const b = cipherKeyGen('A256GCM');
    expect(a.k).not.toBe(b.k);
    expect(a.kid).not.toBe(b.kid);
  });

  it('rejects unsupported algorithms', () => {
    for (const alg of ['A256CBC', 'nope', '']) {
      expect(() => cipherKeyGen(alg)).toThrow(TypeError);
    }
  });

  it('round-trips through tr-jwe', () => {
    const key = cipherKeyGen('A256GCMKW');
    expect(decrypt(encrypt('A256GCMKW', key, { x: 1 }), key)).toEqual({ x: 1 });
  });
});

describe('ecKeyPairGen', () => {
  it('returns JWK pairs with a shared kid and no alg, per curve', async () => {
    for (const curve of ['P-256', 'P-384', 'P-521'] as const) {
      const { secretKey, publicKey } = await ecKeyPairGen(curve);
      expect(secretKey.kty).toBe('EC');
      expect(secretKey.crv).toBe(curve);
      expect(typeof secretKey.d).toBe('string');
      expect(publicKey.kty).toBe('EC');
      expect(publicKey.crv).toBe(curve);
      expect(publicKey.d).toBeUndefined();
      expect(publicKey.x).toBe(secretKey.x);
      expect(publicKey.y).toBe(secretKey.y);
      expect(secretKey.kid).toMatch(UUID_RE);
      expect(publicKey.kid).toBe(secretKey.kid);
      for (const k of [secretKey, publicKey]) {
        expect(k.alg).toBeUndefined();
        expect(k.use).toBeUndefined();
        expect(k.key_ops).toBeUndefined();
      }
    }
  });

  it('generated keys round-trip through tr-jwe ECDH-ES', async () => {
    const { secretKey, publicKey } = await ecKeyPairGen('P-521');
    expect(decrypt(encrypt('ECDH-ES', publicKey, { hello: 'ec' }), secretKey)).toEqual({
      hello: 'ec',
    });
  });

  it('rejects an invalid curve', async () => {
    await expect(ecKeyPairGen('P-999' as never)).rejects.toThrow(TypeError);
  });
});

describe('rsaKeyPairGen', () => {
  it('returns JWK pairs with a shared kid, no alg, and the requested modulus', async () => {
    const { secretKey, publicKey } = await rsaKeyPairGen(2048);
    expect(secretKey.kty).toBe('RSA');
    expect(typeof secretKey.d).toBe('string');
    expect(publicKey.kty).toBe('RSA');
    expect(publicKey.d).toBeUndefined();
    expect(publicKey.n).toBe(secretKey.n);
    expect(publicKey.e).toBe(secretKey.e);
    expect(publicKey.kid).toBe(secretKey.kid);
    expect(secretKey.alg).toBeUndefined();
    expect(publicKey.alg).toBeUndefined();
    expect(Buffer.from(publicKey.n as string, 'base64url')).toHaveLength(2048 / 8);
  });

  it('generated keys round-trip through tr-jwe RSA-OAEP', async () => {
    const { secretKey, publicKey } = await rsaKeyPairGen(2048);
    const pub = { ...publicKey, alg: 'RSA-OAEP' };
    expect(decrypt(encrypt('RSA-OAEP', pub, { hello: 'rsa' }), secretKey)).toEqual({
      hello: 'rsa',
    });
  });

  it('rejects out-of-range and non-integer modulus lengths', async () => {
    for (const bad of [2047, 16385, 0, -2048, 2048.5, NaN, Infinity]) {
      await expect(rsaKeyPairGen(bad)).rejects.toThrow(TypeError);
    }
  });
});
