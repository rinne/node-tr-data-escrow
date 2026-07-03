/**
 * Generic in-package key generation on top of `node:crypto`. This module
 * knows nothing about escrows or auto keys — it only produces JWKs.
 *
 * Key **pairs** are generated asynchronously (`crypto.generateKeyPair` runs
 * on the libuv thread pool), so callers never block the event loop — not
 * even for RSA at large moduli. Symmetric keys are generated synchronously
 * (random bytes are cheap).
 */
import {
  generateKeyPair as generateKeyPairCb,
  generateKeySync,
  randomUUID,
} from 'node:crypto';
import { promisify } from 'node:util';

const generateKeyPair = promisify(generateKeyPairCb);

/** A generated key pair as JWKs. Both keys share one random `kid`; no `alg`. */
export interface JwkKeyPair {
  secretKey: Record<string, unknown>;
  publicKey: Record<string, unknown>;
}

export const EC_KEY_CURVES = ['P-256', 'P-384', 'P-521'] as const;
export type EcKeyCurve = (typeof EC_KEY_CURVES)[number];

export const RSA_MODULUS_LENGTH_MIN = 2048;
export const RSA_MODULUS_LENGTH_MAX = 16384;

/** Exports a node KeyObject pair as JWKs sharing a fresh random kid. */
function exportPair(pair: {
  publicKey: { export(options: { format: 'jwk' }): Record<string, unknown> };
  privateKey: { export(options: { format: 'jwk' }): Record<string, unknown> };
}): JwkKeyPair {
  const kid = randomUUID();
  const secretKey = pair.privateKey.export({ format: 'jwk' });
  const publicKey = pair.publicKey.export({ format: 'jwk' });
  // The caller decides the keys' purpose: no alg/use/key_ops on either side.
  delete secretKey.key_ops;
  delete publicKey.key_ops;
  secretKey.kid = kid;
  publicKey.kid = kid;
  return { secretKey, publicKey };
}

/**
 * Generates an EC key pair on P-256, P-384, or P-521, asynchronously.
 * Both JWKs share one random `kid`; no `alg` is set.
 */
export async function ecKeyPairGen(curve: EcKeyCurve): Promise<JwkKeyPair> {
  if (!EC_KEY_CURVES.includes(curve)) {
    throw new TypeError('ecKeyPairGen: curve must be one of P-256, P-384, P-521');
  }
  return exportPair(await generateKeyPair('ec', { namedCurve: curve }));
}

/**
 * Generates an RSA key pair with the given modulus length (bits; an integer,
 * 2048..16384), asynchronously — RSA generation takes real time at large
 * moduli but runs off the event loop. Both JWKs share one random `kid`; no
 * `alg` is set.
 */
export async function rsaKeyPairGen(modulusLength: number): Promise<JwkKeyPair> {
  if (
    !Number.isInteger(modulusLength) ||
    modulusLength < RSA_MODULUS_LENGTH_MIN ||
    modulusLength > RSA_MODULUS_LENGTH_MAX
  ) {
    throw new TypeError(
      `rsaKeyPairGen: modulusLength must be an integer in ` +
        `[${RSA_MODULUS_LENGTH_MIN}, ${RSA_MODULUS_LENGTH_MAX}]`,
    );
  }
  return exportPair(await generateKeyPair('rsa', { modulusLength }));
}

const CIPHER_KEY_OPTS: Record<string, { keyLength: number; ops: string[] }> = {
  A128GCM: { keyLength: 128, ops: ['encrypt', 'decrypt'] },
  A192GCM: { keyLength: 192, ops: ['encrypt', 'decrypt'] },
  A256GCM: { keyLength: 256, ops: ['encrypt', 'decrypt'] },
  A128GCMKW: { keyLength: 128, ops: ['wrapKey', 'unwrapKey'] },
  A192GCMKW: { keyLength: 192, ops: ['wrapKey', 'unwrapKey'] },
  A256GCMKW: { keyLength: 256, ops: ['wrapKey', 'unwrapKey'] },
};

/**
 * Generates a symmetric AES content-encryption / key-wrap JWK. The output
 * member set — `{ kty: 'oct', k, alg, key_ops, use: 'enc', kid }` — must not
 * drift: these JWKs are embedded verbatim inside sealed escrow payloads.
 */
export function cipherKeyGen(alg: string): Record<string, unknown> {
  const opts = CIPHER_KEY_OPTS[alg];
  if (opts === undefined) {
    throw new TypeError(`cipherKeyGen: unsupported algorithm ${JSON.stringify(alg)}`);
  }
  return {
    ...generateKeySync('aes', { length: opts.keyLength }).export({ format: 'jwk' }),
    alg,
    key_ops: [...opts.ops],
    use: 'enc',
    kid: randomUUID(),
  };
}
