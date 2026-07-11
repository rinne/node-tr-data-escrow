import { createWriteStream } from 'node:fs';
import { open, unlink } from 'node:fs/promises';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { encryptTrde } from './trde-encrypt';
import type { CompressionName } from './trde';
import { AUTO_KID_PREFIX } from './auto-key';
import { ML_KEM_VARIANTS, ML_KEM_JWE_ALG_SUFFIX, type MlKemVariant } from './key-gen';

/** Result of validating a public escrow key. */
export interface EscrowKeyInfo {
  /** The sanitized public JWK (only public members retained). */
  escrowKey: Record<string, unknown>;
  /** The key identifier (`kid`). */
  escrowKid: string;
  /** The JWE key-management algorithm to use with this key. */
  escrowAlg:
    | 'RSA-OAEP'
    | 'ECDH-ES'
    | 'ML-KEM-512@spinium.com'
    | 'ML-KEM-768@spinium.com'
    | 'ML-KEM-1024@spinium.com';
}

const EC_CURVES = ['P-256', 'P-384', 'P-521'];

/**
 * Validates that `key` is an acceptable **public** escrow key and returns the
 * sanitized key, its kid, and the JWE algorithm to use. Accepts:
 *   - RSA-OAEP public keys with modulus >= 2048 bits
 *   - EC public keys on P-256 / P-384 / P-521 (used with ECDH-ES)
 *   - AKP ML-KEM public keys (used with the suffixed ML-KEM-* JWE algorithms)
 * A key carrying private material (`d`/`priv`) is rejected.
 */
export function validateEscrowKey(key: unknown): EscrowKeyInfo {
  if (!key || typeof key !== 'object' || Array.isArray(key)) {
    throw new TypeError('escrowKey must be a JWK object');
  }
  const k = key as Record<string, unknown>;
  if (typeof k.kid !== 'string' || k.kid.length === 0) {
    throw new TypeError('escrowKey.kid must be a non-empty string');
  }
  if (k.kid.startsWith(AUTO_KID_PREFIX)) {
    throw new TypeError(
      `escrowKey.kid must not use the reserved ${JSON.stringify(AUTO_KID_PREFIX)} prefix`,
    );
  }
  const kid = k.kid;

  if (k.kty === 'RSA') {
    if (k.alg !== 'RSA-OAEP') {
      throw new TypeError('RSA escrowKey must have alg "RSA-OAEP"');
    }
    if (typeof k.n !== 'string' || typeof k.e !== 'string') {
      throw new TypeError('RSA escrowKey must have string "n" and "e"');
    }
    if (k.d !== undefined) {
      throw new TypeError('escrowKey must be a public key (RSA private member "d" present)');
    }
    const modulusBits = Buffer.from(k.n, 'base64url').length * 8;
    if (modulusBits < 2048) {
      throw new TypeError(`RSA escrowKey modulus too small (${modulusBits} bits; need >= 2048)`);
    }
    return {
      escrowKey: { kty: 'RSA', n: k.n, e: k.e, alg: 'RSA-OAEP', kid },
      escrowKid: kid,
      escrowAlg: 'RSA-OAEP',
    };
  }

  if (k.kty === 'EC') {
    if (typeof k.crv !== 'string' || !EC_CURVES.includes(k.crv)) {
      throw new TypeError('EC escrowKey crv must be one of P-256, P-384, P-521');
    }
    if (typeof k.x !== 'string' || typeof k.y !== 'string') {
      throw new TypeError('EC escrowKey must have string "x" and "y"');
    }
    if (k.d !== undefined) {
      throw new TypeError('escrowKey must be a public key (EC private member "d" present)');
    }
    return {
      escrowKey: { kty: 'EC', crv: k.crv, x: k.x, y: k.y, kid },
      escrowKid: kid,
      escrowAlg: 'ECDH-ES',
    };
  }

  if (k.kty === 'AKP') {
    // An ML-KEM public key. The JWK carries the UNSUFFIXED variant in `alg`
    // (as node:crypto emits and tr-jwe requires); the JWE key-management
    // algorithm is the suffixed identifier.
    if (typeof k.alg !== 'string' || !ML_KEM_VARIANTS.includes(k.alg as MlKemVariant)) {
      throw new TypeError('AKP escrowKey alg must be one of ML-KEM-512, ML-KEM-768, ML-KEM-1024');
    }
    if (typeof k.pub !== 'string' || k.pub.length === 0) {
      throw new TypeError('AKP escrowKey must have a string "pub"');
    }
    if (k.priv !== undefined) {
      throw new TypeError('escrowKey must be a public key (AKP private member "priv" present)');
    }
    return {
      escrowKey: { kty: 'AKP', alg: k.alg, pub: k.pub, kid },
      escrowKid: kid,
      escrowAlg: (k.alg + ML_KEM_JWE_ALG_SUFFIX) as EscrowKeyInfo['escrowAlg'],
    };
  }

  throw new TypeError('escrowKey.kty must be "RSA", "EC" or "AKP"');
}

/**
 * Writer-side placement of one encrypted file: streams the TRDE container
 * produced by {@link encryptTrde} into `destPath` (inside the escrow's
 * temporary directory) and fsyncs it. Atomicity is provided by the
 * whole-escrow-directory rename at commit, so no per-file rename happens
 * here. On any failure the partial destination file is removed before the
 * error propagates.
 */
export async function streamEncryptToFile(
  src: Readable,
  fileKeyJwk: Record<string, unknown>,
  destPath: string,
  compression: CompressionName,
): Promise<void> {
  try {
    // `wx` fails if the destination somehow already exists (id collision).
    await pipeline(
      encryptTrde(src, fileKeyJwk, compression),
      createWriteStream(destPath, { flags: 'wx' }),
    );
    // Flush the blob to disk; the commit-time directory rename is only durable
    // if the contents are.
    const fh = await open(destPath, 'r+');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch (err) {
    await unlink(destPath).catch(() => {});
    throw err;
  }
}

/**
 * Best-effort fsync of a directory (so a rename/creation inside it is
 * durable). Ignored on platforms where directories cannot be fsynced.
 */
export async function fsyncDir(path: string): Promise<void> {
  try {
    const fh = await open(path, 'r');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch {
    /* best effort */
  }
}
