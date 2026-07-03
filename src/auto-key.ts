/**
 * Auto-key support: option validation and generation of the per-escrow auto
 * key pair. An auto key is a fresh key pair generated for one escrow; the
 * escrow metadata is encrypted to its public half instead of the escrow key.
 */
import { randomUUID } from 'node:crypto';
import {
  ecKeyPairGen,
  rsaKeyPairGen,
  EC_KEY_CURVES,
  RSA_MODULUS_LENGTH_MIN,
  RSA_MODULUS_LENGTH_MAX,
  type EcKeyCurve,
  type JwkKeyPair,
} from './key-gen';

/**
 * Reserved prefix of auto-key kids. An escrow key must never use it (enforced
 * in escrow-key validation), so an `auto:` kid unambiguously marks an escrow
 * whose metadata is encrypted to an auto key.
 */
export const AUTO_KID_PREFIX = 'auto:';

export const AUTO_KEY_ALGORITHMS = ['P-256', 'P-384', 'P-521', 'RSA-OAEP'] as const;
/** Algorithm of the generated auto key pair. */
export type AutoKeyAlgorithm = (typeof AUTO_KEY_ALGORITHMS)[number];

export const DEFAULT_AUTO_KEY_ALGORITHM: AutoKeyAlgorithm = 'P-521';
export const DEFAULT_RSA_MODULUS_LENGTH = 4096;

/** Validates an optional `autoKey` flag; null/undefined mean "not set". */
export function validateAutoKey(value: unknown): boolean | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'boolean') {
    throw new TypeError('autoKey must be a boolean');
  }
  return value;
}

/** Validates an optional `autoKeyAlgorithm`; null/undefined mean "not set". */
export function validateAutoKeyAlgorithm(value: unknown): AutoKeyAlgorithm | null {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== 'string' ||
    !AUTO_KEY_ALGORITHMS.includes(value as AutoKeyAlgorithm)
  ) {
    throw new TypeError(
      'autoKeyAlgorithm must be one of "P-256", "P-384", "P-521", "RSA-OAEP"',
    );
  }
  return value as AutoKeyAlgorithm;
}

/**
 * Validates an optional `rsaModulusLength` (bits); null/undefined mean "not
 * set". Always validated when submitted, even if no RSA key will be
 * generated.
 */
export function validateRsaModulusLength(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < RSA_MODULUS_LENGTH_MIN ||
    value > RSA_MODULUS_LENGTH_MAX
  ) {
    throw new TypeError(
      `rsaModulusLength must be an integer in ` +
        `[${RSA_MODULUS_LENGTH_MIN}, ${RSA_MODULUS_LENGTH_MAX}]`,
    );
  }
  return value;
}

/** A generated auto key pair with its kid and JWE key-management algorithm. */
export interface AutoKeyPair extends JwkKeyPair {
  /** The shared `auto:`-prefixed kid of both JWKs. */
  kid: string;
  /** The JWE algorithm the public key encrypts with. */
  alg: 'RSA-OAEP' | 'ECDH-ES';
}

/**
 * Generates one auto key pair asynchronously. Both JWKs get a fresh
 * `auto:`-prefixed kid; RSA keys are additionally stamped `alg: 'RSA-OAEP'`
 * on both halves (the generic generator sets no `alg`; EC keys carry none,
 * matching the escrow-key rules).
 */
export async function generateAutoKeyPair(
  algorithm: AutoKeyAlgorithm,
  rsaModulusLength: number,
): Promise<AutoKeyPair> {
  const kid = AUTO_KID_PREFIX + randomUUID().toLowerCase();
  if (algorithm === 'RSA-OAEP') {
    const { secretKey, publicKey } = await rsaKeyPairGen(rsaModulusLength);
    secretKey.alg = 'RSA-OAEP';
    publicKey.alg = 'RSA-OAEP';
    secretKey.kid = kid;
    publicKey.kid = kid;
    return { secretKey, publicKey, kid, alg: 'RSA-OAEP' };
  }
  if (!EC_KEY_CURVES.includes(algorithm)) {
    throw new TypeError(`unsupported auto key algorithm ${JSON.stringify(algorithm)}`);
  }
  const { secretKey, publicKey } = await ecKeyPairGen(algorithm as EcKeyCurve);
  secretKey.kid = kid;
  publicKey.kid = kid;
  return { secretKey, publicKey, kid, alg: 'ECDH-ES' };
}
