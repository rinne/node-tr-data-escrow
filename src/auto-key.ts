/**
 * Auto-key support: option validation and generation of the per-escrow auto
 * key pair. An auto key is a fresh key pair generated for one escrow; the
 * escrow metadata is encrypted to its public half instead of the escrow key.
 *
 * The algorithm model (shared with the key-vault layer) is a JWE
 * key-management algorithm plus, per family, a curve (ECDH-ES) or a modulus
 * length (RSA):
 *   - `ECDH-ES`      EC key on `autoKeyCrv` (default P-521)
 *   - `RSA-OAEP`     RSA key of `autoKeyLength` bits (default 4096)
 *   - `RSA-OAEP-256` RSA key of `autoKeyLength` bits (default 4096)
 */
import { randomUUID } from 'node:crypto';
import {
  ecKeyPairGen,
  rsaKeyPairGen,
  mlKemKeyPairGen,
  mlKemVariantOfJweAlg,
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

export const AUTO_KEY_ALGORITHMS = [
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'ML-KEM-512@spinium.com',
  'ML-KEM-768@spinium.com',
  'ML-KEM-1024@spinium.com',
] as const;
/** JWE key-management algorithm of the generated auto key pair. */
export type AutoKeyAlgorithm = (typeof AUTO_KEY_ALGORITHMS)[number];

/** EC curve for an `ECDH-ES` auto key. */
export type AutoKeyCrv = EcKeyCurve;

export const DEFAULT_AUTO_KEY_ALGORITHM: AutoKeyAlgorithm = 'ECDH-ES';
export const DEFAULT_AUTO_KEY_CRV: AutoKeyCrv = 'P-521';
export const DEFAULT_AUTO_KEY_LENGTH = 4096;

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
  if (typeof value !== 'string' || !AUTO_KEY_ALGORITHMS.includes(value as AutoKeyAlgorithm)) {
    throw new TypeError(
      'autoKeyAlgorithm must be one of "ECDH-ES", "RSA-OAEP", "RSA-OAEP-256", ' +
        '"ML-KEM-512@spinium.com", "ML-KEM-768@spinium.com", "ML-KEM-1024@spinium.com"',
    );
  }
  return value as AutoKeyAlgorithm;
}

/** Validates an optional `autoKeyCrv` (ECDH-ES); null/undefined mean "not set". */
export function validateAutoKeyCrv(value: unknown): AutoKeyCrv | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !EC_KEY_CURVES.includes(value as EcKeyCurve)) {
    throw new TypeError('autoKeyCrv must be one of "P-256", "P-384", "P-521"');
  }
  return value as AutoKeyCrv;
}

/**
 * Validates an optional `autoKeyLength` (RSA modulus bits); null/undefined
 * mean "not set". Always validated when submitted, even if no RSA key will be
 * generated.
 */
export function validateAutoKeyLength(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < RSA_MODULUS_LENGTH_MIN ||
    value > RSA_MODULUS_LENGTH_MAX
  ) {
    throw new TypeError(
      `autoKeyLength must be an integer in ` +
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
  alg: AutoKeyAlgorithm;
}

/**
 * Generates one auto key pair asynchronously. Both JWKs get a fresh
 * `auto:`-prefixed kid; RSA keys are additionally stamped with their `alg`
 * (`RSA-OAEP` or `RSA-OAEP-256`) on both halves; EC keys carry no `alg`,
 * matching the escrow-key rules.
 */
export async function generateAutoKeyPair(
  algorithm: AutoKeyAlgorithm,
  options: { crv: AutoKeyCrv; length: number },
): Promise<AutoKeyPair> {
  const kid = AUTO_KID_PREFIX + randomUUID().toLowerCase();
  if (algorithm === 'RSA-OAEP' || algorithm === 'RSA-OAEP-256') {
    const { secretKey, publicKey } = await rsaKeyPairGen(options.length);
    secretKey.alg = algorithm;
    publicKey.alg = algorithm;
    secretKey.kid = kid;
    publicKey.kid = kid;
    return { secretKey, publicKey, kid, alg: algorithm };
  }
  const mlKemVariant = mlKemVariantOfJweAlg(algorithm);
  if (mlKemVariant !== null) {
    // The AKP JWKs keep the UNSUFFIXED variant in `alg` (tr-jwe key
    // validation requirement); the returned JWE algorithm is suffixed.
    // Neither `crv` nor `length` applies.
    const { secretKey, publicKey } = await mlKemKeyPairGen(mlKemVariant);
    secretKey.kid = kid;
    publicKey.kid = kid;
    return { secretKey, publicKey, kid, alg: algorithm };
  }
  if (algorithm !== 'ECDH-ES') {
    throw new TypeError(`unsupported auto key algorithm ${JSON.stringify(algorithm)}`);
  }
  const { secretKey, publicKey } = await ecKeyPairGen(options.crv);
  secretKey.kid = kid;
  publicKey.kid = kid;
  return { secretKey, publicKey, kid, alg: 'ECDH-ES' };
}
