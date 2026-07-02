declare module 'tr-jwk' {
  /** A JSON Web Key as produced/consumed by tr-jwk (loose shape). */
  export type Jwk = Record<string, unknown> & { kty: string; kid?: string; alg?: string };

  /** Generate a signing/MAC key (HS*, ES*, RS*, ML-DSA-*). Returns a private JWK. */
  export function macKeyGen(alg: string): Jwk;

  /** Generate a symmetric AES content-encryption / key-wrap key (A*GCM / A*GCMKW). */
  export function cipherKeyGen(alg: string): Jwk;

  /** Generate an EC key pair (P-256/384/521) for ECDH-ES; both JWKs share a kid. */
  export function ecKeyGen(curve: string): { secretKey: Jwk; publicKey: Jwk };
}
