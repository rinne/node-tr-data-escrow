declare module 'tr-jwe' {
  export interface EncryptOptions {
    compressPayload?: boolean | 'auto';
    extendedReturn?: boolean;
  }

  export interface ExtendedResult {
    token: string;
    contentEncryptionKey: Record<string, unknown>;
  }

  /**
   * Encrypt a JSON-serializable value to a compact JWE string. `jwk.kid`, when a
   * string, is copied into the protected header. Synchronous. With
   * `extendedReturn` it returns `{ token, contentEncryptionKey }` instead.
   */
  export function encrypt(
    alg: string,
    jwk: Record<string, unknown>,
    data: unknown,
    options?: EncryptOptions,
  ): string;
  export function encrypt(
    alg: string,
    jwk: Record<string, unknown>,
    data: unknown,
    options: EncryptOptions & { extendedReturn: true },
  ): ExtendedResult;

  /** Decrypt a compact JWE token and return the parsed JSON payload. */
  export function decrypt(token: string, jwk: Record<string, unknown>): unknown;

  /** Return the content-encryption key of a token as an `oct` JWK. */
  export function unwrap(token: string, jwk: Record<string, unknown>): Record<string, unknown>;
}
