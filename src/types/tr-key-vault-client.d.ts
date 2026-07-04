/**
 * Minimal ambient types for the optional `tr-key-vault-client` dependency
 * (plain-JS package, no bundled types). Only the surface this package uses is
 * declared. Loaded lazily (dynamic import) so it is never required unless the
 * key-vault layer is actually used.
 */
declare module 'tr-key-vault-client' {
  export interface KeyVaultClientOptions {
    url: string;
    user?: string;
    token?: string;
    timeout?: number;
    insecure?: boolean;
    ca?: string | Buffer;
    keepAlive?: boolean;
  }

  export interface GenerateKeyOptions {
    kty?: string;
    crv?: string;
    keyLength?: number;
    nbf?: number;
    exp?: number;
    acl?: Record<string, unknown>;
    returnPublicKey?: boolean;
    op?: string;
    timeout?: number;
  }

  export interface JoseResult {
    header: Record<string, unknown>;
    data: unknown;
  }

  export default class KeyVaultClient {
    constructor(options: KeyVaultClientOptions);
    generateKey(
      alg: string,
      options?: GenerateKeyOptions,
    ): Promise<{ kid: string; key?: Record<string, unknown> }>;
    publicKey(kid: string, options?: { op?: string; timeout?: number }): Promise<Record<string, unknown>>;
    createJwt(kid: string, payload: Record<string, unknown>, options?: { op?: string; timeout?: number }): Promise<string>;
    verifyJwt(token: string, options?: { kid?: string; op?: string; timeout?: number }): Promise<JoseResult>;
    createJwe(kid: string, data: unknown, options?: { compress?: boolean | 'auto'; op?: string; timeout?: number }): Promise<string>;
    decryptJwe(token: string, options?: { kid?: string; op?: string; timeout?: number }): Promise<JoseResult>;
    revokeKey(kid: string, options?: { op?: string; timeout?: number }): Promise<void>;
    exportKey(kid: string, options?: { op?: string; timeout?: number }): Promise<Record<string, unknown>>;
    listKeys(options?: { op?: string; timeout?: number }): Promise<Array<{ kid: string; kty: string; alg: string }>>;
    hello(options?: { op?: string; timeout?: number }): Promise<{ uptime: number }>;
    healthz(options?: { timeout?: number }): Promise<boolean>;
    readyz(options?: { timeout?: number }): Promise<boolean>;
    raw(request: string, data: unknown, options?: { op?: string; timeout?: number }): Promise<Record<string, unknown>>;

    static KeyVaultClientError: new (message?: string) => Error;
    static KeyVaultApiError: new (message: string, errorCode: number, op?: string) => Error & { errorCode: number; op?: string };
    static KeyVaultTransportError: new (message: string, cause?: unknown) => Error;
    static KeyVaultProtocolError: new (message?: string) => Error;
  }
}
