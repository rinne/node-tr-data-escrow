/**
 * Key-vault support: the optional layer that generates the per-escrow key in a
 * [tr-key-vault](https://github.com/rinne/tr-key-vault) server instead of
 * locally. The escrow metadata is encrypted to the vault-held key's public
 * half; the private half never leaves the vault; the escrow's expiry is handed
 * to the vault, which deletes the key at expiry.
 *
 * `tr-key-vault-client` is loaded **lazily** (dynamic import) the first time a
 * client is actually built, so a consumer who never uses `kvKey` never pulls
 * it into the module graph.
 */
import type KeyVaultClient from 'tr-key-vault-client';
import type { KeyVaultClientOptions } from 'tr-key-vault-client';
import { EC_KEY_CURVES, RSA_MODULUS_LENGTH_MIN, RSA_MODULUS_LENGTH_MAX, type EcKeyCurve } from './key-gen';

export const KV_KEY_ALGORITHMS = [
  'ECDH-ES',
  'RSA-OAEP',
  'RSA-OAEP-256',
  'ML-KEM-512@spinium.com',
  'ML-KEM-768@spinium.com',
  'ML-KEM-1024@spinium.com',
] as const;
/** JWE key-management algorithm of the generated key-vault key. */
export type KvKeyAlgorithm = (typeof KV_KEY_ALGORITHMS)[number];
export type KvKeyCrv = EcKeyCurve;

export const DEFAULT_KV_KEY_ALGORITHM: KvKeyAlgorithm = 'ECDH-ES';
export const DEFAULT_KV_KEY_CRV: KvKeyCrv = 'P-521';
export const DEFAULT_KV_KEY_LENGTH = 4096;

/** A key-vault connection: the `tr-key-vault-client` constructor options. */
export type KeyVaultConnection = KeyVaultClientOptions;

/**
 * The `kv` option value: a connection config, an already-built
 * `KeyVaultClient` instance, or null/undefined.
 */
export type KvOption = KeyVaultConnection | KeyVaultClient | null | undefined;

/** Validates an optional `kvKey` flag; null/undefined mean "not set". */
export function validateKvKey(value: unknown): boolean | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'boolean') {
    throw new TypeError('kvKey must be a boolean');
  }
  return value;
}

/** Validates an optional `kvKeyAlgorithm`; null/undefined mean "not set". */
export function validateKvKeyAlgorithm(value: unknown): KvKeyAlgorithm | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !KV_KEY_ALGORITHMS.includes(value as KvKeyAlgorithm)) {
    throw new TypeError(
      'kvKeyAlgorithm must be one of "ECDH-ES", "RSA-OAEP", "RSA-OAEP-256", ' +
        '"ML-KEM-512@spinium.com", "ML-KEM-768@spinium.com", "ML-KEM-1024@spinium.com"',
    );
  }
  return value as KvKeyAlgorithm;
}

/** Validates an optional `kvKeyCrv` (ECDH-ES); null/undefined mean "not set". */
export function validateKvKeyCrv(value: unknown): KvKeyCrv | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !EC_KEY_CURVES.includes(value as EcKeyCurve)) {
    throw new TypeError('kvKeyCrv must be one of "P-256", "P-384", "P-521"');
  }
  return value as KvKeyCrv;
}

/** Validates an optional `kvKeyLength` (RSA modulus bits); null/undefined mean "not set". */
export function validateKvKeyLength(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < RSA_MODULUS_LENGTH_MIN ||
    value > RSA_MODULUS_LENGTH_MAX
  ) {
    throw new TypeError(
      `kvKeyLength must be an integer in [${RSA_MODULUS_LENGTH_MIN}, ${RSA_MODULUS_LENGTH_MAX}]`,
    );
  }
  return value;
}

/** True when a `kv` value looks like an already-built KeyVaultClient. */
function isClientInstance(value: object): value is KeyVaultClient {
  return typeof (value as { generateKey?: unknown }).generateKey === 'function';
}

/**
 * Validates a `kv` option: passes through a client instance, or shape-checks a
 * connection config (no I/O). Returns null for null/undefined. Throws
 * `TypeError` on an invalid config.
 */
export function validateKvOption(value: unknown): KeyVaultConnection | KeyVaultClient | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('kv must be a connection object or a KeyVaultClient instance');
  }
  if (isClientInstance(value)) {
    return value as KeyVaultClient;
  }
  const c = value as Record<string, unknown>;
  if (typeof c.url !== 'string' || c.url.length === 0) {
    throw new TypeError('kv.url must be a non-empty string');
  }
  if (c.user !== undefined && (typeof c.user !== 'string' || c.user.length === 0)) {
    throw new TypeError('kv.user must be a non-empty string when present');
  }
  if (c.token !== undefined && (typeof c.token !== 'string' || c.token.length === 0)) {
    throw new TypeError('kv.token must be a non-empty string when present');
  }
  return value as KeyVaultConnection;
}

/**
 * A reader-side kv connection: like {@link KeyVaultConnection} but `url` may be
 * omitted and filled from the escrow manifest's `metadata.kv.url`.
 */
export type KvReaderConnection = Omit<KeyVaultConnection, 'url'> & { url?: string };
export type KvReaderOption = KvReaderConnection | KeyVaultClient | null | undefined;

/**
 * Validates a reader `kv` option: passes through a client instance, or
 * shape-checks a connection config **without requiring `url`** (it may come
 * from the manifest). Returns null for null/undefined.
 */
export function validateKvReaderOption(value: unknown): KvReaderConnection | KeyVaultClient | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('kv must be a connection object or a KeyVaultClient instance');
  }
  if (isClientInstance(value)) return value as KeyVaultClient;
  const c = value as Record<string, unknown>;
  if (c.url !== undefined && (typeof c.url !== 'string' || c.url.length === 0)) {
    throw new TypeError('kv.url must be a non-empty string when present');
  }
  if (c.user !== undefined && (typeof c.user !== 'string' || c.user.length === 0)) {
    throw new TypeError('kv.user must be a non-empty string when present');
  }
  if (c.token !== undefined && (typeof c.token !== 'string' || c.token.length === 0)) {
    throw new TypeError('kv.token must be a non-empty string when present');
  }
  return value as KvReaderConnection;
}

/**
 * Builds a reader {@link KvVault}, resolving the URL: a configured URL wins,
 * otherwise the manifest's. Throws when neither is available.
 */
export function readerKvVault(
  rawKv: KvReaderConnection | KeyVaultClient,
  manifestUrl: string | undefined,
): KvVault {
  if (isClientInstance(rawKv as object)) {
    return new KvVault(rawKv as KeyVaultClient);
  }
  const cfg = rawKv as KvReaderConnection;
  const url = cfg.url !== undefined && cfg.url.length > 0 ? cfg.url : manifestUrl;
  if (url === undefined || url.length === 0) {
    throw new Error('key-vault URL is not configured and the escrow manifest carries none');
  }
  return new KvVault({ ...cfg, url } as KeyVaultConnection);
}

/** An escrow-level wrapper for a key-vault client error: keeps the message, sets `cause`. */
export class KeyVaultError extends Error {
  constructor(message: string, cause: unknown) {
    super(message, { cause });
    this.name = 'KeyVaultError';
  }
}

/**
 * A resolved key-vault target for one escrow instance or operation. Holds
 * either a client instance or a connection config; builds the client lazily on
 * first use (dynamic import of `tr-key-vault-client`). All calls wrap client
 * errors in {@link KeyVaultError} (message preserved, `cause` set to the
 * underlying typed error).
 */
export class KvVault {
  readonly #value: KeyVaultConnection | KeyVaultClient;
  /** The connection URL when known (config form), for manifest marking. */
  readonly #url: string | undefined;
  #client: KeyVaultClient | null = null;

  constructor(value: KeyVaultConnection | KeyVaultClient) {
    this.#value = value;
    this.#url =
      isClientInstance(value as object)
        ? undefined
        : ((value as KeyVaultConnection).url as string);
  }

  /** The vault base URL when known (config form); undefined for an injected client. */
  get url(): string | undefined {
    return this.#url;
  }

  async #getClient(): Promise<KeyVaultClient> {
    if (this.#client !== null) return this.#client;
    if (isClientInstance(this.#value as object)) {
      this.#client = this.#value as KeyVaultClient;
      return this.#client;
    }
    // Lazy: tr-key-vault-client is loaded only here, on first actual use.
    const mod = (await import('tr-key-vault-client')) as unknown as {
      default: typeof KeyVaultClient;
    };
    const Ctor = mod.default;
    this.#client = new Ctor(this.#value as KeyVaultClientOptions);
    return this.#client;
  }

  /** Generates a per-escrow key in the vault; returns `{ kid, key(public JWK) }`. */
  async generateKey(
    alg: KvKeyAlgorithm,
    options: { crv?: KvKeyCrv; keyLength?: number; exp?: number },
  ): Promise<{ kid: string; key: Record<string, unknown> }> {
    let client: KeyVaultClient;
    try {
      client = await this.#getClient();
    } catch (err) {
      throw new KeyVaultError(
        `failed to load the key-vault client: ${(err as Error).message}`,
        err,
      );
    }
    try {
      const genOpts: {
        returnPublicKey: true;
        crv?: string;
        keyLength?: number;
        exp?: number;
      } = { returnPublicKey: true };
      if (alg === 'ECDH-ES') {
        if (options.crv !== undefined) genOpts.crv = options.crv;
      } else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
        if (options.keyLength !== undefined) genOpts.keyLength = options.keyLength;
      }
      // ML-KEM: the variant is encoded in the algorithm name; the vault
      // rejects crv/keyLength for it, so neither is ever sent.
      if (options.exp !== undefined) genOpts.exp = options.exp;
      const result = await client.generateKey(alg, genOpts);
      if (!result || typeof result.kid !== 'string' || !result.key) {
        throw new Error('key vault did not return a public key');
      }
      return { kid: result.kid, key: result.key };
    } catch (err) {
      throw new KeyVaultError(`key-vault generate-key failed: ${(err as Error).message}`, err);
    }
  }

  /** Decrypts a JWE with the vault-held key; returns the payload claims object. */
  async decryptJwe(token: string, kid: string): Promise<Record<string, unknown>> {
    let client: KeyVaultClient;
    try {
      client = await this.#getClient();
    } catch (err) {
      throw new KeyVaultError(
        `failed to load the key-vault client: ${(err as Error).message}`,
        err,
      );
    }
    try {
      const result = await client.decryptJwe(token, { kid });
      const data = result?.data;
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('key vault returned a non-object payload');
      }
      return data as Record<string, unknown>;
    } catch (err) {
      throw new KeyVaultError(`key-vault decrypt-jwe failed: ${(err as Error).message}`, err);
    }
  }

  /** Best-effort revoke of a vault key; never throws. */
  async revokeKeyBestEffort(kid: string): Promise<void> {
    try {
      const client = await this.#getClient();
      await client.revokeKey(kid);
    } catch {
      /* best effort — no sweat if this fails */
    }
  }
}
