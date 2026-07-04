import { randomUUID } from 'node:crypto';
import { mkdirSync, accessSync, constants as fsConstants } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { resolve as resolvePath, join } from 'node:path';
import { encrypt } from 'tr-jwe';
import { cipherKeyGen } from './key-gen';
import {
  generateAutoKeyPair,
  validateAutoKey,
  validateAutoKeyAlgorithm,
  validateAutoKeyCrv,
  validateAutoKeyLength,
  DEFAULT_AUTO_KEY_ALGORITHM,
  DEFAULT_AUTO_KEY_CRV,
  DEFAULT_AUTO_KEY_LENGTH,
  type AutoKeyAlgorithm,
  type AutoKeyCrv,
} from './auto-key';
import {
  KvVault,
  validateKvKey,
  validateKvKeyAlgorithm,
  validateKvKeyCrv,
  validateKvKeyLength,
  validateKvOption,
  DEFAULT_KV_KEY_ALGORITHM,
  DEFAULT_KV_KEY_CRV,
  DEFAULT_KV_KEY_LENGTH,
  type KvKeyAlgorithm,
  type KvKeyCrv,
  type KvOption,
} from './kv';
import { validateEscrowKey, type EscrowKeyInfo } from './vault';
import { validateCompression, type CompressionName } from './trde';
import {
  validateReference,
  validateDefaultExpiresAfter,
  resolveExp,
  type EscrowOptionsInput,
} from './util';
import { DataEscrowOperation } from './data-escrow-operation';

/** Construction options for {@link DataEscrow}. */
export interface DataEscrowOptions {
  /**
   * The vault directory. **Required.** Escrows are stored as self-contained
   * directories `<vaultDir>/<prefix>/<escrow-id>/`; a `.tmp` staging
   * subdirectory is created and write-tested synchronously in the constructor.
   */
  vaultDir: string;
  /**
   * The **public** escrow key (JWK). One of:
   *   - RSA-OAEP / RSA-OAEP-256: `{ kty:'RSA', alg, kid, n, e }`, modulus >= 2048
   *   - EC:       `{ kty:'EC', crv:'P-256'|'P-384'|'P-521', kid, x, y }`
   * Must carry a non-empty `kid` (the `auto:` prefix is reserved) and must not
   * contain private material. May be omitted (or `null`) **only** when
   * `autoKey` or `kvKey` is `true`; otherwise it is required. Overridable per
   * operation, including to `null`.
   */
  escrowKey?: Record<string, unknown> | null;
  /**
   * Default for the auto-key layer (default `false`). When an operation's
   * effective autoKey is on, a fresh key pair is generated locally for that
   * escrow, the metadata payload is encrypted to its public half, and the
   * private half is returned by `autoKeyPair()` and/or sealed to the escrow
   * key into `auto-key.json`. Mutually exclusive with `kvKey`. Overridable per
   * operation.
   */
  autoKey?: boolean | null;
  /**
   * Default auto key algorithm: `"ECDH-ES"` (default), `"RSA-OAEP"`, or
   * `"RSA-OAEP-256"`. Always validated when submitted, even while unused.
   * Overridable per operation.
   */
  autoKeyAlgorithm?: AutoKeyAlgorithm | null;
  /**
   * Default EC curve for an `ECDH-ES` auto key: `"P-256"`, `"P-384"`, or
   * `"P-521"` (default). Consulted only for ECDH-ES. Overridable per operation.
   */
  autoKeyCrv?: AutoKeyCrv | null;
  /**
   * Default RSA modulus length in bits for RSA auto keys: an integer,
   * 2048..16384 (default 4096). Consulted only for RSA. Overridable per
   * operation.
   */
  autoKeyLength?: number | null;
  /**
   * Default for the key-vault layer (default `false`). When an operation's
   * effective kvKey is on, the per-escrow key is generated in the key-vault
   * server (`kv`); the metadata payload is encrypted to its public half, the
   * private half never leaves the vault, and the escrow's expiry is enforced by
   * the vault (the key is deleted at expiry). Mutually exclusive with
   * `autoKey`. Overridable per operation.
   */
  kvKey?: boolean | null;
  /** Default key-vault key algorithm (default `"ECDH-ES"`). Overridable per operation. */
  kvKeyAlgorithm?: KvKeyAlgorithm | null;
  /** Default EC curve for an ECDH-ES key-vault key (default `"P-521"`). Overridable. */
  kvKeyCrv?: KvKeyCrv | null;
  /** Default RSA modulus bits for an RSA key-vault key (default 4096). Overridable. */
  kvKeyLength?: number | null;
  /**
   * The key-vault connection: a connection config
   * (`{ url, user?, token?, timeout?, insecure?, ca? }`) or an already-built
   * `KeyVaultClient` instance. Required (here or per operation) whenever the
   * effective mode is `kvKey`. `tr-key-vault-client` is loaded lazily on first
   * actual use.
   */
  kv?: KvOption;
  /**
   * Optional default relative expiry in **seconds** after escrow creation,
   * applied to every escrow that does not specify its own
   * `expiresAt`/`expiresAfter`. A finite number >= 0, or null. For plain/auto
   * escrows the expiry is advisory; for a kvKey escrow it is enforced by the
   * vault. Passing `expiresAt` here is not allowed.
   */
  expiresAfter?: number | null;
  /**
   * Default compression applied to file content before encryption: `"none"`
   * (default), `"deflate"`, `"gzip"`, or `"brotli"`. Overridable per escrow and
   * per file. Recorded only in the encrypted-file container header.
   */
  compression?: CompressionName | null;
}

/**
 * Per-escrow options for {@link DataEscrow.escrow} and
 * {@link DataEscrow.createEscrow}.
 */
export type EscrowOptions = EscrowOptionsInput;

/** @internal Resolved per-operation key configuration. */
interface ResolvedKeyOptions {
  escrowKeyInfo: EscrowKeyInfo | null;
  autoKey: boolean;
  autoKeyAlgorithm: AutoKeyAlgorithm;
  autoKeyCrv: AutoKeyCrv;
  autoKeyLength: number;
  kvKey: boolean;
  kvKeyAlgorithm: KvKeyAlgorithm;
  kvKeyCrv: KvKeyCrv;
  kvKeyLength: number;
  kvVault: KvVault | null;
}

/**
 * Write-only cryptographic escrow into a filesystem vault. Each escrow is one
 * self-contained directory holding an `escrow.json` manifest and, when files
 * are included, a `files/` directory of encrypted blobs. The metadata is sealed
 * as JWE to a public key — a long-lived escrow key, a per-escrow auto key, or a
 * per-escrow key held in a key-vault server. Reading back requires the
 * corresponding private key, which for escrow/auto keys this class never
 * possesses and for kvKey escrows lives only in the vault.
 */
export class DataEscrow {
  readonly #escrowKeyInfo: EscrowKeyInfo | null;
  readonly #vaultDir: string;
  readonly #tmpDir: string;
  readonly #defaultExpiresAfter: number | null;
  readonly #defaultCompression: CompressionName;
  readonly #defaultAutoKey: boolean;
  readonly #defaultAutoKeyAlgorithm: AutoKeyAlgorithm;
  readonly #defaultAutoKeyCrv: AutoKeyCrv;
  readonly #defaultAutoKeyLength: number;
  readonly #defaultKvKey: boolean;
  readonly #defaultKvKeyAlgorithm: KvKeyAlgorithm;
  readonly #defaultKvKeyCrv: KvKeyCrv;
  readonly #defaultKvKeyLength: number;
  readonly #kvVault: KvVault | null;

  /**
   * @param options see {@link DataEscrowOptions}. Validates synchronously and
   *                sets up the vault staging directory; throws on invalid
   *                configuration or an unusable vault. No network I/O (the
   *                key-vault client is built lazily).
   */
  constructor(options: DataEscrowOptions) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('options object with vaultDir is required');
    }

    this.#defaultAutoKey = validateAutoKey(options.autoKey) ?? false;
    this.#defaultAutoKeyAlgorithm =
      validateAutoKeyAlgorithm(options.autoKeyAlgorithm) ?? DEFAULT_AUTO_KEY_ALGORITHM;
    this.#defaultAutoKeyCrv = validateAutoKeyCrv(options.autoKeyCrv) ?? DEFAULT_AUTO_KEY_CRV;
    this.#defaultAutoKeyLength = validateAutoKeyLength(options.autoKeyLength) ?? DEFAULT_AUTO_KEY_LENGTH;

    this.#defaultKvKey = validateKvKey(options.kvKey) ?? false;
    this.#defaultKvKeyAlgorithm =
      validateKvKeyAlgorithm(options.kvKeyAlgorithm) ?? DEFAULT_KV_KEY_ALGORITHM;
    this.#defaultKvKeyCrv = validateKvKeyCrv(options.kvKeyCrv) ?? DEFAULT_KV_KEY_CRV;
    this.#defaultKvKeyLength = validateKvKeyLength(options.kvKeyLength) ?? DEFAULT_KV_KEY_LENGTH;

    // Both modes on in the constructor options is an unusable configuration.
    if (options.autoKey === true && options.kvKey === true) {
      throw new TypeError('autoKey and kvKey cannot both be enabled');
    }

    const kvOption = validateKvOption(options.kv);
    this.#kvVault = kvOption === null ? null : new KvVault(kvOption);

    if (options.escrowKey === undefined || options.escrowKey === null) {
      if (!this.#defaultAutoKey && !this.#defaultKvKey) {
        throw new TypeError('escrowKey is required when neither autoKey nor kvKey is enabled');
      }
      this.#escrowKeyInfo = null;
    } else {
      this.#escrowKeyInfo = validateEscrowKey(options.escrowKey);
    }

    if (Object.prototype.hasOwnProperty.call(options, 'expiresAt')) {
      throw new TypeError(
        'expiresAt is not a constructor option; pass expiresAfter as a default, ' +
          'or set expiresAt per escrow',
      );
    }
    this.#defaultExpiresAfter = validateDefaultExpiresAfter(options.expiresAfter);
    this.#defaultCompression = validateCompression(options.compression) ?? 'none';

    if (typeof options.vaultDir !== 'string' || options.vaultDir.length === 0) {
      throw new TypeError('vaultDir must be a non-empty string');
    }
    const vaultDir = resolvePath(options.vaultDir);
    const tmpDir = join(vaultDir, '.tmp');
    try {
      mkdirSync(tmpDir, { recursive: true });
      accessSync(tmpDir, fsConstants.W_OK);
    } catch (err) {
      throw new Error(`vault staging directory ${JSON.stringify(tmpDir)} is not usable`, {
        cause: err,
      });
    }
    this.#vaultDir = vaultDir;
    this.#tmpDir = tmpDir;
  }

  /**
   * The kid of the constructor's escrow key, or `null` when the instance was
   * constructed without one (auto/kv-only operation).
   */
  get escrowKid(): string | null {
    return this.#escrowKeyInfo?.escrowKid ?? null;
  }

  /** The resolved absolute vault directory. */
  get vaultDir(): string {
    return this.#vaultDir;
  }

  /**
   * One-shot escrow of a single data item (any JSON-serializable value,
   * including `null`). Returns the new escrow's id.
   */
  async escrow(data: unknown, options: EscrowOptions = {}): Promise<string> {
    if (!options || typeof options !== 'object') {
      throw new TypeError('escrow options must be an object');
    }
    // The one-shot flow can never call autoKeyPair(), so an auto escrow with
    // no escrow key (hence no auto-key.json) would be unrecoverable from birth.
    // kvKey escrows are recoverable via the vault, so they are fine here.
    const resolved = this.#resolveKeyOptions(options);
    if (resolved.autoKey && resolved.escrowKeyInfo === null) {
      throw new TypeError(
        'one-shot escrow() with autoKey requires an escrow key: without one the ' +
          'auto key pair could never be collected',
      );
    }
    const op = await this.createEscrow(options);
    try {
      await op.addData(data);
      return await op.commit();
    } catch (err) {
      await op.destroy().catch(() => {});
      throw err;
    }
  }

  /**
   * Resolves the effective escrow / auto-key / kv-key options for one
   * operation (`op ?? constructor ?? default`), enforcing mutual exclusion of
   * autoKey/kvKey, the escrow-key requirement, and the escrowKey+kvKey ban.
   * Cheap: validation only, no key generation and no network I/O.
   */
  #resolveKeyOptions(options: EscrowOptions): ResolvedKeyOptions {
    const autoKey = validateAutoKey(options.autoKey) ?? this.#defaultAutoKey;
    const kvKey = validateKvKey(options.kvKey) ?? this.#defaultKvKey;
    if (autoKey && kvKey) {
      throw new TypeError(
        'autoKey and kvKey cannot both be enabled for one escrow; to switch modes ' +
          'per operation, disable the inherited one explicitly, e.g. ' +
          '{ autoKey: false, kvKey: true }',
      );
    }
    const autoKeyAlgorithm =
      validateAutoKeyAlgorithm(options.autoKeyAlgorithm) ?? this.#defaultAutoKeyAlgorithm;
    const autoKeyCrv = validateAutoKeyCrv(options.autoKeyCrv) ?? this.#defaultAutoKeyCrv;
    const autoKeyLength = validateAutoKeyLength(options.autoKeyLength) ?? this.#defaultAutoKeyLength;
    const kvKeyAlgorithm =
      validateKvKeyAlgorithm(options.kvKeyAlgorithm) ?? this.#defaultKvKeyAlgorithm;
    const kvKeyCrv = validateKvKeyCrv(options.kvKeyCrv) ?? this.#defaultKvKeyCrv;
    const kvKeyLength = validateKvKeyLength(options.kvKeyLength) ?? this.#defaultKvKeyLength;

    // Effective vault connection: per-op override, else the constructor's.
    const kvOverride = validateKvOption(options.kv);
    const kvVault = kvOverride === null ? this.#kvVault : new KvVault(kvOverride);

    // escrowKey distinguishes null from undefined (undefined inherits, null
    // means "none"). With kvKey the escrow key is never used as a recipient.
    let escrowKeyInfo: EscrowKeyInfo | null;
    if (options.escrowKey === undefined) {
      escrowKeyInfo = this.#escrowKeyInfo;
    } else if (options.escrowKey === null) {
      escrowKeyInfo = null;
    } else {
      escrowKeyInfo = validateEscrowKey(options.escrowKey);
    }
    if (kvKey && escrowKeyInfo !== null) {
      throw new TypeError(
        'escrowKey and kvKey cannot both be set: a kvKey escrow encrypts its ' +
          'metadata to the vault key, leaving the escrow key unused',
      );
    }
    if (escrowKeyInfo === null && !autoKey && !kvKey) {
      throw new TypeError(
        'an escrow operation without an escrow key requires autoKey or kvKey',
      );
    }
    if (kvKey && kvVault === null) {
      throw new TypeError('kvKey requires a key-vault connection (the `kv` option)');
    }
    return {
      escrowKeyInfo,
      autoKey,
      autoKeyAlgorithm,
      autoKeyCrv,
      autoKeyLength,
      kvKey,
      kvKeyAlgorithm,
      kvKeyCrv,
      kvKeyLength,
      kvVault,
    };
  }

  /**
   * Begins a multi-step escrow: resolves `iat`/`exp`, generates the per-escrow
   * wrapping key and (per mode) the metadata-recipient key, seals the metadata
   * payload, and creates the escrow's staging directory. Returns a
   * {@link DataEscrowOperation}; nothing appears in the vault proper until its
   * `commit()`.
   */
  async createEscrow(options: EscrowOptions = {}): Promise<DataEscrowOperation> {
    if (!options || typeof options !== 'object') {
      throw new TypeError('escrow options must be an object');
    }
    const resolved = this.#resolveKeyOptions(options);
    const reference = validateReference(options.reference, 'reference');
    const encryptedReference = validateReference(options.encryptedReference, 'encryptedReference');
    const iat = Math.floor(Date.now() / 1000);
    const exp = resolveExp(options, this.#defaultExpiresAfter, iat);
    const fileCompression = validateCompression(options.compression) ?? this.#defaultCompression;

    // A kvKey escrow hands `exp` to the vault as a hard deletion deadline; a
    // non-future deadline is a user error the vault would reject anyway.
    if (resolved.kvKey && exp !== undefined && exp <= iat) {
      throw new TypeError('a kvKey escrow expiry must be in the future (exp <= now)');
    }

    const escrowId = randomUUID().toLowerCase();
    const wrappingKey = cipherKeyGen('A256GCMKW');

    // Resolve the metadata recipient: kvKey > autoKey > escrow key.
    let metadataAlg: string;
    let metadataKey: Record<string, unknown>;
    let metadataKid: string;
    let autoPair: Awaited<ReturnType<typeof generateAutoKeyPair>> | null = null;
    let kvKid: string | null = null;
    let kvMarker: { url?: string } | undefined;

    if (resolved.kvKey) {
      const kvVault = resolved.kvVault!;
      const { kid, key } = await kvVault.generateKey(resolved.kvKeyAlgorithm, {
        crv: resolved.kvKeyCrv,
        keyLength: resolved.kvKeyLength,
        exp,
      });
      metadataAlg = resolved.kvKeyAlgorithm;
      metadataKey = key;
      metadataKid = kid;
      kvKid = kid;
      kvMarker = kvVault.url !== undefined ? { url: kvVault.url } : {};
    } else if (resolved.autoKey) {
      autoPair = await generateAutoKeyPair(resolved.autoKeyAlgorithm, {
        crv: resolved.autoKeyCrv,
        length: resolved.autoKeyLength,
      });
      metadataAlg = autoPair.alg;
      metadataKey = autoPair.publicKey;
      metadataKid = autoPair.kid;
    } else {
      metadataAlg = resolved.escrowKeyInfo!.escrowAlg;
      metadataKey = resolved.escrowKeyInfo!.escrowKey;
      metadataKid = resolved.escrowKeyInfo!.escrowKid;
    }

    // The sealed metadata duplicates every cleartext manifest field (plus the
    // optional cref) for tamper-binding, and carries the wrapping key.
    let metadataPayload: string;
    try {
      metadataPayload = encrypt(metadataAlg, metadataKey, {
        id: escrowId,
        kid: metadataKid,
        iat,
        ...(exp !== undefined ? { exp } : {}),
        ...(reference !== null ? { ref: reference } : {}),
        ...(encryptedReference !== null ? { cref: encryptedReference } : {}),
        key: wrappingKey,
      });
    } catch (err) {
      // A kvKey escrow already created a vault key; roll it back best-effort.
      if (kvKid !== null && resolved.kvVault !== null) {
        await resolved.kvVault.revokeKeyBestEffort(kvKid);
      }
      throw err;
    }

    // With both an auto key and an escrow key, the auto secret key is sealed to
    // the escrow key eagerly; the operation writes it out as auto-key.json.
    let autoKeyFile: Record<string, unknown> | undefined;
    if (autoPair !== null && resolved.escrowKeyInfo !== null) {
      const payload = encrypt(resolved.escrowKeyInfo.escrowAlg, resolved.escrowKeyInfo.escrowKey, {
        kid: autoPair.kid,
        iat,
        ...(exp !== undefined ? { exp } : {}),
        key: autoPair.secretKey,
      });
      autoKeyFile = {
        kid: autoPair.kid,
        iat,
        ...(exp !== undefined ? { exp } : {}),
        payload,
      };
    }

    const prefix = escrowId.slice(0, 4);
    const tmpDir = join(this.#tmpDir, escrowId);
    try {
      await mkdir(tmpDir); // non-recursive: fails loudly on an id collision
    } catch (err) {
      if (kvKid !== null && resolved.kvVault !== null) {
        await resolved.kvVault.revokeKeyBestEffort(kvKid);
      }
      throw err;
    }

    return new DataEscrowOperation({
      escrowId,
      escrowKid: metadataKid,
      iat,
      exp,
      reference,
      metadataPayload,
      wrappingKey,
      autoKid: autoPair?.kid ?? null,
      autoKeyPair:
        autoPair !== null
          ? { secretKey: autoPair.secretKey, publicKey: autoPair.publicKey }
          : undefined,
      autoKeyFile,
      kvMarker,
      kvVault: kvKid !== null ? resolved.kvVault : null,
      kvKid,
      fileCompression,
      tmpDir,
      finalParent: join(this.#vaultDir, prefix),
      finalDir: join(this.#vaultDir, prefix, escrowId),
    });
  }
}
