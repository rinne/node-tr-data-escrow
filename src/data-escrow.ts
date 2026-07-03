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
  validateRsaModulusLength,
  DEFAULT_AUTO_KEY_ALGORITHM,
  DEFAULT_RSA_MODULUS_LENGTH,
  type AutoKeyAlgorithm,
} from './auto-key';
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
   *   - RSA-OAEP: `{ kty:'RSA', alg:'RSA-OAEP', kid, n, e }`, modulus >= 2048 bits
   *   - EC:       `{ kty:'EC', crv:'P-256'|'P-384'|'P-521', kid, x, y }`
   * Must carry a non-empty `kid` (the `auto:` prefix is reserved) and must
   * not contain private material. May be omitted (or `null`) **only** when
   * `autoKey` is `true`; without autoKey it is required. Overridable per
   * operation in `createEscrow` options, including to `null` ("no escrow key
   * for this operation" — again only with autoKey on).
   */
  escrowKey?: Record<string, unknown> | null;
  /**
   * Default for the auto-key layer (default `false`). When an operation's
   * effective autoKey is on, a fresh key pair is generated for that escrow,
   * the metadata payload is encrypted to its public half, and the private
   * half is returned by `autoKeyPair()` and/or sealed to the escrow key into
   * `auto-key.json`. Overridable per operation.
   */
  autoKey?: boolean | null;
  /**
   * Default auto key algorithm: `"P-256"`, `"P-384"`, `"P-521"` (default),
   * or `"RSA-OAEP"`. Always validated when submitted, even while unused.
   * Overridable per operation.
   */
  autoKeyAlgorithm?: AutoKeyAlgorithm | null;
  /**
   * Default RSA modulus length in bits for `"RSA-OAEP"` auto keys: an
   * integer, 2048..16384 (default 4096). Consulted only when an RSA auto key
   * is actually generated, but always validated when submitted. Overridable
   * per operation.
   */
  rsaModulusLength?: number | null;
  /**
   * Optional default relative expiry in **seconds** after escrow creation,
   * applied to every escrow that does not specify its own
   * `expiresAt`/`expiresAfter`. A finite number >= 0, or null. Expiry is
   * advisory: stored, never enforced by this module. Passing `expiresAt` here
   * is not allowed.
   */
  expiresAfter?: number | null;
  /**
   * Default compression applied to file content before encryption:
   * `"none"` (default), `"deflate"`, `"gzip"`, or `"brotli"` (`"zstd"` is a
   * reserved container code, not yet enabled). Overridable per escrow in
   * `createEscrow` options and per file in `addFile*` options. Recorded only
   * in the encrypted-file container header, never in the escrow manifest.
   */
  compression?: CompressionName | null;
}

/**
 * Per-escrow options for {@link DataEscrow.escrow} and
 * {@link DataEscrow.createEscrow}. All name the **escrow itself** (in the
 * one-shot `escrow()` the lone data item carries no references of its own).
 */
export type EscrowOptions = EscrowOptionsInput;

/**
 * Write-only cryptographic escrow into a filesystem vault. Each escrow is one
 * self-contained directory holding an `escrow.json` manifest and, when files
 * are included, a `files/` directory of encrypted blobs. Data and per-file
 * keys are sealed as JWE to a public escrow key (RSA-OAEP or ECDH-ES); once
 * written, the running system holds only ciphertext — reading back requires
 * the escrow private key, which this class never possesses. Destroying that
 * private key permanently revokes access to everything escrowed under it.
 */
export class DataEscrow {
  readonly #escrowKeyInfo: EscrowKeyInfo | null;
  readonly #vaultDir: string;
  readonly #tmpDir: string;
  readonly #defaultExpiresAfter: number | null;
  readonly #defaultCompression: CompressionName;
  readonly #defaultAutoKey: boolean;
  readonly #defaultAutoKeyAlgorithm: AutoKeyAlgorithm;
  readonly #defaultRsaModulusLength: number;

  /**
   * @param options see {@link DataEscrowOptions}. Validates synchronously and
   *                sets up the vault staging directory; throws on invalid
   *                configuration or an unusable vault.
   */
  constructor(options: DataEscrowOptions) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('options object with vaultDir and escrowKey is required');
    }

    this.#defaultAutoKey = validateAutoKey(options.autoKey) ?? false;
    this.#defaultAutoKeyAlgorithm =
      validateAutoKeyAlgorithm(options.autoKeyAlgorithm) ?? DEFAULT_AUTO_KEY_ALGORITHM;
    this.#defaultRsaModulusLength =
      validateRsaModulusLength(options.rsaModulusLength) ?? DEFAULT_RSA_MODULUS_LENGTH;

    if (options.escrowKey === undefined || options.escrowKey === null) {
      if (!this.#defaultAutoKey) {
        throw new TypeError('escrowKey is required when autoKey is not enabled');
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
   * constructed without one (autoKey-only operation).
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
   * including `null`). Returns the new escrow's id. The options are
   * escrow-level; for multiple data items, files, or item-level references use
   * {@link createEscrow}.
   */
  async escrow(data: unknown, options: EscrowOptions = {}): Promise<string> {
    if (!options || typeof options !== 'object') {
      throw new TypeError('escrow options must be an object');
    }
    // The one-shot flow can never call autoKeyPair(), so without an escrow
    // key (and thus without auto-key.json) the escrow would be unrecoverable
    // from birth — reject before creating anything.
    if (this.#resolveKeyOptions(options).escrowKeyInfo === null) {
      throw new TypeError(
        'one-shot escrow() requires an escrow key: without one the auto key pair could never be collected',
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
   * Resolves the effective escrow key and auto-key options for one operation
   * (`op ?? constructor ?? default`), enforcing that an operation without an
   * effective escrow key has autoKey enabled. Cheap: validation only, no key
   * generation.
   */
  #resolveKeyOptions(options: EscrowOptions): {
    escrowKeyInfo: EscrowKeyInfo | null;
    autoKey: boolean;
    autoKeyAlgorithm: AutoKeyAlgorithm;
    rsaModulusLength: number;
  } {
    const autoKey = validateAutoKey(options.autoKey) ?? this.#defaultAutoKey;
    const autoKeyAlgorithm =
      validateAutoKeyAlgorithm(options.autoKeyAlgorithm) ?? this.#defaultAutoKeyAlgorithm;
    const rsaModulusLength =
      validateRsaModulusLength(options.rsaModulusLength) ?? this.#defaultRsaModulusLength;
    // Unlike the options above, escrowKey distinguishes null from undefined:
    // undefined/absent inherits the constructor key, null means "none".
    let escrowKeyInfo: EscrowKeyInfo | null;
    if (options.escrowKey === undefined) {
      escrowKeyInfo = this.#escrowKeyInfo;
    } else if (options.escrowKey === null) {
      escrowKeyInfo = null;
    } else {
      escrowKeyInfo = validateEscrowKey(options.escrowKey);
    }
    if (escrowKeyInfo === null && !autoKey) {
      throw new TypeError(
        'an escrow operation without an escrow key requires autoKey to be enabled',
      );
    }
    return { escrowKeyInfo, autoKey, autoKeyAlgorithm, rsaModulusLength };
  }

  /**
   * Begins a multi-step escrow: resolves `iat`/`exp`, generates the per-escrow
   * wrapping key (and, with autoKey on, the auto key pair), seals the wrapping
   * key (with all metadata) into the metadata payload, and creates the
   * escrow's staging directory under `<vault>/.tmp/`. Returns a
   * {@link DataEscrowOperation}; nothing appears in the vault proper until
   * its `commit()`.
   */
  async createEscrow(options: EscrowOptions = {}): Promise<DataEscrowOperation> {
    if (!options || typeof options !== 'object') {
      throw new TypeError('escrow options must be an object');
    }
    const { escrowKeyInfo, autoKey, autoKeyAlgorithm, rsaModulusLength } =
      this.#resolveKeyOptions(options);
    const reference = validateReference(options.reference, 'reference');
    const encryptedReference = validateReference(
      options.encryptedReference,
      'encryptedReference',
    );
    const iat = Math.floor(Date.now() / 1000);
    const exp = resolveExp(options, this.#defaultExpiresAfter, iat);
    const fileCompression = validateCompression(options.compression) ?? this.#defaultCompression;

    const escrowId = randomUUID().toLowerCase();
    const wrappingKey = cipherKeyGen('A256GCMKW');
    const autoPair = autoKey ? await generateAutoKeyPair(autoKeyAlgorithm, rsaModulusLength) : null;

    // With autoKey on, the metadata payload is encrypted to the auto public
    // key and the manifest kid is the auto kid; otherwise to the escrow key
    // exactly as before.
    const metadataAlg = autoPair !== null ? autoPair.alg : escrowKeyInfo!.escrowAlg;
    const metadataKey = autoPair !== null ? autoPair.publicKey : escrowKeyInfo!.escrowKey;
    const metadataKid = autoPair !== null ? autoPair.kid : escrowKeyInfo!.escrowKid;
    // The sealed metadata duplicates every cleartext manifest field (plus the
    // optional cref) so the reader can detect manifest tampering, and carries
    // the wrapping key that opens all other payloads of this escrow.
    const metadataPayload = encrypt(metadataAlg, metadataKey, {
      id: escrowId,
      kid: metadataKid,
      iat,
      ...(exp !== undefined ? { exp } : {}),
      ...(reference !== null ? { ref: reference } : {}),
      ...(encryptedReference !== null ? { cref: encryptedReference } : {}),
      key: wrappingKey,
    });

    // With both the auto key and an escrow key, the auto secret key is sealed
    // to the escrow key eagerly; the operation writes it out as auto-key.json
    // at commit. Sealed claims follow the metadata style minus id.
    let autoKeyFile: Record<string, unknown> | undefined;
    if (autoPair !== null && escrowKeyInfo !== null) {
      const payload = encrypt(escrowKeyInfo.escrowAlg, escrowKeyInfo.escrowKey, {
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
    await mkdir(tmpDir); // non-recursive: fails loudly on an id collision

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
      fileCompression,
      tmpDir,
      finalParent: join(this.#vaultDir, prefix),
      finalDir: join(this.#vaultDir, prefix, escrowId),
    });
  }
}
