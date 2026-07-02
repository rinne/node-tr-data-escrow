import { randomUUID } from 'node:crypto';
import { mkdirSync, accessSync, constants as fsConstants } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { resolve as resolvePath, join } from 'node:path';
import { cipherKeyGen } from 'tr-jwk';
import { encrypt } from 'tr-jwe';
import { validateEscrowKey } from './vault';
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
   * Must carry a non-empty `kid` and must not contain private material.
   */
  escrowKey: Record<string, unknown>;
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
  readonly #escrowKey: Record<string, unknown>;
  readonly #escrowKid: string;
  readonly #escrowAlg: 'RSA-OAEP' | 'ECDH-ES';
  readonly #vaultDir: string;
  readonly #tmpDir: string;
  readonly #defaultExpiresAfter: number | null;
  readonly #defaultCompression: CompressionName;

  /**
   * @param options see {@link DataEscrowOptions}. Validates synchronously and
   *                sets up the vault staging directory; throws on invalid
   *                configuration or an unusable vault.
   */
  constructor(options: DataEscrowOptions) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('options object with vaultDir and escrowKey is required');
    }

    const info = validateEscrowKey(options.escrowKey);
    this.#escrowKey = info.escrowKey;
    this.#escrowKid = info.escrowKid;
    this.#escrowAlg = info.escrowAlg;

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

  /** The escrow key identifier (`kid`) recorded in every escrow this instance writes. */
  get escrowKid(): string {
    return this.#escrowKid;
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
   * Begins a multi-step escrow: resolves `iat`/`exp`, generates the per-escrow
   * wrapping key, seals it (with all metadata) into the metadata payload,
   * and creates the escrow's staging directory under `<vault>/.tmp/`. Returns
   * a {@link DataEscrowOperation}; nothing appears in the vault proper until
   * its `commit()`.
   */
  async createEscrow(options: EscrowOptions = {}): Promise<DataEscrowOperation> {
    if (!options || typeof options !== 'object') {
      throw new TypeError('escrow options must be an object');
    }
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
    // The sealed metadata duplicates every cleartext manifest field (plus the
    // optional cref) so the reader can detect manifest tampering, and carries
    // the wrapping key that opens all other payloads of this escrow.
    const metadataPayload = encrypt(this.#escrowAlg, this.#escrowKey, {
      id: escrowId,
      kid: this.#escrowKid,
      iat,
      ...(exp !== undefined ? { exp } : {}),
      ...(reference !== null ? { ref: reference } : {}),
      ...(encryptedReference !== null ? { cref: encryptedReference } : {}),
      key: wrappingKey,
    });

    const prefix = escrowId.slice(0, 4);
    const tmpDir = join(this.#tmpDir, escrowId);
    await mkdir(tmpDir); // non-recursive: fails loudly on an id collision

    return new DataEscrowOperation({
      escrowId,
      escrowKid: this.#escrowKid,
      iat,
      exp,
      reference,
      metadataPayload,
      wrappingKey,
      fileCompression,
      tmpDir,
      finalParent: join(this.#vaultDir, prefix),
      finalDir: join(this.#vaultDir, prefix, escrowId),
    });
  }
}
