import type { Readable } from 'node:stream';
import { UnknownFileIdError } from './decrypt-errors';
import {
  decryptTrdeToBuffer,
  decryptTrdeToFile,
  decryptTrdeToStream,
  type TrdeSource,
} from './trde-decrypt';

/**
 * A manifest node that carries a `payload` token, augmented with its decrypted
 * claims and the JWE content-encryption key that opened it. The content key
 * allows proving later that `payloadData` came from exactly that `payload`
 * token (tr-jwe `decrypt(payload, payloadContentKey)` must reproduce it)
 * without re-exposing the escrow secret key or the wrapping key.
 */
export interface DecryptedPayload {
  payload: string;
  payloadData: Record<string, unknown>;
  payloadContentKey: Record<string, unknown>;
}

/** An augmented `data`/`file` manifest entry. */
export interface DecryptedItem extends DecryptedPayload {
  ref?: string;
}

/** The augmented escrow manifest returned by {@link DataEscrowDecryptOperation.data}. */
export interface DecryptedManifest {
  metadata: DecryptedPayload & {
    id: string;
    kid: string;
    iat: number;
    exp?: number;
    ref?: string;
  };
  data?: Record<string, DecryptedItem>;
  file?: Record<string, DecryptedItem>;
}

/**
 * A decrypted escrow, returned by `DataEscrowDecrypt.decrypt()`. Exposes the
 * original and augmented manifests as deep copies and decrypts the escrow's
 * physical files. Holds its own key material (the per-file content keys, never
 * the escrow secret key), so its lifecycle is independent of the
 * `DataEscrowDecrypt` that created it. Instances are not meant to be
 * constructed directly.
 */
export class DataEscrowDecryptOperation {
  #original: Record<string, unknown> | null;
  #augmented: DecryptedManifest | null;
  #fileKeys: Map<string, Record<string, unknown>> | null;

  /** @internal Use `DataEscrowDecrypt.decrypt()`. */
  constructor(
    original: Record<string, unknown>,
    augmented: DecryptedManifest,
    fileKeys: Map<string, Record<string, unknown>>,
  ) {
    this.#original = original;
    this.#augmented = augmented;
    this.#fileKeys = fileKeys;
  }

  #checkState(): void {
    if (this.#fileKeys === null) {
      throw new TypeError('escrow decrypt operation is destroyed');
    }
  }

  /** Deep copy of the escrow object exactly as it was passed to `decrypt()`. */
  originalData(): Record<string, unknown> {
    this.#checkState();
    return structuredClone(this.#original) as Record<string, unknown>;
  }

  /**
   * Deep copy of the augmented manifest: the original structure with
   * `payloadData` / `payloadContentKey` siblings added next to every
   * `payload`. A fresh copy on every call; mutating it never affects this
   * instance.
   */
  data(): DecryptedManifest {
    this.#checkState();
    return structuredClone(this.#augmented) as DecryptedManifest;
  }

  /** The content key for a file of this escrow, or {@link UnknownFileIdError}. */
  #fileKey(fileId: unknown): Record<string, unknown> {
    this.#checkState();
    const key = typeof fileId === 'string' ? this.#fileKeys!.get(fileId) : undefined;
    if (key === undefined) {
      throw new UnknownFileIdError(fileId);
    }
    return key;
  }

  /**
   * Decrypts the file's TRDE container from `source` to the path
   * `destination`, atomically: the plaintext streams into a temporary file
   * next to the destination and is renamed into place only after full
   * verification; on any failure nothing appears at the path. The entry's
   * `payloadData.name` is metadata only — the caller chooses the path.
   * Resolves to `true`.
   */
  async decryptFile(fileId: string, source: TrdeSource, destination: string): Promise<true> {
    return decryptTrdeToFile(source, this.#fileKey(fileId), destination);
  }

  /**
   * Decrypts the file's TRDE container from `source` to a plaintext
   * `Readable`. The container header is validated before the promise
   * resolves. Caveat inherent to streamed AEAD: plaintext flows before the
   * GCM tag is verified — a tag or decompression failure surfaces as an
   * `'error'` event on the stream and the caller must discard the output.
   */
  async decryptFileToStream(fileId: string, source: TrdeSource): Promise<Readable> {
    return decryptTrdeToStream(source, this.#fileKey(fileId));
  }

  /**
   * Decrypts the file's TRDE container from `source` fully into memory,
   * verified before return; only for files that fit in memory.
   */
  async decryptFileToBuffer(fileId: string, source: TrdeSource): Promise<Buffer> {
    return decryptTrdeToBuffer(source, this.#fileKey(fileId));
  }

  /**
   * Clears the internal references — per-file content keys, decrypted claims,
   * both manifest copies — and invalidates the object: every other method
   * throws afterwards. Synchronous, idempotent.
   */
  destroy(): void {
    this.#original = null;
    this.#augmented = null;
    this.#fileKeys?.clear();
    this.#fileKeys = null;
  }
}
