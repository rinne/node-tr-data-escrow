import { randomUUID } from 'node:crypto';
import { createReadStream, rmSync } from 'node:fs';
import { mkdir, open, rename, rm } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { Readable } from 'node:stream';
import { encrypt } from 'tr-jwe';
import { cipherKeyGen } from './key-gen';
import { streamEncryptToFile, fsyncDir } from './vault';
import { validateCompression, type CompressionName } from './trde';
import { ReferenceConflictError } from './errors';
import { serializeGuard, validateName, validateReference } from './util';
import type { KvVault } from './kv';

/** Options for {@link DataEscrowOperation.addData}. */
export interface AddDataOptions {
  /** Optional cleartext reference, unique among this escrow's items. */
  reference?: string | null;
  /** Optional sealed reference, stored only inside the encrypted payload. */
  encryptedReference?: string | null;
}

/** Options for the `addFile*` methods. `name` is required for stream/buffer input. */
export interface AddFileOptions extends AddDataOptions {
  /** Restore basename. For `addFile` defaults to the source file's basename. */
  name?: string;
  /**
   * Compression for this file's content (before encryption), overriding the
   * escrow/constructor default. Recorded only in the container header.
   */
  compression?: CompressionName | null;
}

/** The auto key pair of one escrow operation, as returned by `autoKeyPair()`. */
export interface AutoKeyPairResult {
  /** The auto private JWK (contains the public parameters too). */
  secretKey: Record<string, unknown>;
  /** The auto public JWK. */
  publicKey: Record<string, unknown>;
}

/** @internal Context handed from {@link DataEscrow.createEscrow} to an operation. */
export interface EscrowContext {
  escrowId: string;
  /** The manifest `metadata.kid`: the auto kid with autoKey on, else the escrow key kid. */
  escrowKid: string;
  iat: number;
  exp: number | undefined;
  reference: string | null;
  metadataPayload: string;
  wrappingKey: Record<string, unknown>;
  /** The `auto:`-prefixed auto key id, or null when autoKey is off. */
  autoKid: string | null;
  /** The generated auto key pair; present iff autoKey is on. */
  autoKeyPair?: AutoKeyPairResult;
  /**
   * The cleartext auto-key.json object (`{ kid, iat, exp?, payload }`, the
   * payload sealed to the escrow key); present iff autoKey is on **and** the
   * operation has an escrow key. Written out at commit.
   */
  autoKeyFile?: Record<string, unknown>;
  /**
   * The `metadata.kv` marker object written to the manifest for a kvKey escrow
   * (`{ url }` when the vault URL is known, else `{}`); undefined otherwise.
   */
  kvMarker?: { url?: string };
  /** The key-vault target, for best-effort revoke of an abandoned kv key. */
  kvVault?: KvVault | null;
  /** The kv key id to revoke if this operation never commits. */
  kvKid?: string | null;
  /** Resolved default compression for this escrow's files. */
  fileCompression: CompressionName;
  /** `<vault>/.tmp/<escrow-id>` — already created. */
  tmpDir: string;
  /** `<vault>/<prefix>` — created at commit. */
  finalParent: string;
  /** `<vault>/<prefix>/<escrow-id>`. */
  finalDir: string;
}

type State = 'pending' | 'committed' | 'destroyed';

interface ItemEntry {
  ref: string | null;
  payload: string;
}

// Best-effort removal of an abandoned (never committed/destroyed) operation's
// temporary directory if the operation is garbage-collected. The held value is
// just the path string, so it does not keep the operation alive.
const finalizer = new FinalizationRegistry((tmpDir: string) => {
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

/**
 * A single in-progress escrow, returned by {@link DataEscrow.createEscrow}.
 * Add data items and files (each encrypted immediately into the escrow's
 * temporary directory), then `commit()` to atomically place the escrow
 * directory into the vault, or `destroy()` to abandon and clean up. Any add
 * that throws auto-destroys the whole operation. Instances are not meant to be
 * constructed directly.
 */
export class DataEscrowOperation {
  readonly #ctx: EscrowContext;
  #state: State = 'pending';
  #busy = false;

  #dataEntries = new Map<string, ItemEntry>();
  #fileEntries = new Map<string, ItemEntry>();
  #filesDirCreated = false;
  #refsSeen = new Set<string>();
  #crefsSeen = new Set<string>();
  #autoKeyPairServed = false;

  /** @internal Use {@link DataEscrow.createEscrow}. */
  constructor(ctx: EscrowContext) {
    this.#ctx = ctx;
    finalizer.register(this, ctx.tmpDir, this);
  }

  /** The escrow id (UUID); known from creation, also the directory name. */
  get id(): string {
    return this.#ctx.escrowId;
  }

  /** Current lifecycle state: `pending`, `committed`, or `destroyed`. */
  get state(): State {
    return this.#state;
  }

  /** The escrow-level cleartext `reference` (or null). */
  get reference(): string | null {
    return this.#ctx.reference;
  }

  /** The `auto:`-prefixed auto key id, or null when autoKey is off. */
  get autoKid(): string | null {
    return this.#ctx.autoKid;
  }

  /**
   * The escrow's generated auto key pair, `{ secretKey, publicKey }`, for the
   * caller to store independently — the only recovery path when the operation
   * has no escrow key. Returns a fresh deep copy on every call; callable any
   * number of times while the operation is `pending` (secrets are wiped at
   * commit/destroy). Throws `TypeError` when autoKey is not enabled for this
   * operation or the operation is no longer pending. An accessor, not a
   * mutator: a throwing call does not destroy the operation.
   */
  autoKeyPair(): AutoKeyPairResult {
    if (this.#state !== 'pending') {
      throw new TypeError(`escrow operation is not pending (state: ${this.#state})`);
    }
    if (this.#ctx.autoKeyPair === undefined) {
      throw new TypeError('autoKeyPair(): auto key is not enabled for this escrow operation');
    }
    this.#autoKeyPairServed = true;
    return structuredClone(this.#ctx.autoKeyPair);
  }

  /**
   * Serializes operations and enforces the state machine. On any thrown error
   * from a mutator, the whole operation auto-destroys before re-throwing.
   */
  async #exec<T>(fn: () => Promise<T>): Promise<T> {
    if (this.#state !== 'pending') {
      throw new TypeError(`escrow operation is not pending (state: ${this.#state})`);
    }
    if (this.#busy) {
      throw new TypeError('escrow operation is busy with another call');
    }
    this.#busy = true;
    try {
      return await fn();
    } catch (err) {
      await this.#teardown();
      throw err;
    } finally {
      this.#busy = false;
    }
  }

  /**
   * Validates and registers an item's references. Each kind has its own scope,
   * shared across this escrow's data and file items; a duplicate throws
   * {@link ReferenceConflictError} (which auto-destroys the operation).
   */
  #claimRefs(options: AddDataOptions | undefined): { ref: string | null; cref: string | null } {
    if (options !== undefined && (options === null || typeof options !== 'object')) {
      throw new TypeError('options must be an object');
    }
    const ref = validateReference(options?.reference, 'reference');
    const cref = validateReference(options?.encryptedReference, 'encryptedReference');
    if (ref !== null && this.#refsSeen.has(ref)) {
      throw new ReferenceConflictError('reference', ref);
    }
    if (cref !== null && this.#crefsSeen.has(cref)) {
      throw new ReferenceConflictError('encryptedReference', cref);
    }
    if (ref !== null) this.#refsSeen.add(ref);
    if (cref !== null) this.#crefsSeen.add(cref);
    return { ref, cref };
  }

  /**
   * Encrypts one JSON-serializable value as a data item. Callable any number of
   * times. Returns the generated data-id.
   */
  addData(data: unknown, options?: AddDataOptions): Promise<string> {
    return this.#exec(async () => {
      const { ref, cref } = this.#claimRefs(options);
      serializeGuard(data);
      const id = randomUUID().toLowerCase();
      const payload = encrypt('A256GCMKW', this.#ctx.wrappingKey, {
        iat: this.#ctx.iat,
        id,
        ...(ref !== null ? { ref } : {}),
        ...(cref !== null ? { cref } : {}),
        data,
      });
      this.#dataEntries.set(id, { ref, payload });
      return id;
    });
  }

  /**
   * Encrypts the file at `path` into the escrow. The restore name defaults to
   * the basename of `path`. Returns the generated file-id.
   */
  addFile(path: string, options?: AddFileOptions): Promise<string> {
    return this.#exec(async () => {
      if (typeof path !== 'string' || path.length === 0) {
        throw new TypeError('addFile: path must be a non-empty string');
      }
      const { ref, cref } = this.#claimRefs(options);
      const name = options?.name !== undefined
        ? validateName(options.name)
        : validateName(basename(path));
      const compression = this.#fileCompression(options);
      await this.#ensureFilesDir();
      // No awaits between creating the read stream and attaching its error
      // handlers inside the encryption pipeline, so an early open error (e.g.
      // ENOENT) is always captured.
      return this.#encryptFile(createReadStream(path), name, ref, cref, compression);
    });
  }

  /**
   * Encrypts the contents of a readable stream into the escrow.
   * `options.name` is required. Returns the generated file-id.
   */
  addFileStream(readable: Readable, options: AddFileOptions): Promise<string> {
    return this.#exec(async () => {
      if (!(readable instanceof Readable)) {
        throw new TypeError('addFileStream: first argument must be a Readable stream');
      }
      const { ref, cref } = this.#claimRefs(options);
      const name = validateName(options?.name);
      const compression = this.#fileCompression(options);
      await this.#ensureFilesDir();
      return this.#encryptFile(readable, name, ref, cref, compression);
    });
  }

  /**
   * Encrypts an in-memory buffer into the escrow. `options.name` is required.
   * Returns the generated file-id.
   */
  addFileBuffer(buffer: Buffer, options: AddFileOptions): Promise<string> {
    return this.#exec(async () => {
      if (!Buffer.isBuffer(buffer)) {
        throw new TypeError('addFileBuffer: first argument must be a Buffer');
      }
      const { ref, cref } = this.#claimRefs(options);
      const name = validateName(options?.name);
      const compression = this.#fileCompression(options);
      await this.#ensureFilesDir();
      return this.#encryptFile(Readable.from(buffer), name, ref, cref, compression);
    });
  }

  /** Per-file compression: the add option, else the escrow-level default. */
  #fileCompression(options: AddFileOptions | undefined): CompressionName {
    return validateCompression(options?.compression) ?? this.#ctx.fileCompression;
  }

  async #ensureFilesDir(): Promise<void> {
    if (!this.#filesDirCreated) {
      await mkdir(join(this.#ctx.tmpDir, 'files'), { recursive: true });
      this.#filesDirCreated = true;
    }
  }

  async #encryptFile(
    src: Readable,
    name: string,
    ref: string | null,
    cref: string | null,
    compression: CompressionName,
  ): Promise<string> {
    const id = randomUUID().toLowerCase();
    const fileKey = cipherKeyGen('A256GCM');
    const payload = encrypt('A256GCMKW', this.#ctx.wrappingKey, {
      iat: this.#ctx.iat,
      id,
      ...(ref !== null ? { ref } : {}),
      ...(cref !== null ? { cref } : {}),
      name,
      key: fileKey,
    });
    await streamEncryptToFile(src, fileKey, join(this.#ctx.tmpDir, 'files', id), compression);
    this.#fileEntries.set(id, { ref, payload });
    return id;
  }

  /**
   * Finalizes the escrow: writes `escrow.json` (and, for an auto-key escrow
   * with an escrow key, `auto-key.json`) into the temporary directory,
   * fsyncs, and atomically renames the directory into its final place in the
   * vault. Throws `TypeError` if the escrow is empty (no data and no files),
   * or if the operation has no escrow key and `autoKeyPair()` was never
   * called — the latter **without** destroying the operation, so the caller
   * can collect the key pair and commit again. Returns the escrow-id. On
   * success all in-memory secrets are dropped.
   */
  commit(): Promise<string> {
    // Guard before any work and outside the auto-destroy convention: with no
    // escrow key there will be no auto-key.json, so an uncollected auto key
    // pair would make the escrow unrecoverable from birth. The operation
    // stays pending — recoverable by calling autoKeyPair() and committing
    // again.
    if (
      this.#state === 'pending' &&
      this.#ctx.autoKid !== null &&
      this.#ctx.autoKeyFile === undefined &&
      !this.#autoKeyPairServed
    ) {
      return Promise.reject(
        new TypeError(
          'cannot commit: this escrow has no escrow key and its auto key pair ' +
            'has not been collected with autoKeyPair() — committing would make ' +
            'the escrow unrecoverable',
        ),
      );
    }
    return this.#exec(async () => {
      if (this.#dataEntries.size === 0 && this.#fileEntries.size === 0) {
        throw new TypeError('cannot commit an empty escrow (no data and no files)');
      }

      if (this.#ctx.autoKeyFile !== undefined) {
        // The escrow-key-sealed auto secret key rides the same atomicity
        // boundary as the manifest.
        const autoKeyPath = join(this.#ctx.tmpDir, 'auto-key.json');
        const akfh = await open(autoKeyPath, 'wx');
        try {
          await akfh.writeFile(JSON.stringify(this.#ctx.autoKeyFile, null, 2) + '\n', 'utf8');
          await akfh.sync();
        } finally {
          await akfh.close();
        }
      }

      const manifest: Record<string, unknown> = {
        metadata: {
          id: this.#ctx.escrowId,
          kid: this.#ctx.escrowKid,
          iat: this.#ctx.iat,
          ...(this.#ctx.exp !== undefined ? { exp: this.#ctx.exp } : {}),
          ...(this.#ctx.reference !== null ? { ref: this.#ctx.reference } : {}),
          ...(this.#ctx.kvMarker !== undefined ? { kv: this.#ctx.kvMarker } : {}),
          payload: this.#ctx.metadataPayload,
        },
        ...(this.#dataEntries.size > 0 ? { data: entriesToManifest(this.#dataEntries) } : {}),
        ...(this.#fileEntries.size > 0 ? { file: entriesToManifest(this.#fileEntries) } : {}),
      };

      // Write + fsync the manifest and the escrow directory, then place the
      // whole directory with one atomic rename and make the rename durable.
      const manifestPath = join(this.#ctx.tmpDir, 'escrow.json');
      const fh = await open(manifestPath, 'wx');
      try {
        await fh.writeFile(JSON.stringify(manifest, null, 2) + '\n', 'utf8');
        await fh.sync();
      } finally {
        await fh.close();
      }
      await fsyncDir(this.#ctx.tmpDir);
      await mkdir(this.#ctx.finalParent, { recursive: true });
      await rename(this.#ctx.tmpDir, this.#ctx.finalDir);
      await fsyncDir(this.#ctx.finalParent);

      this.#state = 'committed';
      finalizer.unregister(this);
      this.#wipe();
      return this.#ctx.escrowId;
    });
  }

  /**
   * Abandons a pending operation: removes its temporary directory (recursive,
   * best effort) and drops secrets. A no-op once committed. Idempotent.
   */
  async destroy(): Promise<void> {
    if (this.#state !== 'pending') return; // committed => keep; destroyed => idempotent
    await this.#teardown();
  }

  /** Cleanup path shared by destroy() and #exec's error handler. */
  async #teardown(): Promise<void> {
    if (this.#state !== 'pending') return;
    this.#state = 'destroyed';
    finalizer.unregister(this);
    // Best-effort revoke of an abandoned kvKey escrow's vault key. Swallowed on
    // failure ("no sweat"): an expiring key self-cleans, a non-expiring one is
    // a permanent orphan.
    if (this.#ctx.kvVault && this.#ctx.kvKid) {
      await this.#ctx.kvVault.revokeKeyBestEffort(this.#ctx.kvKid);
    }
    await rm(this.#ctx.tmpDir, { recursive: true, force: true }).catch(() => {});
    this.#wipe();
  }

  #wipe(): void {
    this.#dataEntries.clear();
    this.#fileEntries.clear();
    this.#refsSeen.clear();
    this.#crefsSeen.clear();
    // Drop the wrapping-key material, the metadata token, and the auto key.
    (this.#ctx as { wrappingKey?: unknown }).wrappingKey = undefined;
    (this.#ctx as { metadataPayload?: unknown }).metadataPayload = undefined;
    this.#ctx.autoKeyPair = undefined;
    this.#ctx.autoKeyFile = undefined;
    // Drop the kv references (a committed kv key stays live in the vault; an
    // abandoned one was already revoked in #teardown before this runs).
    this.#ctx.kvVault = null;
    this.#ctx.kvKid = null;
  }
}

function entriesToManifest(entries: Map<string, ItemEntry>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [id, e] of entries) {
    out[id] = { ...(e.ref !== null ? { ref: e.ref } : {}), payload: e.payload };
  }
  return out;
}
