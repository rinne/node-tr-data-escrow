/**
 * TRDE decryption codec, independent of escrows and the decrypt classes: a
 * container source plus a bare `A256GCM` content-key JWK in, plaintext out as
 * a stream, a buffer, or an atomically written file. Loaded only via the
 * `tr-data-escrow/decrypt` subpath — nothing in the writer imports this.
 */
import { createDecipheriv, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { pipeline as pipelineCb, Readable, type Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import {
  contentKeyBytes,
  parseTrdeFixedHeader,
  TRDE_FIXED_LEN,
  TRDE_TAG_LEN,
} from './trde';

/** Where an encrypted TRDE container comes from. */
export type TrdeSource = string | Buffer | Readable;

/** The zlib decompressor stream for a container compression code, or null. */
function makeDecompressor(comp: number): Transform | null {
  switch (comp) {
    case 0:
      return null;
    case 1:
      return createInflate();
    case 2:
      return createGunzip();
    case 3:
      return createBrotliDecompress();
    case 4:
      throw new Error('TRDE container: compression "zstd" is reserved and not yet supported');
    default:
      throw new Error(`TRDE container: unknown compression code ${comp}`);
  }
}

function normalizeSource(source: TrdeSource): Readable {
  if (typeof source === 'string') {
    if (source.length === 0) {
      throw new TypeError('source path must be a non-empty string');
    }
    return createReadStream(source);
  }
  if (Buffer.isBuffer(source)) {
    return Readable.from([source]);
  }
  if (source instanceof Readable) {
    return source;
  }
  throw new TypeError('source must be a path string, a Buffer, or a Readable');
}

/**
 * Decrypts one TRDE container to a plaintext `Readable`. The header is read
 * and validated before the promise resolves (bad magic / version / enc /
 * compression code reject here). Caveat inherent to streamed AEAD: plaintext
 * flows before the GCM tag is verified — a tag or decompression failure
 * surfaces as an `'error'` event on the returned stream and the caller must
 * discard the output.
 */
export async function decryptTrdeToStream(
  source: TrdeSource,
  contentKeyJwk: Record<string, unknown>,
): Promise<Readable> {
  const key = contentKeyBytes(contentKeyJwk);
  const src = normalizeSource(source);
  try {
    const it = src[Symbol.asyncIterator]() as AsyncIterator<Buffer>;
    let buf: Buffer = Buffer.alloc(0);
    const need = async (n: number) => {
      while (buf.length < n) {
        const r = await it.next();
        if (r.done) {
          throw new Error('TRDE container: truncated (incomplete header)');
        }
        const chunk = Buffer.isBuffer(r.value) ? r.value : Buffer.from(r.value);
        buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
      }
    };
    await need(TRDE_FIXED_LEN);
    const { comp, ivLen } = parseTrdeFixedHeader(buf);
    const decompressor = makeDecompressor(comp);
    const headerLen = TRDE_FIXED_LEN + ivLen;
    await need(headerLen);
    const header = buf.subarray(0, headerLen);
    const iv = buf.subarray(TRDE_FIXED_LEN, headerLen);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(header);
    const initial = buf.subarray(headerLen);

    // Feeds the remaining container bytes to the decipher, holding back the
    // trailing 16 bytes. When the input ends, the holdback is the GCM auth tag
    // and is handed to the decipher just before the pipeline ends it, so
    // `final()` verifies it.
    async function* ciphertext(): AsyncGenerator<Buffer> {
      let pending: Buffer = initial;
      for (;;) {
        const r = await it.next();
        if (r.done) break;
        const chunk = Buffer.isBuffer(r.value) ? r.value : Buffer.from(r.value);
        pending = pending.length === 0 ? chunk : Buffer.concat([pending, chunk]);
        if (pending.length > TRDE_TAG_LEN) {
          yield pending.subarray(0, pending.length - TRDE_TAG_LEN);
          pending = pending.subarray(pending.length - TRDE_TAG_LEN);
        }
      }
      if (pending.length < TRDE_TAG_LEN) {
        throw new Error('TRDE container: truncated (missing auth tag)');
      }
      if (pending.length > TRDE_TAG_LEN) {
        yield pending.subarray(0, pending.length - TRDE_TAG_LEN);
        pending = pending.subarray(pending.length - TRDE_TAG_LEN);
      }
      decipher.setAuthTag(pending);
    }

    // The pipeline propagates any stage's failure to the last stream, so the
    // returned Readable emits 'error' on tag or decompression failure.
    const out = decompressor ?? decipher;
    if (decompressor) {
      pipelineCb(Readable.from(ciphertext()), decipher, decompressor, () => {});
    } else {
      pipelineCb(Readable.from(ciphertext()), decipher, () => {});
    }
    return out as unknown as Readable;
  } catch (err) {
    src.destroy();
    throw err;
  }
}

/**
 * Decrypts one TRDE container fully into memory. The plaintext is verified
 * (GCM tag and decompression) **before** it is returned; only for containers
 * whose plaintext fits in memory.
 */
export async function decryptTrdeToBuffer(
  source: TrdeSource,
  contentKeyJwk: Record<string, unknown>,
): Promise<Buffer> {
  const stream = await decryptTrdeToStream(source, contentKeyJwk);
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

/**
 * Decrypts one TRDE container **atomically** to the path `destination`: the
 * plaintext streams into a temporary file next to the destination, is
 * fsynced, and is renamed into place only after full verification. On any
 * failure the temporary file is removed and nothing appears at the path.
 * Resolves to `true`.
 */
export async function decryptTrdeToFile(
  source: TrdeSource,
  contentKeyJwk: Record<string, unknown>,
  destination: string,
): Promise<true> {
  if (typeof destination !== 'string' || destination.length === 0) {
    throw new TypeError('destination must be a non-empty path string');
  }
  const stream = await decryptTrdeToStream(source, contentKeyJwk);
  const tmpPath = `${destination}.${randomUUID()}.tmp`;
  try {
    await pipeline(stream, createWriteStream(tmpPath, { flags: 'wx' }));
    const fh = await open(tmpPath, 'r+');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
    await rename(tmpPath, destination);
    await fsyncDirBestEffort(dirname(destination));
  } catch (err) {
    stream.destroy();
    await unlink(tmpPath).catch(() => {});
    throw err;
  }
  return true;
}

/** Best-effort directory fsync so the rename into it is durable. */
async function fsyncDirBestEffort(path: string): Promise<void> {
  try {
    const fh = await open(path, 'r');
    try {
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch {
    /* best effort */
  }
}
