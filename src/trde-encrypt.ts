/**
 * TRDE encryption codec, independent of escrows and the vault: plaintext
 * `Readable` in, complete container (header, ciphertext, auth tag) out.
 * Writer-side placement policy (paths, `wx`, fsync) lives in `vault.ts`.
 */
import { createCipheriv, randomBytes } from 'node:crypto';
import { PassThrough, type Readable, type Transform } from 'node:stream';
import { createBrotliCompress, createDeflate, createGzip } from 'node:zlib';
import {
  buildTrdeHeader,
  contentKeyBytes,
  TRDE_IV_LEN,
  type CompressionName,
} from './trde';

/** The zlib compressor stream for a compression name, or null for none. */
function makeCompressor(name: CompressionName): Transform | null {
  switch (name) {
    case 'none':
      return null;
    case 'deflate':
      return createDeflate();
    case 'gzip':
      return createGzip();
    case 'brotli':
      return createBrotliCompress();
    case 'zstd':
      throw new TypeError('compression "zstd" is reserved and not yet supported');
  }
}

/**
 * Compresses `src` per `compression`, AES-256-GCM-encrypts it with the given
 * `A256GCM` content-key JWK, and returns a `Readable` emitting the complete
 * TRDE container. A failure in any stage destroys the returned stream with
 * that error; destroying the returned stream tears down the pipeline.
 */
export function encryptTrde(
  src: Readable,
  contentKeyJwk: Record<string, unknown>,
  compression: CompressionName,
): Readable {
  const key = contentKeyBytes(contentKeyJwk);
  const iv = randomBytes(TRDE_IV_LEN);
  const header = buildTrdeHeader(compression, iv);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(header);
  const compressor = makeCompressor(compression);

  const out = new PassThrough();
  const fail = (err: Error) => {
    src.destroy();
    compressor?.destroy();
    cipher.destroy();
    out.destroy(err);
  };
  src.on('error', fail);
  compressor?.on('error', fail);
  cipher.on('error', fail);
  // If the consumer abandons the container stream, stop the upstream work too.
  out.once('close', () => {
    src.destroy();
    compressor?.destroy();
    cipher.destroy();
  });

  out.write(header);
  // Pipe ciphertext but do not let the pipe end the output — the 16-byte GCM
  // auth tag goes after the last ciphertext chunk.
  cipher.pipe(out, { end: false });
  cipher.once('end', () => {
    let tag: Buffer;
    try {
      tag = cipher.getAuthTag();
    } catch (err) {
      fail(err as Error);
      return;
    }
    out.end(tag);
  });
  if (compressor) {
    src.pipe(compressor).pipe(cipher);
  } else {
    src.pipe(cipher);
  }
  return out;
}
