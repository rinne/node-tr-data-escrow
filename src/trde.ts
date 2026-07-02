/**
 * TRDE physical container: constants and header codec shared by the writer and
 * the decrypt subpath. This module knows nothing about escrows, manifests, or
 * JWE payloads — only the container byte format.
 *
 * Layout: magic "TRDE" | version 0x01 | enc 0x01 (AES-256-GCM) | comp |
 * ivlen 0x0C | iv(12) — the whole header is authenticated as AES-GCM AAD —
 * followed by the ciphertext and the 16-byte GCM auth tag.
 */

export const TRDE_MAGIC = Buffer.from('TRDE', 'ascii');
export const TRDE_VERSION = 1;
export const TRDE_ENC_AES256GCM = 1;
export const TRDE_IV_LEN = 12;
export const TRDE_TAG_LEN = 16;
/** Bytes before the IV: magic(4) version(1) enc(1) comp(1) ivlen(1). */
export const TRDE_FIXED_LEN = 8;

/**
 * Streamable compression applied to file content before encryption. Recorded
 * only in the container header (one byte after the enc byte), never in the
 * escrow manifest or payloads.
 */
export type CompressionName = 'none' | 'deflate' | 'gzip' | 'brotli' | 'zstd';

export const COMPRESSION_CODES: Record<CompressionName, number> = {
  none: 0,
  deflate: 1,
  gzip: 2,
  brotli: 3,
  zstd: 4, // reserved, not yet enabled
};

/**
 * Validates an optional compression option value. Returns the name, or null
 * when absent (caller falls back to the next default in the chain). `"zstd"`
 * is a reserved container code and is rejected until enabled.
 */
export function validateCompression(value: unknown): CompressionName | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || !(value in COMPRESSION_CODES)) {
    throw new TypeError(
      'compression must be one of "none", "deflate", "gzip", "brotli" (or the reserved "zstd")',
    );
  }
  if (value === 'zstd') {
    throw new TypeError('compression "zstd" is reserved and not yet supported');
  }
  return value as CompressionName;
}

/** Builds the authenticated container header (used verbatim as AES-GCM AAD). */
export function buildTrdeHeader(compression: CompressionName, iv: Buffer): Buffer {
  return Buffer.concat([
    TRDE_MAGIC,
    Buffer.from([TRDE_VERSION, TRDE_ENC_AES256GCM, COMPRESSION_CODES[compression], iv.length]),
    iv,
  ]);
}

/** The fixed (pre-IV) header fields. */
export interface TrdeFixedHeader {
  /** Compression code (validity is checked where a decompressor is needed). */
  comp: number;
  /** Recorded IV length; the full header is `TRDE_FIXED_LEN + ivLen` bytes. */
  ivLen: number;
}

/**
 * Parses and validates the fixed part of a container header (`buf` must hold
 * at least {@link TRDE_FIXED_LEN} bytes). Throws on bad magic, version, or
 * encryption code; the compression code is returned unchecked.
 */
export function parseTrdeFixedHeader(buf: Buffer): TrdeFixedHeader {
  if (!buf.subarray(0, 4).equals(TRDE_MAGIC)) {
    throw new Error('TRDE container: bad magic');
  }
  const version = buf.readUInt8(4);
  if (version !== TRDE_VERSION) {
    throw new Error(`TRDE container: unsupported version ${version}`);
  }
  const enc = buf.readUInt8(5);
  if (enc !== TRDE_ENC_AES256GCM) {
    throw new Error(`TRDE container: unsupported encryption code ${enc}`);
  }
  const comp = buf.readUInt8(6);
  const ivLen = buf.readUInt8(7);
  if (ivLen === 0) {
    throw new Error('TRDE container: zero IV length');
  }
  return { comp, ivLen };
}

/**
 * Extracts the raw AES-256 key bytes from a bare `A256GCM` content-key `oct`
 * JWK. Throws `TypeError` unless `k` decodes to exactly 32 bytes.
 */
export function contentKeyBytes(jwk: unknown): Buffer {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
    throw new TypeError('content key must be a JWK object');
  }
  const k = (jwk as Record<string, unknown>).k;
  if (typeof k !== 'string' || k.length === 0) {
    throw new TypeError('content key JWK must have a base64url "k" member');
  }
  const bytes = Buffer.from(k, 'base64url');
  if (bytes.length !== 32) {
    throw new TypeError(`content key must be 32 bytes (got ${bytes.length})`);
  }
  return bytes;
}
