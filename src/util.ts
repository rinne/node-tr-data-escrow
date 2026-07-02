/**
 * Shared validation and expiry helpers. All escrow timestamps follow the JWT
 * convention: integer unix seconds.
 */
import type { CompressionName } from './trde';

/**
 * Throws `TypeError` unless `value` is JSON-serializable and not `undefined`.
 * `JSON.stringify` either throws (circular, `BigInt`) or yields `undefined`
 * (top-level `undefined`, function, or symbol).
 */
export function serializeGuard(value: unknown): void {
  let json: string | undefined;
  try {
    json = JSON.stringify(value);
  } catch (err) {
    throw new TypeError('data is not JSON-serializable', { cause: err });
  }
  if (json === undefined) {
    throw new TypeError(
      'data is not JSON-serializable (undefined, a function, or a symbol)',
    );
  }
}

const REFERENCE_MAX_LENGTH = 1024;

/**
 * Validates an optional reference string (`reference` or `encryptedReference`;
 * `label` names it in error messages). Returns the string, or null when absent.
 */
export function validateReference(value: unknown, label: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string') {
    throw new TypeError(`${label} must be a string or null`);
  }
  if (value.length === 0) {
    throw new TypeError(`${label} must not be an empty string (use null to omit)`);
  }
  if (value.length > REFERENCE_MAX_LENGTH) {
    throw new TypeError(
      `${label} must be at most ${REFERENCE_MAX_LENGTH} characters (got ${value.length})`,
    );
  }
  return value;
}

const NAME_MAX_LENGTH = 255;

/**
 * Validates a stored file name (a basename, not a path). It is metadata only —
 * this module never uses it as a filesystem path — but it is kept sane for the
 * future reader: a non-empty string without path separators or NUL.
 */
export function validateName(name: unknown): string {
  if (typeof name !== 'string' || name.length === 0) {
    throw new TypeError('file name must be a non-empty string');
  }
  if (name.length > NAME_MAX_LENGTH) {
    throw new TypeError(`file name must be at most ${NAME_MAX_LENGTH} characters (got ${name.length})`);
  }
  const byteLength = Buffer.byteLength(name, 'utf8');
  if (byteLength > NAME_MAX_LENGTH) {
    throw new TypeError(
      `file name must be at most ${NAME_MAX_LENGTH} bytes of UTF-8 (got ${byteLength})`,
    );
  }
  if (name.includes('/') || name.includes('\\') || name.includes('\0')) {
    throw new TypeError('file name must not contain path separators or NUL');
  }
  if (name === '.' || name === '..') {
    throw new TypeError('file name must not be "." or ".."');
  }
  return name;
}

/** Coerces a `Date` or ISO-8601 string to integer unix seconds; throws otherwise. */
export function coerceExpiresAt(value: unknown): number {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) throw new TypeError('expiresAt is an invalid Date');
    return Math.floor(value.getTime() / 1000);
  }
  if (typeof value === 'string') {
    const t = new Date(value).getTime();
    if (Number.isNaN(t)) {
      throw new TypeError(`expiresAt is not a valid timestamp string: ${JSON.stringify(value)}`);
    }
    return Math.floor(t / 1000);
  }
  throw new TypeError('expiresAt must be a Date or an ISO-8601 timestamp string');
}

/** Validates a relative expiry in seconds: a finite number >= 0 (floored). */
export function validateExpiresAfter(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TypeError('expiresAfter must be a finite number of seconds >= 0');
  }
  return Math.floor(value);
}

/**
 * Validates the constructor-level default `expiresAfter` (seconds, null, or
 * undefined). Returns a number of seconds or null.
 */
export function validateDefaultExpiresAfter(value: unknown): number | null {
  if (value === undefined || value === null) return null;
  return validateExpiresAfter(value);
}

export interface EscrowOptionsInput {
  reference?: string | null;
  encryptedReference?: string | null;
  expiresAt?: Date | string | null;
  expiresAfter?: number | null;
  /**
   * Default file compression for this escrow, overriding the constructor
   * default; may still be overridden per file in the `addFile*` options.
   * Recorded only in the encrypted-file container header.
   */
  compression?: CompressionName | null;
}

/**
 * Resolves an escrow's advisory `exp` (integer unix seconds) from per-escrow
 * options plus the constructor default, relative to the escrow's `iat`.
 * Supplying both `expiresAt` and `expiresAfter` is an error. An explicit `null`
 * on either option means "no expiry", overriding the constructor default.
 * Returns `undefined` when the escrow has no expiry.
 */
export function resolveExp(
  options: EscrowOptionsInput,
  defaultExpiresAfter: number | null,
  iat: number,
): number | undefined {
  const hasAt = options.expiresAt !== undefined;
  const hasAfter = options.expiresAfter !== undefined;
  if (hasAt && hasAfter) {
    throw new TypeError('provide at most one of expiresAt / expiresAfter');
  }
  if (hasAt) {
    return options.expiresAt === null ? undefined : coerceExpiresAt(options.expiresAt);
  }
  if (hasAfter) {
    return options.expiresAfter === null
      ? undefined
      : iat + validateExpiresAfter(options.expiresAfter);
  }
  if (defaultExpiresAfter != null) {
    return iat + defaultExpiresAfter;
  }
  return undefined;
}
