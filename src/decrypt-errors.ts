/** Error classes exported from the `tr-data-escrow/decrypt` subpath. */

/**
 * No configured escrow secret key matches the token's kid (the manifest's
 * `metadata.kid`, or an auto-key payload's protected-header kid — the latter
 * may also be missing entirely, leaving `kid` undefined).
 */
export class UnknownEscrowKeyError extends Error {
  /** The kid the token was encrypted to, when it carries one. */
  readonly kid: string | undefined;
  constructor(kid: string | undefined) {
    super(
      kid === undefined
        ? 'the encrypted payload carries no kid in its protected header'
        : `no escrow secret key configured for kid ${JSON.stringify(kid)}`,
    );
    this.name = 'UnknownEscrowKeyError';
    this.kid = kid;
  }
}

/** A file method's `fileId` is not a file of the decrypted escrow. */
export class UnknownFileIdError extends Error {
  /** The offending file id argument, as given. */
  readonly fileId: unknown;
  constructor(fileId: unknown) {
    super(
      `no such file in this escrow: ${
        typeof fileId === 'string' ? JSON.stringify(fileId) : String(fileId)
      }`,
    );
    this.name = 'UnknownFileIdError';
    this.fileId = fileId;
  }
}

/**
 * The sealed claims of a payload do not match their cleartext counterparts in
 * the manifest (including a field present on one side and absent on the
 * other) — the manifest has been tampered with or corrupted.
 */
export class EscrowIntegrityError extends Error {
  /** Dotted path of the offending field (e.g. `metadata.iat`, `file.<id>.ref`). */
  readonly field: string;
  constructor(field: string, detail?: string) {
    super(`escrow integrity violation at ${field}${detail ? `: ${detail}` : ''}`);
    this.name = 'EscrowIntegrityError';
    this.field = field;
  }
}
