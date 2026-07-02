/** Error classes exported from the `tr-data-escrow/decrypt` subpath. */

/** No configured escrow secret key matches the manifest's `metadata.kid`. */
export class UnknownEscrowKeyError extends Error {
  /** The kid the escrow was encrypted to. */
  readonly kid: string;
  constructor(kid: string) {
    super(`no escrow secret key configured for kid ${JSON.stringify(kid)}`);
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
