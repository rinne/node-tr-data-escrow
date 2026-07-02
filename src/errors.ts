/**
 * Thrown when an added item's `reference` or `encryptedReference` collides with
 * one already used within the same escrow (each kind has its own scope; both
 * are checked in memory, per escrow only). The failing add auto-destroys the
 * whole escrow operation before this is thrown.
 */
export class ReferenceConflictError extends Error {
  /** Which reference kind collided. */
  readonly kind: 'reference' | 'encryptedReference';
  /** The conflicting reference value. */
  readonly reference: string;
  constructor(kind: 'reference' | 'encryptedReference', reference: string) {
    super(`duplicate ${kind} within escrow: ${JSON.stringify(reference)}`);
    this.name = 'ReferenceConflictError';
    this.kind = kind;
    this.reference = reference;
  }
}
