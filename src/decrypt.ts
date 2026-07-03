/**
 * The `tr-data-escrow/decrypt` subpath: the escrow reader. Kept out of the
 * main entry so that `require('tr-data-escrow')` loads zero decryption code.
 */
export {
  DataEscrowDecrypt,
  type DataEscrowDecryptOptions,
  type AutoKeyPairResult,
} from './data-escrow-decrypt';
export type {
  DataEscrowDecryptOperation,
  DecryptedManifest,
  DecryptedItem,
  DecryptedPayload,
} from './data-escrow-decrypt-operation';
export type { TrdeSource } from './trde-decrypt';
export {
  EscrowIntegrityError,
  UnknownEscrowKeyError,
  UnknownFileIdError,
} from './decrypt-errors';
