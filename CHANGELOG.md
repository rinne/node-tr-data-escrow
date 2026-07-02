# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.0] - Unreleased

Initial implementation, ready for testing.

### Added

- `DataEscrow` class: write-only cryptographic escrow of JSON data and files
  into a filesystem vault, encrypted to a public escrow key (RSA-OAEP ≥ 2048 or
  EC P-256/384/521 via ECDH-ES). The writer holds no decryption power;
  destroying the private key revokes access permanently.
- One escrow = one self-contained directory `<vault>/<prefix>/<escrow-id>/`
  containing an `escrow.json` manifest and (when files are included) encrypted
  `files/<file-id>` blobs (streamed AES-256-GCM, self-describing container).
  Escrows are staged under `<vault>/.tmp/` and placed with one atomic
  directory rename at commit.
- Optional file compression before encryption (`none`/`deflate`/`gzip`/
  `brotli` via zlib streams; `zstd` reserved), recorded only as one byte in
  the encrypted-file container header. Default from the constructor
  `compression` option, overridable per escrow (`createEscrow`) and per file
  (`addFile*`).
- Manifest/JWE design: a per-escrow `A256GCMKW` wrapping key sealed (with all
  metadata, for tamper-binding) to the escrow key; per-item payloads sealed
  with the wrapping key; per-file `A256GCM` content keys sealed inside the
  file payloads. Timestamps in unix seconds; advisory `exp` (stored, never
  enforced).
- One-shot `escrow(data, options?)` and `createEscrow(options?)` returning a
  `DataEscrowOperation` builder with `addData`, `addFile`, `addFileStream`,
  `addFileBuffer`, `commit`, and `destroy`; ids (escrow, data, file) are
  random UUIDs.
- References: optional cleartext `reference` and sealed `encryptedReference`
  at the escrow level and per item; per-escrow in-memory uniqueness for item
  references (`ReferenceConflictError`).
- Expiry options: per-escrow `expiresAt` (Date/ISO) or `expiresAfter`
  (seconds), plus a constructor-level `expiresAfter` default with explicit
  null override.
- Failure handling: any failing add auto-destroys the operation and removes
  the staging directory; a `FinalizationRegistry` backstop cleans up abandoned
  operations.
- `escrow` command-line tool (option parsing with `optist`): one escrow
  per invocation from repeatable `--data` (JSON) and `--file` options, with
  escrow-level references, expiry (`--expires-at` / `--expires-after` with
  `s`/`m`/`h`/`d`/`w`/`y` duration suffixes), and a global `--compression`
  flag; a `--file` argument may also be a JSON object
  (`{"filename", "name"?, "reference"?, "encryptedReference"?,
  "compression"?}`) for per-file overrides; mandatory `--escrow-key-file`
  and `--vault-directory` may come from the `OPT_ESCROW_KEY_FILE` /
  `OPT_VAULT_DIRECTORY` environment variables.
- Test suite (vitest, filesystem-only) including full round-trip decryption
  and CLI integration tests, and documentation.
- Decryption behind the separate `tr-data-escrow/decrypt` subpath (the main
  entry loads zero decryption code): `DataEscrowDecrypt` (constructed with one
  or more escrow secret JWKs indexed by `kid`) whose `decrypt(escrowObject)`
  opens a parsed `escrow.json`, verifies the sealed/cleartext tamper binding
  of every duplicated field, and returns a `DataEscrowDecryptOperation` with
  `originalData()`, `data()` (payloads augmented with `payloadData` and
  `payloadContentKey`), atomic `decryptFile`, `decryptFileToStream`,
  `decryptFileToBuffer`, and `destroy()`; errors `UnknownEscrowKeyError`,
  `UnknownFileIdError`, and `EscrowIntegrityError`.
- Class-independent TRDE container codec (`encryptTrde` /
  `decryptTrdeToStream` / `decryptTrdeToBuffer` / `decryptTrdeToFile`,
  internal for now); the writer's file encryption was refactored onto it with
  unchanged behavior and on-disk format.
- `decrypt-escrow` command-line tool: restores one escrow directory
  (`escrow-decrypted.json` + `files-decrypted/<name>`) with an all-or-nothing
  staging strategy; source defaults to `.`, destination to the source
  directory (in-place decryption is safe); the secret key file may come from
  `OPT_ESCROW_SECRET_KEY_FILE`.
- File `name` validation additionally enforces a 255-byte UTF-8 maximum (the
  255-character limit alone did not guarantee a legal unix path component).
