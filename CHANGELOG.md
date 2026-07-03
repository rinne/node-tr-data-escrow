# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.2] - 2026-07-03

No functional changes.

### Added

- `JWT-KEY-EMBEDDING.md`: the optional `public_key` property of
  `embedded_key_info` — a deliberate, cleartext disclosure of the public
  half of the embedded private key, with kid-matching rules.

## [2.1.1] - 2026-07-03

No functional changes.

### Added

- `JWT-KEY-EMBEDDING.md`: a formal specification of the convention for
  embedding a JWK inside a JWE — a mandatory `key` claim in the encrypted
  payload plus an optional `embedded_key_info` protected-header object.
  The escrow's `auto-key.json` payload follows this convention. The
  document is included in the published package.

## [2.1.0] - 2026-07-03

### Added

- `escrow` CLI: `--auto-key-algorithm=<P-256|P-384|P-521|RSA-OAEP>` (requires
  `--auto-key`; default remains P-521). An RSA-OAEP auto key always uses a
  4096-bit modulus — the modulus is not configurable in the CLI.

## [2.0.0] - 2026-07-03

### Added

- **Auto key** — an optional second key layer, default off (no changes when
  unused). New options `autoKey` (default `false`), `autoKeyAlgorithm`
  (`P-256`/`P-384`/`P-521` default/`RSA-OAEP`), and `rsaModulusLength`
  (2048–16384, default 4096) on the constructor, all overridable per
  operation in `createEscrow`; `escrowKey` is likewise overridable per
  operation, including to `null` ("no escrow key", requiring autoKey), and is
  optional on the constructor when `autoKey` is `true`. With autoKey on, a
  fresh key pair (kid `auto:<uuid>`; the prefix is reserved and rejected for
  escrow keys) is generated per escrow and the manifest metadata is encrypted
  to it; the private half is returned by the new
  `DataEscrowOperation.autoKeyPair()` (with an `autoKid` getter) and — when
  the operation also has an escrow key — sealed to the escrow key into a new
  `auto-key.json` (`{ kid, iat, exp?, payload }`) beside `escrow.json`.
  `commit()` on a no-escrow-key operation refuses (without destroying the
  operation) until `autoKeyPair()` has been called. Decrypt side:
  `DataEscrowDecrypt.decryptAutoKey()` recovers the pair from `auto-key.json`
  with binding verification, and an auto escrow's `escrow.json` opens
  directly with the auto secret JWK as `escrowSecretKey`. CLI: `escrow` gains
  `--auto-key` (making `--escrow-key-file` optional) and
  `--auto-key-output-file` (writes the auto key private JWK, mode 0600;
  required when no escrow key is given); `decrypt-escrow` usage is unchanged
  — the auto key secret passes as an ordinary secret key file, and when the
  escrow carries an `auto-key.json` the escrow secret key works as always
  via automatic auto-key recovery.
- In-package key generation module (`src/key-gen.ts`) on `node:crypto`: key
  pairs asynchronously off the event loop, symmetric keys with a
  tr-jwk-output-compatible `cipherKeyGen` (embedded-JWK payload shape
  unchanged; the on-disk escrow format is untouched and remains fully
  compatible with 1.0.0).

### Changed

- `DataEscrow`'s `escrowKid` getter is now `string | null` (`null` for an
  autoKey-only instance constructed without an escrow key).
- `UnknownEscrowKeyError.kid` is now `string | undefined` (`undefined` when
  an auto-key payload carries no kid in its protected header).
- Dependencies: `tr-jwk` dropped from runtime dependencies (now dev-only;
  the wrapping/content key generation moved in-package with identical
  output); `tr-jwe` bumped to `^1.1.0` (feature-identical) and is the sole
  runtime dependency.

## [1.0.0] - 2026-07-02

Initial implementation.

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
