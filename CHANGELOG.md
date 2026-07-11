# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.2] - 2026-07-11

### Fixed

- `decryptAutoKey` failed with `EscrowIntegrityError` for ML-KEM auto keys:
  the reader-side public-JWK derivation lacked an AKP branch, so escrows
  whose auto key was ML-KEM could be written but their auto key could not be
  recovered from `auto-key.json`. Found in a post-release adversarial
  security review of the ML-KEM paths (which found no vulnerabilities — the
  failure was fail-closed, availability-only). Regression test added.

### Changed

- Documentation: post-quantum standards status. draft-ietf-jose-pqc-kem-06
  removed the JOSE mechanism (the document is COSE-only from -06 on, and
  JWE post-quantum registrations are expected via the HPKE track), so the
  `ML-KEM-*@spinium.com` identifiers are the stable long-term form.

## [4.0.0] - 2026-07-11

Post-quantum ML-KEM escrow keys in all three key modes, on the modernised
JOSE stack. **Existing escrows written by 2.x/3.x decrypt unchanged.**

### Added

- **ML-KEM (FIPS 203) support** in every key mode, using tr-jwe's
  collision-resistant JWE algorithm identifiers
  `ML-KEM-{512,768,1024}@spinium.com` (frozen at draft-ietf-jose-pqc-kem-05
  semantics; content encryption always `A256GCM`):
  - escrow keys: AKP public JWKs
    (`{ kty:'AKP', alg:'ML-KEM-*', kid, pub }`) accepted by `escrowKey`,
    sealed under the corresponding suffixed algorithm;
  - auto keys: `autoKeyAlgorithm: 'ML-KEM-*@spinium.com'` (no
    curve/length parameters);
  - key-vault keys: `kvKeyAlgorithm: 'ML-KEM-*@spinium.com'` (requires a
    tr-key-vault server >= 1.0.0);
  - readers: `escrowSecretKey` accepts AKP private JWKs
    (`priv`/`pub`, unsuffixed variant in `alg`);
  - CLI: the new algorithm values on `--auto-key-algorithm` and
    `--kv-key-algorithm`.
- In-package `mlKemKeyPairGen` in the key generator.

### Changed

- **Breaking:** dependency majors — `tr-jwe ^2.1.0` (brings `tr-kmac` as a
  transitive dependency) and `tr-key-vault-client ^1.0.0` (functionally
  identical to 0.2.0; re-versioned to mark production). The
  `AutoKeyAlgorithm`/`KvKeyAlgorithm` type unions widened with the ML-KEM
  identifiers (a compile-time break for exhaustive `switch`es over them).
- RSA key-vault key generation no longer sends `keyLength` for non-RSA
  algorithms (parameter hygiene; behaviour unchanged for existing
  algorithms).

## [3.0.0] - 2026-07-04

Optional integration with a [tr-key-vault](https://github.com/rinne/tr-key-vault)
key-vault server, plus an auto-key algorithm cleanup. Key-vault use is fully
optional and invisible when unused. **Existing escrows written by 2.x decrypt
unchanged**; the breaking changes are confined to the writer/CLI option surface
for creating new escrows.

### Added

- **`kvKey`** layer (mutually exclusive with `autoKey`): the per-escrow key is
  generated in a key-vault server, the metadata is encrypted to its public
  half, the private half never leaves the vault, and the escrow's expiry is
  **enforced** by the vault (the key is deleted at expiry — hands-off
  expiration). New options `kvKey`, `kvKeyAlgorithm`, `kvKeyCrv`, `kvKeyLength`,
  and `kv` (a connection config or a `KeyVaultClient` instance), on the
  constructor and per operation.
  - `DataEscrow` marks such escrows with `metadata.kv = { url }` and best-effort
    revokes the vault key if an operation is abandoned or fails before commit.
  - `DataEscrowDecrypt` accepts an optional `kv` connection (constructor and per
    `decrypt()` call) and recovers kv-backed escrows through the vault; the
    escrow secret key becomes optional (a key-vault-only reader).
  - `escrow` / `decrypt-escrow` CLIs gain `--kv-key` and `--kv-url` /
    `--kv-user` / `--kv-token` / `--kv-token-file` (with `OPT_KV_*` fallbacks).
  - `tr-key-vault-client` is a new dependency, loaded lazily — code that never
    uses `kvKey` never pulls it in.
- Escrow keys and auto keys may now use `RSA-OAEP-256`.
- Auto keys gain a separate `autoKeyCrv` (EC curve).

### Changed (breaking)

- **`autoKeyAlgorithm`** values are now `ECDH-ES` (default) | `RSA-OAEP` |
  `RSA-OAEP-256`. The curve is no longer an algorithm value: use `autoKeyCrv`
  (`P-256`/`P-384`/`P-521`, default `P-521`) for `ECDH-ES`. The default auto key
  is unchanged in substance (EC P-521 / ECDH-ES).
- **`rsaModulusLength`** is renamed **`autoKeyLength`** (algorithm-specific
  length).
- CLI: `--auto-key-algorithm` takes the new value set; `--auto-key-crv` and
  `--auto-key-length` are added. `requiresAlso` is dropped — auto-/kv- sub-
  options given without their mode flag are now ignored (enabling env-based
  defaults) rather than an error.

## [2.1.2] - 2026-07-03

No functional changes.

### Added

- `JWE-KEY-EMBEDDING.md`: the optional `public_key` property of
  `embedded_key_info` — a deliberate, cleartext disclosure of the public
  half of the embedded private key, with kid-matching rules.

### Changed

- The key-embedding specification was renamed from `JWT-KEY-EMBEDDING.md`
  (as introduced in 2.1.1) to `JWE-KEY-EMBEDDING.md`: the encapsulating
  format is JWE, not JWT. (The document's references to JWT conventions —
  NumericDate timestamps and claim names — are intentional and unchanged.)

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
