# tr-data-escrow

**Write-only cryptographic escrow** of JSON data and files into a filesystem
vault. Each escrow is one self-contained, atomically placed directory.

You hand it plaintext and a **public** escrow key; it encrypts everything and
persists only ciphertext. The system that performs escrow **cannot read back**
what it stored — recovery requires the escrow *private* key, which this library
never holds. Destroying that private key permanently and irrevocably revokes
access to every escrow written under it.

This is the shape you want for *"we must delete this data from the live system,
but a break-glass copy has to survive under separate key custody"* — regulated
retention, right-to-erasure with a sealed archive, incident forensics, and
similar.

- **Encrypt to a public key.** All metadata, data items, and per-file keys are
  sealed as JWE to an RSA-OAEP or EC (ECDH-ES) escrow key. No decryption
  capability lives in the writer.
- **One directory per escrow.** An escrow is a directory holding an
  `escrow.json` manifest and (when files are included) a `files/` directory of
  encrypted blobs. It is fully self-contained and relocatable — archive it,
  ship it, or leave it in the vault.
- **Atomic placement.** Everything is staged under `<vault>/.tmp/` and moved
  into place with a single directory rename at commit. Failures clean up after
  themselves.
- **Streams, not memory.** File bytes are encrypted with a fresh per-file
  AES-256-GCM key and streamed to disk; they never sit in memory.
- **Per-escrow keys, optionally.** Generate a fresh key per escrow locally
  ([auto key](#auto-key)) or in a [key vault](#key-vault) — the latter enforces
  a hard, hands-off expiry (the key is deleted at expiry). Both are off by
  default; when unused, nothing changes.
- **No database, no services** for the core. Runtime dependency:
  [`tr-jwe`](https://www.npmjs.com/package/tr-jwe); the optional key-vault layer
  adds [`tr-key-vault-client`](https://www.npmjs.com/package/tr-key-vault-client),
  loaded lazily only when used.

> **Scope.** The main entry point is deliberately **write-only**: it has no
> read, restore, delete, or expiry-enforcement API, and it loads zero
> decryption code. Reading an escrow back (with the private key) lives behind
> the separate [`tr-data-escrow/decrypt`](#decryption-tr-data-escrowdecrypt)
> subpath, meant to be used only where the escrow secret key legitimately
> exists. The on-disk format documented below is that reader's contract.

## Install

```sh
npm install tr-data-escrow
```

Requires **Node `>= 24`** (the underlying `tr-jwe` / `tr-jwk` libraries
require it).

## Quick start

```ts
import { DataEscrow } from 'tr-data-escrow';

// escrowKey is the PUBLIC half of your escrow key (kept in the running system).
// The PRIVATE half lives elsewhere, under separate custody.
const escrowKey = {
  kty: 'EC', crv: 'P-521', kid: 'escrow-key-2026',
  x: '…', y: '…',
};

const esc = new DataEscrow({
  vaultDir: '/spool/vault',
  escrowKey,
});

// One-shot: a single JSON value.
const escrowId = await esc.escrow(
  { foo: 1, secret: 'this is very secret', x: [1, 2, 3] },
  { reference: 'data-1231532' },
);
```

Data **and** files, via the builder:

```ts
const op = await esc.createEscrow({
  reference: 'case-7',                       // cleartext, in the manifest
  encryptedReference: 'sealed-case-ref',     // sealed inside the encrypted metadata
  expiresAfter: 90 * 86_400,                 // advisory expiry, seconds
});

const dataId = await op.addData({ foo: 1 }, { reference: 'Data42' });
await op.addData({ more: 'items allowed' });
const fileId = await op.addFile('/foo/bar/zap');            // stored under name "zap"
await op.addFile('/tmp/upload.tmp', { name: 'report.pdf' }); // explicit restore name
await op.addFileStream(someReadable, { name: 'stream.bin' });
await op.addFileBuffer(Buffer.from('…'), { name: 'note.txt', reference: 'Image1' });

const escrowId = await op.commit();  // atomic directory rename into the vault
// or: await op.destroy();           // abandon; staging directory removed

// The caller is responsible for deleting the plaintext sources afterwards.
```

If anything fails between `createEscrow()` and `commit()`, the operation
auto-destroys (see [Failure handling](#failure-handling)).

## Command-line tool

The package installs `escrow`, which creates one escrow per invocation and
prints its escrow-id to stdout (errors go to stderr with a non-zero exit):

```sh
escrow --escrow-key-file=./escrow-key.json --vault-directory=/escrow/vault \
           --reference='Secret data' --encrypted-reference='Very Secret Info' \
           --expires-after=90d \
           --data='{ "something": "fishy" }' --data='[1, 2, 3]' \
           --file=/fishy/file1 --file=/fishy/file2
02ac9ce7-d869-4ca3-822c-2bb4ef601d5c
```

| Option | Meaning |
|--------|---------|
| `--escrow-key-file=<file>` | **Required unless `--auto-key` or `--kv-key` is given.** JSON file containing the public escrow JWK. Env fallback: `OPT_ESCROW_KEY_FILE`. |
| `--vault-directory=<dir>` | **Required.** The vault directory. Env fallback: `OPT_VAULT_DIRECTORY`. |
| `--auto-key` | Generate a per-escrow [auto key](#auto-key). Conflicts with `--kv-key`. |
| `--auto-key-algorithm=<alg>` | `ECDH-ES` (default), `RSA-OAEP`, or `RSA-OAEP-256`. Env: `OPT_AUTO_KEY_ALGORITHM`. |
| `--auto-key-crv=<crv>` | EC curve for `ECDH-ES`: `P-256`, `P-384`, `P-521` (default). Env: `OPT_AUTO_KEY_CRV`. |
| `--auto-key-length=<bits>` | RSA modulus length (default 4096; ignored for `ECDH-ES`). Env: `OPT_AUTO_KEY_LENGTH`. |
| `--auto-key-output-file=<file>` | Write the generated auto key **private JWK** here (mode 0600; the path must not exist) — usable directly as `decrypt-escrow`'s secret key file. **Required** when `--auto-key` is given without `--escrow-key-file`. |
| `--kv-key` | Generate the per-escrow key in a [key vault](#key-vault); the metadata is encrypted to it and the expiry is enforced by the vault (the key is deleted at expiry). Conflicts with `--auto-key`. |
| `--kv-key-algorithm=<alg>` | `ECDH-ES` (default), `RSA-OAEP`, or `RSA-OAEP-256`. Env: `OPT_KV_KEY_ALGORITHM`. |
| `--kv-key-crv=<crv>` | EC curve for `ECDH-ES`: `P-256`, `P-384`, `P-521` (default). Env: `OPT_KV_KEY_CRV`. |
| `--kv-key-length=<bits>` | RSA modulus length (default 4096; ignored for `ECDH-ES`). Env: `OPT_KV_KEY_LENGTH`. |
| `--kv-url=<url>` | Key vault base URL. Env: `OPT_KV_URL`. |
| `--kv-user=<uuid>` | Key vault user id. Env: `OPT_KV_USER`. |
| `--kv-token=<uuid>` | Key vault token (mutually exclusive with `--kv-token-file`). Env: `OPT_KV_TOKEN`. |
| `--kv-token-file=<file>` | Read the key vault token from a file. Env: `OPT_KV_TOKEN_FILE`. |
| `--reference=<string>` | Cleartext escrow reference. |
| `--encrypted-reference=<string>` | Sealed escrow reference. |
| `--expires-at=<timestamp>` | Absolute advisory expiry (ISO-8601 or `YYYY-MM-DD HH:MM:SS` local time). Conflicts with `--expires-after`. |
| `--expires-after=<duration>` | Relative advisory expiry: an integer with optional `s`/`m`/`h`/`d`/`w`/`y` suffix (bare number = seconds). |
| `--compression=<alg>` | File compression before encryption: `none` (default), `deflate`, `gzip`, or `brotli`. Applies to every file unless overridden per file. |
| `--data=<json>` | A JSON data item (any JSON value). Repeatable. |
| `--file=<path-or-json>` | A file to escrow. Repeatable. Either a plain path (stored under its basename), or a JSON object for per-file options: `{"filename": <path>, "name"?, "reference"?, "encryptedReference"?, "compression"?}`. An argument starting with `{` is taken as JSON. |

At least one `--data` or `--file` is required. The two mandatory options may be
supplied via the environment instead of the command line. Auto-key and key-vault
sub-options given **without** their mode flag (`--auto-key` / `--kv-key`) are
ignored, so defaults can be set via the environment and take effect only when
the mode is on.

```sh
# Per-escrow key generated (and auto-expired) in a key vault
escrow --vault-directory=/escrow/vault --kv-key \
           --kv-url=https://kv.example.com/ --kv-user=<uuid> --kv-token-file=./kv-token \
           --expires-after=90d --data='{ "case": 7 }'
```

```sh
# global gzip, but ship the already-compressed video uncompressed under a new name
escrow … --compression=gzip \
             --file=/logs/app.log \
             --file='{"filename": "/media/cam1.mp4", "name": "evidence.mp4", "compression": "none"}'
```

## Vault layout

```
<vault>/
  .tmp/                          # staging area (created by the constructor)
  <prefix>/                      # first 4 characters of the escrow-id
    <escrow-id>/                 # one committed escrow (atomic rename from .tmp)
      escrow.json                # the manifest
      auto-key.json              # only for auto-key escrows written with an escrow key
      files/                     # present only if the escrow includes files
        <file-id>                # encrypted blob, named by UUID
```

`escrow-id`, `data-id`, and `file-id` are lower-case random UUIDs. A committed
escrow directory is immutable and self-contained; nothing outside it points at
it, so it may be moved or archived freely.

## The escrow.json manifest

```jsonc
{
  "metadata": {
    "id":  "02ac9ce7-d869-4ca3-822c-2bb4ef601d5c",  // escrow-id = directory name
    "kid": "escrow-key-2026",                       // kid of the escrow public key
    "iat": 1782977997,                              // unix seconds, creation time
    "exp": 1814513997,                              // unix seconds, advisory expiry (absent if none)
    "ref": "case-7",                                // optional cleartext reference
    "payload": "ey..."                              // JWE to the escrow public key
  },
  "data": {                                         // omitted when there are no data items
    "<data-id>": { "ref": "Data42", "payload": "ey..." },
    "<data-id>": { "payload": "ey..." }
  },
  "file": {                                         // omitted when there are no files
    "<file-id>": { "ref": "Image1", "payload": "ey..." }
  }
}
```

All timestamps are integer unix **seconds** (JWT convention).

### Token payloads

Compact JWE throughout (via `tr-jwe`). Two key layers, generated fresh:

1. **`metadata.payload`** — encrypted to the escrow **public** key (`RSA-OAEP`
   for RSA keys, `ECDH-ES` for EC keys; the key's `kid` is also in the JWE
   header). Encrypted claims: `{ id, kid, iat, exp?, ref?, cref?, key }` —
   every cleartext manifest field duplicated for tamper-binding, the optional
   sealed reference, and `key`, a per-escrow `A256GCMKW` **wrapping key** that
   opens all other payloads of this escrow.
2. **`data[id].payload`** — sealed with the wrapping key:
   `{ iat, id, ref?, cref?, data }`.
3. **`file[id].payload`** — sealed with the wrapping key:
   `{ iat, id, ref?, cref?, name, key }` — `name` is the restore basename and
   `key` that file's fresh `A256GCM` content key.

So a reader must first open `metadata.payload` (needs the private key) to get
the wrapping key, then open the data/file payloads, then decrypt the blobs.

### References

Two kinds, each optional at the escrow level and per item:

- **`reference`** — **cleartext** in the manifest (`ref`), also bound inside
  the corresponding encrypted payload so manifest tampering is detectable.
  Cleartext by design (findability without the private key); omit it if that
  is not acceptable.
- **`encryptedReference`** — stored **only** inside the corresponding encrypted
  payload (as `cref`); never appears in cleartext.

Uniqueness is enforced **within a single escrow only**, in memory: item-level
`reference`s share one scope across data and file items, `encryptedReference`s
have their own scope, and the escrow-level references are outside both. A
duplicate throws `ReferenceConflictError` and the whole escrow auto-destroys.
Nothing is enforced across escrows (there is no index).

### Encrypted file container

`files/<file-id>` is a self-describing AES-256-GCM container:

```
magic   "TRDE"  (4 bytes)
version 0x01     (1 byte)
enc     0x01     (1 byte, = AES-256-GCM)
comp    0x00     (1 byte, compression; see below)
ivlen   0x0C     (1 byte, = 12)
iv      12 bytes
                      ← the header above is authenticated as GCM AAD
ciphertext …
tag     16 bytes (GCM auth tag, appended last)
```

The content key is *not* in the file — it is in the corresponding
`file[id].payload`, sealed under the escrow key.

**Compression.** File content may be streamed through a zlib compression
filter before encryption. The `comp` byte names it: `0` = none, `1` = deflate,
`2` = gzip, `3` = brotli, `4` = zstd (reserved, not yet enabled). This byte in
the container header — authenticated but not encrypted — is the **only** place
the compression is recorded; it appears in neither the manifest nor any
payload. A reader decrypts first, then reverses the named compression.
Selected via the `compression` option: constructor default (`"none"`),
overridable per escrow in `createEscrow` options, overridable again per file
in `addFile*` options.

## API

### `new DataEscrow(options)`

Validates synchronously; the only constructor I/O is creating and
write-testing `<vaultDir>/.tmp` (throws on failure).

| Option         | Type             | Default | Meaning |
|----------------|------------------|---------|---------|
| `vaultDir`     | `string`         | —       | **Required.** The vault directory. |
| `escrowKey`    | JWK (public) `\| null` | —  | **Required unless `autoKey` or `kvKey` is `true`.** See [Escrow keys](#escrow-keys). |
| `autoKey`      | `boolean \| null` | `false` | Enable the per-escrow [auto key](#auto-key) layer. Mutually exclusive with `kvKey`. |
| `autoKeyAlgorithm` | `'ECDH-ES' \| 'RSA-OAEP' \| 'RSA-OAEP-256' \| null` | `'ECDH-ES'` | Auto key algorithm. Validated even when unused. |
| `autoKeyCrv`   | `'P-256' \| 'P-384' \| 'P-521' \| null` | `'P-521'` | EC curve for an `ECDH-ES` auto key. |
| `autoKeyLength` | `number \| null` | `4096` | Modulus bits for RSA auto keys: an integer, 2048–16384. |
| `kvKey`        | `boolean \| null` | `false` | Generate the per-escrow key in a [key vault](#key-vault). Mutually exclusive with `autoKey`. |
| `kvKeyAlgorithm` | `'ECDH-ES' \| 'RSA-OAEP' \| 'RSA-OAEP-256' \| null` | `'ECDH-ES'` | Key-vault key algorithm. |
| `kvKeyCrv`     | `'P-256' \| 'P-384' \| 'P-521' \| null` | `'P-521'` | EC curve for an `ECDH-ES` key-vault key. |
| `kvKeyLength`  | `number \| null` | `4096` | Modulus bits for RSA key-vault keys. |
| `kv`           | connection `\| KeyVaultClient \| null` | — | Key-vault connection: `{ url, user?, token?, timeout?, insecure?, ca? }` or a `tr-key-vault-client` instance. Required (here or per operation) when `kvKey` is on. |
| `expiresAfter` | `number \| null` | none    | Default expiry in **seconds** after creation, for escrows that don't set their own. Finite, `≥ 0`. Advisory for plain/auto escrows; **enforced by the vault** for kvKey escrows. (`expiresAt` is not a constructor option.) |
| `compression`  | `'none' \| 'deflate' \| 'gzip' \| 'brotli'` | `'none'` | Default compression for file content (before encryption). `'zstd'` is a reserved container code and rejected for now. |

### `escrow(data, options?): Promise<string>`

One-shot escrow of exactly one data item — any JSON-serializable value
(object, array, string, number, boolean, or `null`). Returns the escrow-id.
`undefined`/non-serializable data throws `TypeError`. The options are
**escrow-level** (they name the escrow, not the data item). For files,
multiple data items, or item-level references use `createEscrow`.

### `createEscrow(options?): Promise<DataEscrowOperation>`

Begins a multi-step escrow: fixes `iat`, resolves the advisory `exp`,
generates the wrapping key, seals the metadata payload, and creates the
staging directory. Nothing appears in the vault proper until `commit()`.

Per-escrow options (also accepted by `escrow()`):

| Option               | Type                     | Meaning |
|----------------------|--------------------------|---------|
| `reference`          | `string \| null`         | Cleartext escrow reference. |
| `encryptedReference` | `string \| null`         | Sealed escrow reference (`cref`). |
| `expiresAt`          | `Date \| string \| null` | Absolute advisory expiry (`Date` or ISO-8601 string). `null` = no expiry (overrides the constructor default). |
| `expiresAfter`       | `number \| null`         | Relative advisory expiry, **seconds** after creation. `null` = no expiry (overrides the constructor default). |
| `compression`        | `'none' \| 'deflate' \| 'gzip' \| 'brotli'` | Default file compression for this escrow, overriding the constructor default. |
| `escrowKey`          | JWK (public) `\| null`   | Escrow key for this operation only. Absent/`undefined`: inherit the constructor key. **`null`: no escrow key** — requires effective `autoKey` or `kvKey`. |
| `autoKey`            | `boolean \| null`        | [Auto key](#auto-key) for this escrow (`null`/absent: inherit; `false`: off). |
| `autoKeyAlgorithm` / `autoKeyCrv` / `autoKeyLength` | see constructor | Auto key parameters for this escrow (`null`/absent: inherit). |
| `kvKey`              | `boolean \| null`        | [Key vault](#key-vault) for this escrow (`null`/absent: inherit; `false`: off). To switch an inherited `autoKey:true` to the vault, pass `{ autoKey: false, kvKey: true }`. |
| `kvKeyAlgorithm` / `kvKeyCrv` / `kvKeyLength` / `kv` | see constructor | Key-vault parameters and connection for this escrow (`null`/absent: inherit). |

Supplying both `expiresAt` and `expiresAfter` throws `TypeError`. Expiry is
advisory: stored in the manifest (and sealed into the metadata payload), never
enforced by this module. One-shot `escrow()` rejects an effective-`null`
escrow key eagerly — it could never call `autoKeyPair()`.

### `DataEscrowOperation`

Returned by `createEscrow()`. Encrypts each input immediately into the staging
directory, so `commit()` is just manifest-write + rename. Methods are
serialized (one at a time). `state` is `pending`, then `committed` or
`destroyed`; the escrow `id` is available from creation.

| Method | Returns | Notes |
|--------|---------|-------|
| `addData(data, options?)` | `Promise<string>` (data-id) | Any number of calls. `options`: `{ reference?, encryptedReference? }`. |
| `addFile(path, options?)` | `Promise<string>` (file-id) | `options`: `{ name?, reference?, encryptedReference?, compression? }`; `name` defaults to the file's basename. |
| `addFileStream(readable, options)` | `Promise<string>` (file-id) | Same options; `options.name` **required**. |
| `addFileBuffer(buffer, options)` | `Promise<string>` (file-id) | Same options; `options.name` **required**. |
| `autoKeyPair()` | `{ secretKey, publicKey }` | Synchronous. The escrow's [auto key](#auto-key) pair (fresh deep copy each call), for independent storage. Throws when autoKey is off or the operation is not pending; a throwing call does **not** destroy the operation. |
| `commit()` | `Promise<string>` (escrow-id) | Throws `TypeError` if the escrow is empty, or (without destroying the operation) if it has no escrow key and `autoKeyPair()` was never called. Atomic rename into the vault; drops in-memory secrets. |
| `destroy()` | `Promise<void>` | Abandon: removes the staging directory. No-op after `commit()`. Idempotent. |

The `autoKid` getter is the `auto:`-prefixed auto key id (`null` when autoKey
is off).

`name` is a restore basename (metadata only, sealed in the payload) and must
be a legal unix filesystem path component: non-empty, ≤ 255 chars and ≤ 255
UTF-8 bytes, no path separators or NUL, not `.` or `..`. References: non-empty
strings, ≤ 1024 chars.

## Escrow keys

The `escrowKey` must be a **public** JWK carrying a non-empty `kid`, one of:

- **RSA** — `{ kty: 'RSA', alg: 'RSA-OAEP' | 'RSA-OAEP-256', kid, n, e }`,
  modulus **≥ 2048 bits**. Sealed with that algorithm.
- **EC** — `{ kty: 'EC', crv: 'P-256' | 'P-384' | 'P-521', kid, x, y }`. Sealed
  with `ECDH-ES`.

A key carrying private material (an RSA/EC `d` member) is rejected — the writer
must not be able to hold decryption power. The key's `kid` is recorded in the
manifest and the JWE headers so a reader can select the right private key.

Generate keys with [`tr-jwk`](https://www.npmjs.com/package/tr-jwk)
(`ecKeyGen('P-521')` returns `{ secretKey, publicKey }`); keep the public half
in the writer and the secret half under separate custody. The `auto:` kid
prefix is reserved for [auto keys](#auto-key) and rejected here.

## Auto key

An optional second key layer, default off — when unused, nothing changes.
With `autoKey` enabled (constructor default or per operation), `createEscrow`
generates a fresh **auto key pair** for that one escrow (`autoKeyAlgorithm`
`ECDH-ES` on `autoKeyCrv`, or `RSA-OAEP`/`RSA-OAEP-256` of `autoKeyLength`
bits; kid `auto:<uuid>`), and the manifest's metadata payload is encrypted to
its public half instead of the escrow key — `metadata.kid` becomes the auto
kid. Key pairs are generated asynchronously (never blocking the event loop,
though RSA at large moduli still takes real time). `autoKey` and `kvKey` are
mutually exclusive.

The auto **private** key has two recovery paths, usable together:

- **`autoKeyPair()`** on the operation returns `{ secretKey, publicKey }` for
  the caller to store independently — the auto secret JWK opens the escrow
  directly as a `DataEscrowDecrypt` `escrowSecretKey`.
- **`auto-key.json`** — when the operation also has an escrow key, the auto
  secret key is sealed to it and stored beside `escrow.json`:

  ```jsonc
  {
    "kid": "auto:678ebcc5-45cb-4d50-8704-e5d1b297ddf8",  // auto key id
    "iat": 1783007751,                                    // same iat as escrow.json
    "exp": 1787007751,                                    // advisory; present iff the escrow has one
    "payload": "ey..."                                    // JWE to the escrow public key
  }
  ```

  The sealed claims are `{ kid, iat, exp?, key }` with `key` the auto secret
  JWK; `DataEscrowDecrypt.decryptAutoKey()` recovers it (verifying the
  sealed/cleartext binding).

With an escrow key present the escrow stays recoverable through either path.
Without one (`escrowKey: null` per operation, or an autoKey-only
constructor), the auto key is the **only** path — so `commit()` refuses,
without destroying the operation, until `autoKeyPair()` has been called.

## Key vault

An alternative to `autoKey`, default off and mutually exclusive with it. With
`kvKey` enabled, `createEscrow` asks a
[tr-key-vault](https://github.com/rinne/tr-key-vault) server (the `kv`
connection) to generate the per-escrow key; the vault returns only the public
half and keeps the private half. The metadata is encrypted to that public key,
`metadata.kid` is the vault's key id, and the manifest records `metadata.kv =
{ url }`. **The private key never touches this process** — recovery goes back
through the vault.

```js
const kc = { url: 'https://kv.example.com/', user: '<uuid>', token: '<uuid>' };
const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kc });
const id = await esc.escrow({ case: 7 }, { expiresAfter: 90 * 86400 });
// recover later:
const dec = new DataEscrowDecrypt({ kv: kc });
const opened = await dec.decrypt(JSON.parse(readFileSync(join(dir, 'escrow.json'), 'utf8')));
```

- **Hands-off expiry.** The escrow's `exp` is handed to the vault as a hard
  deletion deadline — the vault deletes the key at expiry, after which the
  escrow is permanently unrecoverable. Set an expiry with `expiresAfter` /
  `expiresAt`; with none, the vault key is non-expiring. A past/now expiry is
  rejected. (For plain and auto escrows `exp` stays purely advisory.)
- **No local custody dance.** The vault is the custody, so there is no
  `autoKeyPair()` collection and no `auto-key.json`; one-shot `escrow()` works
  with `kvKey` and no escrow key.
- **Recovery.** `DataEscrowDecrypt` takes an optional `kv` connection
  (constructor or per `decrypt()` call). For a kv-backed escrow it unwraps the
  metadata via the vault, then decrypts everything else locally. The reader's
  `url` overrides the manifest's; `user`/`token` always come from the reader.
  `decrypt-escrow` gains matching `--kv-url` / `--kv-user` / `--kv-token[-file]`
  (with `OPT_KV_*` fallbacks; `--kv-url` optional, taken from the manifest).
- **Abandon cleanup.** If an operation is destroyed or fails before commit, its
  vault key is revoked best-effort.
- **The `kv` connection** is `{ url, user?, token?, timeout?, insecure?, ca? }`
  or a `tr-key-vault-client` `KeyVaultClient` instance; it is overridable per
  operation. `tr-key-vault-client` is a dependency but is **loaded lazily** —
  code that never uses `kvKey` never pulls it in.

## Failure handling

- **Eager encryption.** Every `add*` fully encrypts (and fsyncs file blobs)
  into the staging directory before resolving.
- **Auto-destroy on error.** If any `add*` throws (bad path, I/O error,
  duplicate reference, non-serializable data), the operation auto-destroys:
  the staging directory is removed recursively and the operation becomes
  unusable (later calls throw).
- **Commit is all-or-nothing.** The manifest is written and fsynced in
  staging; the escrow then appears in the vault via a single atomic
  `rename`. A failed commit cleans up staging before throwing.
- **GC safety net.** A `FinalizationRegistry` best-effort-removes the staging
  directory of an operation that is garbage-collected without
  `commit()`/`destroy()`. A backstop, not a guarantee — call `destroy()` to
  abandon explicitly. Staging leftovers from process crashes are not swept by
  this version.

## Errors

| Error                    | When |
|--------------------------|------|
| `TypeError`              | Invalid configuration (vaultDir, escrowKey, expiry options); non-serializable data; invalid file input/name/reference; empty `commit`; using an operation after `commit`/`destroy`. |
| `ReferenceConflictError` | A duplicate `reference` or `encryptedReference` among the items of one escrow. Carries `.kind` and `.reference`. The operation auto-destroys first. Exported. |

Operational filesystem errors propagate from the underlying calls (and trigger
auto-destroy of the operation).

## Decryption: `tr-data-escrow/decrypt`

The reader is a separate subpath so that `require('tr-data-escrow')` pulls in
zero decryption code; import it only where the escrow **secret** key
legitimately exists:

```ts
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DataEscrowDecrypt } from 'tr-data-escrow/decrypt';

const dec = new DataEscrowDecrypt({ escrowSecretKey: [key2025, key2026] });
const opened = await dec.decrypt(
  JSON.parse(readFileSync(join(dir, 'escrow.json'), 'utf8')),
);

const manifest = opened.data(); // augmented deep copy
for (const [fileId, entry] of Object.entries(manifest.file ?? {})) {
  // payloadData.name is metadata only — the caller sanitizes and joins
  await opened.decryptFile(fileId, join(dir, 'files', fileId),
                           join(outDir, String(entry.payloadData.name)));
}
opened.destroy();
dec.destroy();
```

### `new DataEscrowDecrypt({ escrowSecretKey })`

`escrowSecretKey`: one secret JWK or a non-empty array of them, each with a
unique non-empty `kid` (escrows select their key by kid). RSA needs `d` and a
modulus ≥ 2048 bits (`alg`, when present, must be `"RSA-OAEP"`); EC needs `d`
and `crv` P-256/384/521. Synchronous, no I/O.

### `decrypt(escrowObject, options?): Promise<DataEscrowDecryptOperation>`

Takes the object JSON-parsed from `escrow.json` (the caller does the reading —
no filesystem I/O here) and a reserved `options` object (unknown keys are
rejected). Selects the secret key by `metadata.kid`, decrypts every payload,
and verifies that all sealed claims match their cleartext duplicates in the
manifest (absence included) — any mismatch throws `EscrowIntegrityError`. The
input object is never mutated. The advisory `exp` is **not** enforced: an
expired escrow still decrypts.

The returned operation exposes:

- `originalData()` — deep copy of the input object, exactly as passed in.
- `data()` — deep copy of the augmented manifest: next to every `payload`
  sit `payloadData` (the decrypted claims) and `payloadContentKey` (the JWE
  content-encryption key, letting anyone later prove `payloadData` came from
  exactly that token without re-exposing the escrow secret key). A fresh copy
  on every call.
- `decryptFile(fileId, source, destination)` — decrypts the physical
  container **atomically** to the path `destination` (temp file next to it,
  fsync, rename; nothing appears on failure). Resolves to `true`.
- `decryptFileToStream(fileId, source)` — resolves to a plaintext `Readable`
  after header validation. Streamed-AEAD caveat: bytes flow before the GCM
  tag is verified; a tag/decompression failure is an `'error'` event on the
  stream and the output must be discarded.
- `decryptFileToBuffer(fileId, source)` — resolves to the full plaintext,
  verified before return.
- `destroy()` — clears keys and decrypted data; further calls throw.

`source` is a path string, a `Buffer`, or a `Readable` — escrow directories
are relocatable, so the caller says where the encrypted container lives.
Both classes have independent `destroy()` lifecycles: destroying the
`DataEscrowDecrypt` does not invalidate operations it already returned.

### `decryptAutoKey(autoKeyObject): Promise<{ secretKey, publicKey }>`

Recovers an [auto key](#auto-key) pair from the object JSON-parsed from an
escrow's `auto-key.json` (again, the caller reads the file). The escrow
secret key is selected by the payload's JWE protected-header kid; the sealed
`kid`/`iat`/`exp` are verified against their cleartext counterparts and the
sealed key's own kid must match (`EscrowIntegrityError` otherwise). Returns
deep copies; the recovered `secretKey` opens the escrow's `escrow.json`
through a `DataEscrowDecrypt` of its own. An auto escrow written **without**
an escrow key has no `auto-key.json` — only the pair stored via
`autoKeyPair()` can open it.

### Decrypt errors

| Error                    | When |
|--------------------------|------|
| `TypeError`              | Invalid constructor options or arguments; unknown `decrypt` options; use after `destroy()`. |
| `UnknownEscrowKeyError`  | No configured secret key matches `metadata.kid` (or an auto-key payload's header kid). Carries `.kid`. |
| `UnknownFileIdError`     | A file method's `fileId` is not a file of the escrow. Carries `.fileId`. |
| `EscrowIntegrityError`   | A sealed claim does not match its cleartext duplicate. Carries `.field`. |

Token, container, and decompression failures propagate (wrapped with context
where it helps).

### Command-line restore: `decrypt-escrow`

```sh
decrypt-escrow --escrow-secret-key-file=<path> \
               [ <source-directory> [ <destination-directory> ] ]
```

Restores one escrow directory and prints its escrow-id (errors go to stderr
with a non-zero exit). The key file contains one escrow secret JWK or an array
of them; it may also come from the `OPT_ESCROW_SECRET_KEY_FILE` environment
variable. The source directory (default `.`) is the escrow directory itself —
it must contain `escrow.json` (plus `files/` when the escrow has files). The
destination (default: the source directory) must already exist, be writable,
and not yet contain `escrow-decrypted.json` or `files-decrypted`.

Usage is the same for [auto-key](#auto-key) escrows. When the auto key is
stored in the escrow (`auto-key.json` present), pass the escrow secret key
file as always — if no configured key matches directly, the tool recovers
the auto key with the configured keys automatically and proceeds (the
recovered secret key is never written to the output). When the auto key is
not stored in the escrow, pass the auto key secret JWK (the
`escrow --auto-key-output-file` output) in place of the escrow secret key —
it is an ordinary secret key file.

It writes `escrow-decrypted.json` (the augmented manifest, as from `data()`)
and, when the escrow has files, `files-decrypted/<name>` with each file's
plaintext under its sealed `name`. The run is **all-or-nothing**: outputs are
staged in a temporary directory inside the destination and renamed into place
at the end; any failure (wrong key, integrity violation, damaged blob,
duplicate decrypted name) leaves the destination without any of the output
entries. Decrypting in place — next to `escrow.json` — is safe by
construction.

## License

MIT © Timo J. Rinne &lt;tri@iki.fi&gt;
