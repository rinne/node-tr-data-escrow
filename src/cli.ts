#!/usr/bin/env node
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import Optist from 'optist';
import {
  DataEscrow,
  type AutoKeyAlgorithm,
  type CompressionName,
  type EscrowOptions,
} from './index';

/** Any valid JSON text → the parsed value; invalid → undefined (optist failure). */
function jsonCb(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return undefined;
  }
}

/** A path that exists and is a regular file; otherwise undefined. */
function existingFileCb(s: string): string | undefined {
  try {
    return statSync(s).isFile() ? s : undefined;
  } catch {
    return undefined;
  }
}

/** One --file argument, normalized. */
interface FileSpec {
  filename: string;
  name?: string;
  reference?: string;
  encryptedReference?: string;
  compression?: CompressionName;
}

const FILE_SPEC_KEYS = ['filename', 'name', 'reference', 'encryptedReference', 'compression'];

/**
 * A --file argument: a plain path, or (when it starts with "{") a JSON object
 * `{ "filename": ..., "name"?, "reference"?, "encryptedReference"?,
 * "compression"? }`. The named file must exist. Value details (compression
 * name, references) are validated by the library for clearer errors.
 */
function fileCb(s: string): FileSpec | undefined {
  let spec: FileSpec;
  if (/^\s*\{/.test(s)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(s);
    } catch {
      return undefined;
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return undefined;
    }
    const o = parsed as Record<string, unknown>;
    if (Object.keys(o).some((k) => !FILE_SPEC_KEYS.includes(k))) {
      return undefined;
    }
    if (typeof o.filename !== 'string' || o.filename.length === 0) {
      return undefined;
    }
    spec = o as unknown as FileSpec;
  } else {
    spec = { filename: s };
  }
  return existingFileCb(spec.filename) === undefined ? undefined : spec;
}

/** Anything `new Date()` parses (ISO-8601, `YYYY-MM-DD HH:MM:SS`, …) → Date. */
function dateCb(s: string): Date | undefined {
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? undefined : d;
}

const DURATION_UNITS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
  y: 31536000,
};

/** Duration → seconds: a non-negative integer with optional s/m/h/d/w/y suffix. */
function durationCb(s: string): number | undefined {
  const m = /^([0-9]+)([smhdwy])?$/.exec(s.trim());
  if (!m) return undefined;
  const n = Number.parseInt(m[1] as string, 10);
  const seconds = n * (DURATION_UNITS[m[2] ?? 's'] as number);
  return Number.isSafeInteger(seconds) ? seconds : undefined;
}

function nonEmptyCb(s: string): string | undefined {
  return s.length > 0 ? s : undefined;
}

function fail(message: string): never {
  process.stderr.write(`escrow: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const opt = new Optist()
    .opts([
      {
        longName: 'escrow-key-file',
        hasArg: true,
        optArgCb: existingFileCb,
        environment: 'OPT_ESCROW_KEY_FILE',
        description: 'JSON file containing the public escrow key (JWK); required unless --auto-key is given',
      },
      {
        longName: 'auto-key',
        description: 'generate a per-escrow auto key; the escrow metadata is encrypted to it',
      },
      {
        longName: 'auto-key-algorithm',
        hasArg: true,
        optArgCb: nonEmptyCb,
        requiresAlso: 'auto-key',
        description:
          'auto key algorithm: P-256|P-384|P-521|RSA-OAEP (default P-521; RSA uses a 4096-bit modulus)',
      },
      {
        longName: 'auto-key-output-file',
        hasArg: true,
        optArgCb: nonEmptyCb,
        requiresAlso: 'auto-key',
        description:
          'write the generated auto key private JWK here (mode 0600; must not exist); ' +
          'required with --auto-key when no --escrow-key-file is given',
      },
      {
        longName: 'vault-directory',
        hasArg: true,
        required: true,
        optArgCb: nonEmptyCb,
        environment: 'OPT_VAULT_DIRECTORY',
        description: 'vault directory the escrow is written into',
      },
      {
        longName: 'reference',
        hasArg: true,
        optArgCb: nonEmptyCb,
        description: 'cleartext escrow reference',
      },
      {
        longName: 'encrypted-reference',
        hasArg: true,
        optArgCb: nonEmptyCb,
        description: 'sealed escrow reference (stored only inside the encrypted metadata)',
      },
      {
        longName: 'expires-at',
        hasArg: true,
        optArgCb: dateCb,
        conflictsWith: 'expires-after',
        description: 'absolute advisory expiry (ISO-8601 or "YYYY-MM-DD HH:MM:SS")',
      },
      {
        longName: 'expires-after',
        hasArg: true,
        optArgCb: durationCb,
        conflictsWith: 'expires-at',
        description: 'relative advisory expiry: integer with optional s/m/h/d/w/y suffix (default s)',
      },
      {
        longName: 'compression',
        hasArg: true,
        optArgCb: nonEmptyCb,
        description: 'file compression before encryption: none|deflate|gzip|brotli (default none)',
      },
      {
        longName: 'data',
        hasArg: true,
        multi: true,
        optArgCb: jsonCb,
        description: 'JSON data item to escrow (repeatable)',
      },
      {
        longName: 'file',
        hasArg: true,
        multi: true,
        optArgCb: fileCb,
        description:
          'file to escrow (repeatable): a path, or a JSON object ' +
          '{"filename":...,"name"?,"reference"?,"encryptedReference"?,"compression"?}',
      },
    ])
    .help('escrow')
    .additional(0, 0)
    .parse();

  const dataItems = opt.value('data') as unknown[];
  const files = opt.value('file') as FileSpec[];
  if (dataItems.length === 0 && files.length === 0) {
    fail('nothing to escrow: provide at least one --data or --file');
  }

  const autoKey = opt.value('auto-key') as boolean;
  const autoKeyOutputFile = opt.value('auto-key-output-file') as string | undefined;
  const keyFile = opt.value('escrow-key-file') as string | undefined;
  if (keyFile === undefined && !autoKey) {
    fail('--escrow-key-file is required unless --auto-key is given');
  }
  if (autoKey && keyFile === undefined && autoKeyOutputFile === undefined) {
    // Without an escrow key no auto-key.json is written; losing the auto key
    // would make the escrow unrecoverable from birth.
    fail('with --auto-key and no --escrow-key-file, --auto-key-output-file is required');
  }
  let escrowKey: Record<string, unknown> | undefined;
  if (keyFile !== undefined) {
    try {
      escrowKey = JSON.parse(readFileSync(keyFile, 'utf8')) as Record<string, unknown>;
    } catch (err) {
      fail(`cannot read escrow key from ${JSON.stringify(keyFile)}: ${(err as Error).message}`);
    }
  }

  const escrowOptions: EscrowOptions = {};
  if (opt.value('reference') !== undefined) {
    escrowOptions.reference = opt.value('reference') as string;
  }
  if (opt.value('encrypted-reference') !== undefined) {
    escrowOptions.encryptedReference = opt.value('encrypted-reference') as string;
  }
  if (opt.value('expires-at') !== undefined) {
    escrowOptions.expiresAt = opt.value('expires-at') as Date;
  }
  if (opt.value('expires-after') !== undefined) {
    escrowOptions.expiresAfter = opt.value('expires-after') as number;
  }
  if (opt.value('compression') !== undefined) {
    // Escrow-level default; a --file JSON object may still override per file.
    // Name validation (including the reserved "zstd") is the library's.
    escrowOptions.compression = opt.value('compression') as CompressionName;
  }

  const esc = new DataEscrow({
    vaultDir: opt.value('vault-directory') as string,
    ...(escrowKey !== undefined ? { escrowKey } : {}),
    ...(autoKey ? { autoKey: true } : {}),
    // Value validation is the library's; an RSA-OAEP auto key uses the
    // library-default 4096-bit modulus (not configurable in the CLI).
    ...(opt.value('auto-key-algorithm') !== undefined
      ? { autoKeyAlgorithm: opt.value('auto-key-algorithm') as AutoKeyAlgorithm }
      : {}),
  });

  const op = await esc.createEscrow(escrowOptions);
  try {
    if (autoKeyOutputFile !== undefined) {
      // The private JWK alone (it contains the public parameters) — the file
      // drops directly into decrypt-escrow's --escrow-secret-key-file.
      // Persisted before anything else happens, so a failure here can never
      // leave a committed escrow behind without its key.
      writeFileSync(
        autoKeyOutputFile,
        JSON.stringify(op.autoKeyPair().secretKey, null, 2) + '\n',
        { flag: 'wx', mode: 0o600 },
      );
    }
    for (const data of dataItems) {
      await op.addData(data);
    }
    for (const file of files) {
      await op.addFile(file.filename, {
        name: file.name,
        reference: file.reference,
        encryptedReference: file.encryptedReference,
        compression: file.compression,
      });
    }
    const id = await op.commit();
    process.stdout.write(`${id}\n`);
  } catch (err) {
    await op.destroy().catch(() => {});
    throw err;
  }
}

main().catch((err: unknown) => {
  fail(err instanceof Error ? err.message : String(err));
});
