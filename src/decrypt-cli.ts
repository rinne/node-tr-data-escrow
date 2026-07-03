#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import {
  accessSync,
  constants as fsConstants,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import Optist from 'optist';
import { DataEscrowDecrypt, UnknownEscrowKeyError } from './decrypt';
import { validateName } from './util';

function existingFileCb(s: string): string | undefined {
  try {
    return statSync(s).isFile() ? s : undefined;
  } catch {
    return undefined;
  }
}

function fail(message: string): never {
  process.stderr.write(`decrypt-escrow: ${message}\n`);
  process.exit(1);
}

/** A directory that exists; fails with a labeled error otherwise. */
function requireDirectory(path: string, label: string): void {
  let st;
  try {
    st = statSync(path);
  } catch {
    fail(`${label} ${JSON.stringify(path)} does not exist`);
  }
  if (!st.isDirectory()) {
    fail(`${label} ${JSON.stringify(path)} is not a directory`);
  }
}

async function main(): Promise<void> {
  const opt = new Optist()
    .opts([
      {
        longName: 'escrow-secret-key-file',
        hasArg: true,
        required: true,
        optArgCb: existingFileCb,
        environment: 'OPT_ESCROW_SECRET_KEY_FILE',
        description: 'JSON file containing the escrow secret key (JWK, or an array of them)',
      },
    ])
    .help('decrypt-escrow [ <source-directory> [ <destination-directory> ] ]')
    .additional(0, 2)
    .parse();

  const rest = opt.rest();
  const srcDir = resolve(rest[0] ?? '.');
  const destDir = resolve(rest[1] ?? srcDir);

  // --- escrow secret key ---
  const keyFile = opt.value('escrow-secret-key-file') as string;
  let escrowSecretKey: Record<string, unknown> | Record<string, unknown>[];
  try {
    escrowSecretKey = JSON.parse(readFileSync(keyFile, 'utf8'));
  } catch (err) {
    fail(`cannot read escrow secret key from ${JSON.stringify(keyFile)}: ${(err as Error).message}`);
  }
  const dec = new DataEscrowDecrypt({ escrowSecretKey });

  // --- source directory ---
  requireDirectory(srcDir, 'source directory');
  const manifestPath = join(srcDir, 'escrow.json');
  let manifest: unknown;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    fail(`cannot read escrow manifest ${JSON.stringify(manifestPath)}: ${(err as Error).message}`);
  }

  // --- destination directory ---
  requireDirectory(destDir, 'destination directory');
  try {
    accessSync(destDir, fsConstants.W_OK);
  } catch {
    fail(`destination directory ${JSON.stringify(destDir)} is not writable`);
  }
  const destManifest = join(destDir, 'escrow-decrypted.json');
  const destFiles = join(destDir, 'files-decrypted');
  for (const target of [destManifest, destFiles]) {
    if (existsSync(target)) {
      fail(`destination already contains ${JSON.stringify(target)}`);
    }
  }

  // --- decrypt the manifest ---
  // When no configured key matches and the escrow carries an auto-key.json,
  // recover the auto key with the configured keys and retry; if the fallback
  // fails for any reason, the original error surfaces.
  let op;
  try {
    op = await dec.decrypt(manifest);
  } catch (err) {
    if (!(err instanceof UnknownEscrowKeyError)) throw err;
    const autoKeyPath = join(srcDir, 'auto-key.json');
    if (!existsSync(autoKeyPath)) throw err;
    try {
      const autoKeyObject: unknown = JSON.parse(readFileSync(autoKeyPath, 'utf8'));
      const { secretKey } = await dec.decryptAutoKey(autoKeyObject);
      const autoDec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
      op = await autoDec.decrypt(manifest);
    } catch {
      throw err;
    }
  }
  const data = op.data();
  const fileEntries = Object.entries(data.file ?? {});
  if (fileEntries.length > 0) {
    requireDirectory(join(srcDir, 'files'), 'escrow files directory');
  }

  // --- stage everything, then place; the whole run fully succeeds or fully
  // fails (nothing named escrow-decrypted.json / files-decrypted appears on
  // failure) ---
  const tmpDir = join(destDir, `.escrow-decrypt-${randomUUID()}.tmp`);
  mkdirSync(tmpDir);
  try {
    if (fileEntries.length > 0) {
      mkdirSync(join(tmpDir, 'files-decrypted'));
      const seen = new Set<string>();
      for (const [fileId, entry] of fileEntries) {
        // Thrown (not fail()ed) so the finally below removes the staging
        // directory; main()'s catch turns it into the CLI error exit.
        const name = entry.payloadData.name;
        let safeName: string;
        try {
          safeName = validateName(name);
        } catch (err) {
          throw new Error(
            `escrow file ${fileId} has an unusable stored name: ${(err as Error).message}`,
          );
        }
        if (seen.has(safeName)) {
          throw new Error(`escrow files decrypt to a duplicate name ${JSON.stringify(safeName)}`);
        }
        seen.add(safeName);
        await op.decryptFile(
          fileId,
          join(srcDir, 'files', fileId),
          join(tmpDir, 'files-decrypted', safeName),
        );
      }
    }
    writeFileSync(
      join(tmpDir, 'escrow-decrypted.json'),
      JSON.stringify(data, null, 2) + '\n',
      { flag: 'wx' },
    );

    // Final placement. Re-check the targets, then rename out of staging; if
    // the manifest placement fails after the files were placed, roll back.
    for (const target of [destManifest, destFiles]) {
      if (existsSync(target)) {
        throw new Error(`destination already contains ${JSON.stringify(target)}`);
      }
    }
    let filesPlaced = false;
    try {
      if (fileEntries.length > 0) {
        renameSync(join(tmpDir, 'files-decrypted'), destFiles);
        filesPlaced = true;
      }
      renameSync(join(tmpDir, 'escrow-decrypted.json'), destManifest);
    } catch (err) {
      if (filesPlaced) {
        rmSync(destFiles, { recursive: true, force: true });
      }
      throw err;
    }
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }

  process.stdout.write(`${data.metadata.id}\n`);
}

main().catch((err: unknown) => {
  fail(err instanceof Error ? err.message : String(err));
});
