import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { type Jwk } from 'tr-jwk';
import { DataEscrow } from '../src/index';
import { makeVaultDir, ecEscrowKeys, escrowDir } from './helpers';

const execFileAsync = promisify(execFile);
const CLI = resolve(__dirname, '..', 'dist', 'decrypt-cli.js');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function runCli(args: string[], cwd?: string): Promise<CliResult> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], { cwd });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

interface Setup {
  workDir: string;
  keyFile: string;
  srcDir: string;
  escrowId: string;
  fileContents: Map<string, Buffer>;
}

/** A committed escrow (two data items, optional files) plus a secret-key file. */
async function setup(fileNames: string[] = ['a.bin', 'b.txt']): Promise<Setup> {
  const workDir = makeVaultDir();
  const { publicKey, secretKey } = ecEscrowKeys('P-384');
  const keyFile = join(workDir, 'secret.json');
  writeFileSync(keyFile, JSON.stringify(secretKey));

  const vaultDir = join(workDir, 'vault');
  const esc = new DataEscrow({ vaultDir, escrowKey: publicKey, compression: 'gzip' });
  const op = await esc.createEscrow({ reference: 'cli-restore' });
  await op.addData({ n: 1 });
  await op.addData(['x', 'y']);
  const fileContents = new Map<string, Buffer>();
  for (const name of fileNames) {
    const content = randomBytes(2048);
    fileContents.set(name, content);
    await op.addFileBuffer(content, { name });
  }
  const escrowId = await op.commit();
  return { workDir, keyFile, srcDir: escrowDir(vaultDir, escrowId), escrowId, fileContents };
}

function expectFullResult(s: Setup, destDir: string): void {
  const decrypted = JSON.parse(readFileSync(join(destDir, 'escrow-decrypted.json'), 'utf8'));
  expect(decrypted.metadata.id).toBe(s.escrowId);
  expect(decrypted.metadata.payloadData.ref).toBe('cli-restore');
  const dataValues = Object.values(decrypted.data as Record<string, { payloadData: { data: unknown } }>)
    .map((e) => e.payloadData.data);
  expect(dataValues).toContainEqual({ n: 1 });
  expect(dataValues).toContainEqual(['x', 'y']);
  for (const [name, content] of s.fileContents) {
    expect(readFileSync(join(destDir, 'files-decrypted', name))).toEqual(content);
  }
}

describe('decrypt-escrow CLI', () => {
  it('decrypts into a separate destination directory and prints the escrow id', async () => {
    const s = await setup();
    const destDir = join(s.workDir, 'restore');
    mkdirSync(destDir);
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir, destDir]);
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    expect(r.stdout.trim()).toBe(s.escrowId);
    expect(r.stdout.trim()).toMatch(UUID_RE);
    expectFullResult(s, destDir);
    // no staging residue anywhere
    expect(readdirSync(destDir).sort()).toEqual(['escrow-decrypted.json', 'files-decrypted']);
  });

  it('defaults the destination to the source directory (safe in-place decrypt)', async () => {
    const s = await setup();
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir]);
    expect(r.code).toBe(0);
    expectFullResult(s, s.srcDir);
    // the encrypted escrow is untouched next to its decryption
    expect(readdirSync(s.srcDir).sort()).toEqual([
      'escrow-decrypted.json',
      'escrow.json',
      'files',
      'files-decrypted',
    ]);
  });

  it('defaults the source directory to the current working directory', async () => {
    const s = await setup();
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`], s.srcDir);
    expect(r.code).toBe(0);
    expectFullResult(s, s.srcDir);
  });

  it('creates no files-decrypted for an escrow without files', async () => {
    const s = await setup([]);
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir]);
    expect(r.code).toBe(0);
    expect(existsSync(join(s.srcDir, 'escrow-decrypted.json'))).toBe(true);
    expect(existsSync(join(s.srcDir, 'files-decrypted'))).toBe(false);
  });

  it('fails cleanly on preconditions', async () => {
    const s = await setup();

    // missing / unreadable key file
    let r = await runCli([`--escrow-secret-key-file=${join(s.workDir, 'nope.json')}`, s.srcDir]);
    expect(r.code).not.toBe(0);

    // source without escrow.json
    const empty = join(s.workDir, 'empty');
    mkdirSync(empty);
    r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, empty]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/escrow\.json|manifest/);

    // destination does not exist
    r = await runCli([
      `--escrow-secret-key-file=${s.keyFile}`,
      s.srcDir,
      join(s.workDir, 'no-such-dir'),
    ]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/destination/);

    // destination already contains an output entry
    const taken = join(s.workDir, 'taken');
    mkdirSync(taken);
    writeFileSync(join(taken, 'escrow-decrypted.json'), '{}');
    r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir, taken]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/already contains/);

    const taken2 = join(s.workDir, 'taken2');
    mkdirSync(join(taken2, 'files-decrypted'), { recursive: true });
    r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir, taken2]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/already contains/);
  });

  it('fully fails with a wrong key, leaving the destination untouched', async () => {
    const s = await setup();
    const wrongKeyFile = join(s.workDir, 'wrong.json');
    writeFileSync(wrongKeyFile, JSON.stringify(ecEscrowKeys().secretKey));
    const destDir = join(s.workDir, 'restore');
    mkdirSync(destDir);
    const r = await runCli([`--escrow-secret-key-file=${wrongKeyFile}`, s.srcDir, destDir]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/no escrow secret key configured/);
    expect(readdirSync(destDir)).toEqual([]);
  });

  it('fully fails on a damaged file blob, leaving the destination untouched', async () => {
    const s = await setup(['a.bin', 'b.txt']);
    const manifest = JSON.parse(readFileSync(join(s.srcDir, 'escrow.json'), 'utf8'));
    const fileIds = Object.keys(manifest.file as Record<string, unknown>);
    const blob = join(s.srcDir, 'files', fileIds[fileIds.length - 1]!);
    const corrupt = readFileSync(blob);
    corrupt[corrupt.length - 1] ^= 0xff;
    writeFileSync(blob, corrupt);

    const destDir = join(s.workDir, 'restore');
    mkdirSync(destDir);
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir, destDir]);
    expect(r.code).not.toBe(0);
    // nothing placed, no staging residue
    expect(readdirSync(destDir)).toEqual([]);
  });

  it('fully fails when two files decrypt to the same name', async () => {
    const s = await setup(['same.bin', 'same.bin']);
    const destDir = join(s.workDir, 'restore');
    mkdirSync(destDir);
    const r = await runCli([`--escrow-secret-key-file=${s.keyFile}`, s.srcDir, destDir]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toMatch(/duplicate name/);
    expect(readdirSync(destDir)).toEqual([]);
  });

  it('accepts the key file via the environment and an array of keys', async () => {
    const s = await setup([]);
    const other = ecEscrowKeys().secretKey;
    const multiKeyFile = join(s.workDir, 'multi.json');
    const own = JSON.parse(readFileSync(s.keyFile, 'utf8')) as Jwk;
    writeFileSync(multiKeyFile, JSON.stringify([other, own]));
    const { stdout } = await execFileAsync(process.execPath, [CLI, s.srcDir], {
      env: { ...process.env, OPT_ESCROW_SECRET_KEY_FILE: multiKeyFile },
    });
    expect(stdout.trim()).toBe(s.escrowId);
  });
});
