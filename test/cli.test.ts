import { describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  makeVaultDir,
  ecEscrowKeys,
  escrowDir,
  readManifest,
  openEscrow,
  readVaultFileHeader,
} from './helpers';

const execFileAsync = promisify(execFile);
const CLI = resolve(__dirname, '..', 'dist', 'cli.js');
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

async function runCli(args: string[], env: Record<string, string> = {}): Promise<CliResult> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
    });
    return { code: 0, stdout, stderr };
  } catch (err) {
    const e = err as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

function makeKeyFile(vaultDir: string): { keyFile: string; secretKey: ReturnType<typeof ecEscrowKeys>['secretKey'] } {
  const { publicKey, secretKey } = ecEscrowKeys();
  const keyFile = join(vaultDir, 'escrow-key.json');
  writeFileSync(keyFile, JSON.stringify(publicKey));
  return { keyFile, secretKey };
}

describe('escrow CLI', () => {
  it('escrows data and files, printing the escrow id', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile, secretKey } = makeKeyFile(vaultDir);
    const content = randomBytes(512);
    const srcFile = join(vaultDir, 'fishy-file');
    writeFileSync(srcFile, content);

    const r = await runCli([
      `--escrow-key-file=${keyFile}`,
      `--vault-directory=${vaultDir}`,
      '--reference=Secret data',
      '--encrypted-reference=Very Secret Info',
      '--expires-after=30d',
      '--data={ "something": "fishy" }',
      '--data=[1, 2, 3]',
      `--file=${srcFile}`,
    ]);
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    const id = r.stdout.trim();
    expect(id).toMatch(UUID_RE);

    const dir = escrowDir(vaultDir, id);
    const m = readManifest(dir);
    expect(m.metadata.ref).toBe('Secret data');
    expect(m.metadata.exp).toBe(m.metadata.iat + 30 * 86400);

    const opened = openEscrow(dir, secretKey);
    expect(opened.metadata.cref).toBe('Very Secret Info');
    expect(opened.data.map((d) => d.data)).toEqual(
      expect.arrayContaining([{ something: 'fishy' }, [1, 2, 3]]),
    );
    expect(opened.files).toHaveLength(1);
    expect(opened.files[0]?.name).toBe('fishy-file');
    expect(opened.files[0]?.bytes).toEqual(content);
  });

  it('accepts mandatory options from the environment', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile, secretKey } = makeKeyFile(vaultDir);

    const r = await runCli(['--data=true'], {
      OPT_ESCROW_KEY_FILE: keyFile,
      OPT_VAULT_DIRECTORY: vaultDir,
    });
    expect(r.stderr).toBe('');
    expect(r.code).toBe(0);
    const id = r.stdout.trim();
    expect(openEscrow(escrowDir(vaultDir, id), secretKey).data.map((d) => d.data)).toEqual([true]);
  });

  it('stores an absolute --expires-at', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile } = makeKeyFile(vaultDir);
    const at = '2030-12-31 23:59:59';
    const r = await runCli([
      `--escrow-key-file=${keyFile}`,
      `--vault-directory=${vaultDir}`,
      `--expires-at=${at}`,
      '--data=1',
    ]);
    expect(r.code).toBe(0);
    const m = readManifest(escrowDir(vaultDir, r.stdout.trim()));
    expect(m.metadata.exp).toBe(Math.floor(new Date(at).getTime() / 1000));
  });

  it('fails without any --data or --file', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile } = makeKeyFile(vaultDir);
    const r = await runCli([`--escrow-key-file=${keyFile}`, `--vault-directory=${vaultDir}`]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('nothing to escrow');
  });

  it('fails when mandatory options are missing', async () => {
    const r = await runCli(['--data=1']);
    expect(r.code).not.toBe(0);
  });

  it('rejects conflicting expiry options', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile } = makeKeyFile(vaultDir);
    const r = await runCli([
      `--escrow-key-file=${keyFile}`,
      `--vault-directory=${vaultDir}`,
      '--expires-at=2030-01-01T00:00:00Z',
      '--expires-after=3600',
      '--data=1',
    ]);
    expect(r.code).not.toBe(0);
  });

  it('rejects invalid JSON in --data, bad durations, and missing files', async () => {
    const vaultDir = makeVaultDir();
    const { keyFile } = makeKeyFile(vaultDir);
    const base = [`--escrow-key-file=${keyFile}`, `--vault-directory=${vaultDir}`];

    expect((await runCli([...base, '--data={broken']))).toMatchObject({ code: expect.any(Number) });
    expect((await runCli([...base, '--data={broken'])).code).not.toBe(0);
    expect((await runCli([...base, '--data=1', '--expires-after=5x'])).code).not.toBe(0);
    expect((await runCli([...base, '--file=/no/such/file'])).code).not.toBe(0);
  });

  it('reports a clear error for an unusable escrow key', async () => {
    const vaultDir = makeVaultDir();
    const badKeyFile = join(vaultDir, 'bad-key.json');
    writeFileSync(badKeyFile, '{ "kty": "oct", "k": "AAAA", "kid": "nope" }');
    const r = await runCli([
      `--escrow-key-file=${badKeyFile}`,
      `--vault-directory=${vaultDir}`,
      '--data=1',
    ]);
    expect(r.code).not.toBe(0);
    expect(r.stderr).toContain('escrowKey');
  });

  describe('compression', () => {
    const compressible = 'abcdefgh'.repeat(4096);

    it('applies a global --compression to files and round-trips', async () => {
      const vaultDir = makeVaultDir();
      const { keyFile, secretKey } = makeKeyFile(vaultDir);
      const srcFile = join(vaultDir, 'big.dat');
      writeFileSync(srcFile, compressible);

      const r = await runCli([
        `--escrow-key-file=${keyFile}`,
        `--vault-directory=${vaultDir}`,
        '--compression=gzip',
        `--file=${srcFile}`,
      ]);
      expect(r.stderr).toBe('');
      expect(r.code).toBe(0);
      const id = r.stdout.trim();
      const dir = escrowDir(vaultDir, id);
      const fileId = Object.keys(readManifest(dir).file ?? {})[0] as string;
      expect(readVaultFileHeader(join(dir, 'files', fileId)).comp).toBe(2);
      const opened = openEscrow(dir, secretKey);
      expect(opened.files[0]?.bytes.toString()).toBe(compressible);
    });

    it('lets a --file JSON object override compression, name, and references', async () => {
      const vaultDir = makeVaultDir();
      const { keyFile, secretKey } = makeKeyFile(vaultDir);
      const plainFile = join(vaultDir, 'plain.dat');
      const overrideFile = join(vaultDir, 'override.dat');
      writeFileSync(plainFile, compressible);
      writeFileSync(overrideFile, compressible);

      const spec = JSON.stringify({
        filename: overrideFile,
        name: 'renamed.dat',
        reference: 'File1',
        encryptedReference: 'sealed-file',
        compression: 'none',
      });
      const r = await runCli([
        `--escrow-key-file=${keyFile}`,
        `--vault-directory=${vaultDir}`,
        '--compression=brotli',
        `--file=${plainFile}`,
        `--file=${spec}`,
      ]);
      expect(r.stderr).toBe('');
      expect(r.code).toBe(0);
      const dir = escrowDir(vaultDir, r.stdout.trim());
      const m = readManifest(dir);
      const opened = openEscrow(dir, secretKey);
      const byName = new Map(opened.files.map((f) => [f.name, f]));

      const plain = byName.get('plain.dat');
      const renamed = byName.get('renamed.dat');
      expect(plain).toBeDefined();
      expect(renamed).toBeDefined();
      expect(readVaultFileHeader(join(dir, 'files', plain!.id)).comp).toBe(3); // global brotli
      expect(readVaultFileHeader(join(dir, 'files', renamed!.id)).comp).toBe(0); // per-file none
      expect(m.file?.[renamed!.id]?.ref).toBe('File1');
      expect(renamed!.claims.cref).toBe('sealed-file');
      expect(renamed!.bytes.toString()).toBe(compressible);
    });

    it('rejects the reserved zstd and unknown compression names', async () => {
      const vaultDir = makeVaultDir();
      const { keyFile } = makeKeyFile(vaultDir);
      const base = [`--escrow-key-file=${keyFile}`, `--vault-directory=${vaultDir}`, '--data=1'];
      const zstd = await runCli([...base, '--compression=zstd']);
      expect(zstd.code).not.toBe(0);
      expect(zstd.stderr).toContain('reserved');
      expect((await runCli([...base, '--compression=lzma'])).code).not.toBe(0);
    });

    it('rejects malformed --file JSON objects', async () => {
      const vaultDir = makeVaultDir();
      const { keyFile } = makeKeyFile(vaultDir);
      const base = [`--escrow-key-file=${keyFile}`, `--vault-directory=${vaultDir}`];
      // missing filename
      expect((await runCli([...base, '--file={"name":"x"}'])).code).not.toBe(0);
      // unknown key
      const src = join(vaultDir, 'f.dat');
      writeFileSync(src, 'x');
      expect(
        (await runCli([...base, `--file={"filename":${JSON.stringify(src)},"bogus":1}`])).code,
      ).not.toBe(0);
      // nonexistent file inside the object
      expect((await runCli([...base, '--file={"filename":"/no/such/file"}'])).code).not.toBe(0);
    });
  });
});
