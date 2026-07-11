import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const execFileP = promisify(execFile);
const ESCROW_CLI = join(__dirname, '..', 'dist', 'cli.js');
const DECRYPT_CLI = join(__dirname, '..', 'dist', 'decrypt-cli.js');
import { DataEscrow } from '../src/index';
import { DataEscrowDecrypt } from '../src/decrypt';
import { makeVaultDir, ecEscrowKeys, escrowDir, readManifest, type Manifest } from './helpers';
import { startStubVault, type StubVault } from './stub-vault';

let vault: StubVault;
beforeEach(async () => {
  vault = await startStubVault();
});
afterEach(async () => {
  await vault.close();
});

function kvConn(): { url: string; user: string; token: string; keepAlive: boolean } {
  return { url: vault.url, user: vault.user, token: vault.token, keepAlive: false };
}

describe('kvKey — writer + reader round-trip', () => {
  const cases = [
    { algorithm: 'ECDH-ES', crv: 'P-256' },
    { algorithm: 'ECDH-ES', crv: 'P-521' },
    { algorithm: 'RSA-OAEP', length: 2048 },
    { algorithm: 'RSA-OAEP-256', length: 2048 },
    { algorithm: 'ML-KEM-512@spinium.com' },
    { algorithm: 'ML-KEM-768@spinium.com' },
    { algorithm: 'ML-KEM-1024@spinium.com' },
  ] as const;
  for (const c of cases) {
    it(`round-trips a ${c.algorithm}${'crv' in c ? ' ' + c.crv : ''} kv key`, async () => {
      const vaultDir = makeVaultDir();
      const esc = new DataEscrow({
        vaultDir,
        kvKey: true,
        kvKeyAlgorithm: c.algorithm,
        ...('crv' in c ? { kvKeyCrv: c.crv } : {}),
        ...('length' in c ? { kvKeyLength: c.length } : {}),
        kv: kvConn(),
      });
      const content = randomBytes(512);
      const op = await esc.createEscrow({ reference: 'kv-rt', expiresAfter: 3600 });
      await op.addData({ v: 7 }, { reference: 'd1' });
      await op.addFileBuffer(content, { name: 'blob.bin' });
      const id = await op.commit();

      const dir = escrowDir(vaultDir, id);
      const m = readManifest(dir) as Manifest & { metadata: { kv?: { url?: string } } };
      // The manifest marks the escrow as kv-backed with the vault URL.
      expect(m.metadata.kv).toEqual({ url: vault.url });
      expect(m.metadata.kid).toMatch(/^[0-9a-f-]{36}$/);

      // Recover via the vault (a kv-only reader).
      const dec = new DataEscrowDecrypt({ kv: kvConn() });
      const opened = await dec.decrypt(m);
      const data = opened.data();
      expect(data.metadata.payloadData.id).toBe(id);
      expect(data.metadata.payloadContentKey).toBeUndefined(); // vault CEK not exposed
      expect(Object.values(data.data!).map((e) => e.payloadData.data)).toEqual([{ v: 7 }]);
      const [fileId] = Object.keys(data.file!);
      expect(await opened.decryptFileToBuffer(fileId!, join(dir, 'files', fileId!))).toEqual(content);
    });
  }

  it('forwards the escrow exp to the vault', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const op = await esc.createEscrow({ expiresAfter: 100 });
    await op.addData(1);
    await op.commit();
    const gen = vault.generateKeyCalls.at(-1)!;
    expect(gen.returnPublicKey).toBe(true);
    expect(typeof gen.exp).toBe('number');
    expect(gen.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it('one-shot escrow() works with kvKey and no escrow key', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const id = await esc.escrow({ hello: 'kv' }, { expiresAfter: 3600 });
    const dec = new DataEscrowDecrypt({ kv: kvConn() });
    const opened = await dec.decrypt(readManifest(escrowDir(vaultDir, id)));
    expect(Object.values(opened.data().data!).map((e) => e.payloadData.data)).toEqual([
      { hello: 'kv' },
    ]);
  });

  it('accepts an injected KeyVaultClient instance (writer and reader)', async () => {
    const vaultDir = makeVaultDir();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const KeyVaultClient = require('tr-key-vault-client');
    const client = new KeyVaultClient({ ...kvConn() });
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: client });
    const id = await esc.escrow('injected', { expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id)) as Manifest & {
      metadata: { kv?: { url?: string } };
    };
    // No URL is recorded for an injected client (the client owns its URL).
    expect(m.metadata.kv).toEqual({});
    const dec = new DataEscrowDecrypt({ kv: new KeyVaultClient({ ...kvConn() }) });
    expect(Object.values((await dec.decrypt(m)).data().data!).map((e) => e.payloadData.data)).toEqual(
      ['injected'],
    );
  });
});

describe('kvKey — option resolution & mutual exclusion', () => {
  it('constructor rejects both autoKey and kvKey true', () => {
    const vaultDir = makeVaultDir();
    expect(() => new DataEscrow({ vaultDir, autoKey: true, kvKey: true, kv: kvConn() })).toThrow(
      /cannot both be enabled/,
    );
  });

  it('a method with both effective on throws; { autoKey:false, kvKey:true } switches modes', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, autoKey: true, kv: kvConn() });
    // inheriting autoKey:true and turning kvKey on → both on → throws
    await expect(esc.createEscrow({ kvKey: true })).rejects.toThrow(/cannot both be enabled/);
    // the documented override: explicitly disable the inherited autoKey
    const id = await esc.escrow('switched', { autoKey: false, kvKey: true, expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id)) as Manifest & {
      metadata: { kv?: unknown };
    };
    expect(m.metadata.kv).toBeDefined();
  });

  it('forbids escrowKey together with kvKey', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    await expect(esc.createEscrow({ escrowKey: publicKey })).rejects.toThrow(
      /escrowKey and kvKey cannot both be set/,
    );
  });

  it('requires a kv connection when kvKey is on', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true }); // no kv
    await expect(esc.createEscrow()).rejects.toThrow(/requires a key-vault connection/);
    // supplied per operation instead
    const id = await esc.escrow('perop', { kv: kvConn(), expiresAfter: 3600 });
    expect(id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('rejects a kvKey escrow whose exp is not in the future', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    await expect(
      esc.createEscrow({ expiresAt: new Date(Date.now() - 1000) }),
    ).rejects.toThrow(/expiry must be in the future/);
  });

  it('validates kv option shape', () => {
    const vaultDir = makeVaultDir();
    expect(() => new DataEscrow({ vaultDir, kvKey: true, kv: { user: 'u' } as never })).toThrow(
      /kv.url/,
    );
    expect(() => new DataEscrow({ vaultDir, kvKey: true, kv: 'nope' as never })).toThrow(/kv must be/);
  });
});

describe('kvKey — orphan revoke on abandon / failure', () => {
  it('revokes the vault key when the operation is destroyed', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const op = await esc.createEscrow({ expiresAfter: 3600 });
    await op.addData(1);
    expect(vault.keyCount()).toBe(1);
    await op.destroy();
    expect(vault.revokeCalls).toHaveLength(1);
    expect(vault.keyCount()).toBe(0);
  });

  it('revokes the vault key when commit fails (empty escrow)', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const op = await esc.createEscrow({ expiresAfter: 3600 });
    await expect(op.commit()).rejects.toThrow(/empty/);
    expect(vault.revokeCalls).toHaveLength(1);
    expect(vault.keyCount()).toBe(0);
  });

  it('does not revoke after a successful commit', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const op = await esc.createEscrow({ expiresAfter: 3600 });
    await op.addData(1);
    await op.commit();
    await op.destroy(); // no-op after commit
    expect(vault.revokeCalls).toHaveLength(0);
    expect(vault.keyCount()).toBe(1);
  });
});

describe('kvKey — reader', () => {
  it('resolves the URL from the manifest when the reader supplies none', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const id = await esc.escrow('from-manifest-url', { expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id));
    // Reader configured with creds but no url: url comes from metadata.kv.url.
    const dec = new DataEscrowDecrypt({ kv: { user: vault.user, token: vault.token, keepAlive: false } });
    expect(Object.values((await dec.decrypt(m)).data().data!).map((e) => e.payloadData.data)).toEqual(
      ['from-manifest-url'],
    );
  });

  it('errors clearly on a kv escrow without a kv connection', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const id = await esc.escrow('x', { expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id));
    // A local-key reader has no kv config.
    const { publicKey, secretKey } = ecEscrowKeys();
    void publicKey;
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey });
    await expect(dec.decrypt(m)).rejects.toThrow(/key-vault-backed/);
  });

  it('accepts a per-decrypt() kv override', async () => {
    const vaultDir = makeVaultDir();
    const esc = new DataEscrow({ vaultDir, kvKey: true, kv: kvConn() });
    const id = await esc.escrow('override', { expiresAfter: 3600 });
    const m = readManifest(escrowDir(vaultDir, id));
    const { secretKey } = ecEscrowKeys();
    const dec = new DataEscrowDecrypt({ escrowSecretKey: secretKey }); // no ctor kv
    const opened = await dec.decrypt(m, { kv: kvConn() });
    expect(Object.values(opened.data().data!).map((e) => e.payloadData.data)).toEqual(['override']);
  });

  it('constructor requires escrowSecretKey or kv', () => {
    expect(() => new DataEscrowDecrypt({})).toThrow(/escrowSecretKey or kv/);
  });
});

describe('kvKey — dependency isolation', () => {
  it('a non-kv escrow never loads tr-key-vault-client; a kv escrow does', async () => {
    const script = (useKv: boolean): string => `
      const { DataEscrow } = require(${JSON.stringify(join(__dirname, '..', 'dist', 'index.js'))});
      const os = require('node:os'), fs = require('node:fs'), path = require('node:path');
      const crypto = require('node:crypto');
      (async () => {
        const vaultDir = fs.mkdtempSync(path.join(os.tmpdir(), 'depgraph-'));
        ${
          useKv
            ? `const esc = new DataEscrow({ vaultDir, kvKey: true, kv: ${JSON.stringify(kvConn())} });
               await esc.escrow('x', { expiresAfter: 3600 });`
            : `const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
               const pub = ec.publicKey.export({ format: 'jwk' }); pub.kid = 'k1';
               const esc = new DataEscrow({ vaultDir, escrowKey: pub });
               await esc.escrow('x');`
        }
        const loaded = Object.keys(require.cache).some((k) => k.includes('tr-key-vault-client'));
        process.stdout.write(loaded ? 'LOADED' : 'NOT-LOADED');
      })().catch((e) => { process.stderr.write(String(e && e.message || e)); process.exit(1); });
    `;
    const noKv = await execFileP('node', ['-e', script(false)], { encoding: 'utf8' });
    expect(noKv.stdout).toBe('NOT-LOADED');
    const withKv = await execFileP('node', ['-e', script(true)], { encoding: 'utf8' });
    expect(withKv.stdout).toBe('LOADED');
  });
});

describe('kvKey — CLIs', () => {
  it('escrow --kv-key round-trips through decrypt-escrow --kv-*', async () => {
    const vaultDir = makeVaultDir();
    const gen = await execFileP(
      'node',
      [
        ESCROW_CLI,
        `--vault-directory=${vaultDir}`,
        '--kv-key',
        `--kv-url=${vault.url}`,
        `--kv-user=${vault.user}`,
        `--kv-token=${vault.token}`,
        '--expires-after=1h',
        '--data={"cli":true}',
      ],
      { encoding: 'utf8' },
    );
    const id = gen.stdout.trim();
    const dir = escrowDir(vaultDir, id);
    const m = readManifest(dir) as Manifest & { metadata: { kv?: { url?: string } } };
    expect(m.metadata.kv).toEqual({ url: vault.url });

    // decrypt with creds only; the URL comes from the manifest.
    const dec = await execFileP(
      'node',
      [DECRYPT_CLI, `--kv-user=${vault.user}`, `--kv-token=${vault.token}`, dir],
      { encoding: 'utf8' },
    );
    expect(dec.stdout.trim()).toBe(id);
    const decrypted = JSON.parse(readFileSync(join(dir, 'escrow-decrypted.json'), 'utf8')) as {
      data: Record<string, { payloadData: { data: unknown } }>;
    };
    expect(Object.values(decrypted.data).map((e) => e.payloadData.data)).toEqual([{ cli: true }]);
  });

  it('escrow warns and ignores --escrow-key-file under --kv-key', async () => {
    const vaultDir = makeVaultDir();
    const { publicKey } = ecEscrowKeys();
    const keyFile = join(vaultDir, 'escrow-key.json');
    writeFileSyncJson(keyFile, publicKey);
    const gen = await execFileP(
      'node',
      [
        ESCROW_CLI,
        `--vault-directory=${vaultDir}`,
        '--kv-key',
        `--escrow-key-file=${keyFile}`,
        `--kv-url=${vault.url}`,
        `--kv-user=${vault.user}`,
        `--kv-token=${vault.token}`,
        '--expires-after=1h',
        '--data=1',
      ],
      { encoding: 'utf8' },
    );
    expect(gen.stderr).toContain('--escrow-key-file is ignored');
    const dir = escrowDir(vaultDir, gen.stdout.trim());
    const m = readManifest(dir) as Manifest & { metadata: { kv?: unknown } };
    expect(m.metadata.kv).toBeDefined(); // metadata went to the vault key, not the escrow key
  });
});

function writeFileSyncJson(path: string, obj: unknown): void {
  // local import to keep the top imports minimal
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  (require('node:fs') as typeof import('node:fs')).writeFileSync(path, JSON.stringify(obj));
}
