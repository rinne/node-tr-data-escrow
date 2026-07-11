/**
 * A stub tr-key-vault server for the tests: a tiny in-process HTTP server that
 * speaks the `/api/v1` envelope with *real* keys, so the escrow metadata JWE is
 * genuinely encryptable to the returned public key and genuinely decryptable by
 * the stub. It records calls for assertions.
 */
import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { decrypt as jweDecrypt } from 'tr-jwe';
import { ecKeyPairGen, rsaKeyPairGen, mlKemKeyPairGen, mlKemVariantOfJweAlg } from '../src/key-gen';

export const KV_USER = '31b27ab4-a826-4f83-b383-3893bff8a1a6';
export const KV_TOKEN = '3aa577dc-e8f4-4d70-9258-842a6d1af26d';

export interface StubVault {
  url: string;
  user: string;
  token: string;
  keyCount(): number;
  generateKeyCalls: Array<Record<string, unknown>>;
  decryptJweCalls: Array<Record<string, unknown>>;
  revokeCalls: string[];
  close(): Promise<void>;
}

export async function startStubVault(): Promise<StubVault> {
  const keys = new Map<string, { secret: Record<string, unknown>; exp?: number }>();
  const generateKeyCalls: Array<Record<string, unknown>> = [];
  const decryptJweCalls: Array<Record<string, unknown>> = [];
  const revokeCalls: string[] = [];

  function send(res: ServerResponse, obj: unknown): void {
    const body = Buffer.from(JSON.stringify(obj), 'utf8');
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length });
    res.end(body);
  }

  async function handleApi(req: IncomingMessage, res: ServerResponse, raw: string): Promise<void> {
    let env: Record<string, unknown>;
    try {
      env = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return send(res, { status: 'error', errorCode: 1000, message: 'Malformed request' });
    }
    const op = env.op as string;
    const auth = /^Bearer (.*)$/.exec(req.headers['authorization'] ?? '');
    if (!(auth && auth[1] === KV_TOKEN && env.user === KV_USER)) {
      return send(res, { status: 'error', op, errorCode: 1001, message: 'Unauthorized' });
    }
    const data = (env.data ?? {}) as Record<string, unknown>;
    const ok = (d: unknown): void => send(res, { status: 'ok', op, data: d });
    const err = (code: number, message: string): void =>
      send(res, { status: 'error', op, errorCode: code, message });

    switch (env.request) {
      case 'healthcheck':
        return ok({ uptime: 1 });
      case 'generate-key': {
        generateKeyCalls.push(data);
        const alg = data.alg as string;
        let secret: Record<string, unknown>;
        let publicJwk: Record<string, unknown>;
        if (alg === 'ECDH-ES') {
          const pair = await ecKeyPairGen(
            (data.crv as 'P-256' | 'P-384' | 'P-521' | undefined) ?? 'P-521',
          );
          secret = pair.secretKey;
          publicJwk = pair.publicKey;
        } else if (alg === 'RSA-OAEP' || alg === 'RSA-OAEP-256') {
          const pair = await rsaKeyPairGen((data.keyLength as number | undefined) ?? 4096);
          secret = { ...pair.secretKey, alg };
          publicJwk = { ...pair.publicKey, alg };
        } else if (mlKemVariantOfJweAlg(alg) !== null) {
          // Real-vault rule: crv/keyLength are rejected for ML-KEM, and the
          // AKP JWKs keep the unsuffixed variant in their alg member.
          if (data.crv !== undefined || data.keyLength !== undefined) {
            return err(1100, 'crv/keyLength not applicable to ML-KEM');
          }
          const pair = await mlKemKeyPairGen(mlKemVariantOfJweAlg(alg)!);
          secret = pair.secretKey;
          publicJwk = pair.publicKey;
        } else {
          return err(1100, `unsupported alg ${String(alg)}`);
        }
        const kid = secret.kid as string;
        keys.set(kid, { secret, exp: data.exp as number | undefined });
        const rv: Record<string, unknown> = { kid };
        if (data.returnPublicKey === true) rv.key = publicJwk;
        return ok(rv);
      }
      case 'decrypt-jwe': {
        decryptJweCalls.push(data);
        const entry = keys.get(data.kid as string);
        if (entry === undefined) return err(1101, 'Key not found');
        let claims: unknown;
        try {
          claims = jweDecrypt(data.token as string, entry.secret);
        } catch {
          return err(1103, 'Invalid input token');
        }
        return ok({ header: {}, data: claims });
      }
      case 'revoke-key': {
        const kid = data.kid as string;
        revokeCalls.push(kid);
        if (!keys.has(kid)) return err(1101, 'Key not found');
        keys.delete(kid);
        return ok({ kid, revoked: true });
      }
      default:
        return err(1002, 'Unknown operation');
    }
  }

  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (req.method === 'GET' && url.pathname === '/healthz') return send(res, { status: 'ok' });
    if (req.method === 'GET' && url.pathname === '/readyz') return send(res, { status: 'ok' });
    if (req.method === 'POST' && url.pathname === '/api/v1') {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        void handleApi(req, res, Buffer.concat(chunks).toString('utf8'));
      });
      return;
    }
    send(res, { status: 'error', errorCode: 1004, message: 'Unknown endpoint' });
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;

  return {
    url: `http://127.0.0.1:${port}/`,
    user: KV_USER,
    token: KV_TOKEN,
    keyCount: () => keys.size,
    generateKeyCalls,
    decryptJweCalls,
    revokeCalls,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
