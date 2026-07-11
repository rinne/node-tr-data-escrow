import { createDecipheriv } from 'node:crypto';
import { brotliDecompressSync, gunzipSync, inflateSync } from 'node:zlib';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { decrypt } from 'tr-jwe';
import { ecKeyGen, macKeyGen, mlKemKeyGen, type Jwk } from 'tr-jwk';

/** A fresh, isolated vault directory for a test. */
export function makeVaultDir(): string {
  return mkdtempSync(join(tmpdir(), 'tr-escrow-vault-'));
}

/** An EC (ECDH-ES) escrow key pair for tests. */
export function ecEscrowKeys(curve = 'P-256'): { publicKey: Jwk; secretKey: Jwk } {
  return ecKeyGen(curve);
}

/** An RSA-OAEP escrow key pair derived from an RSA signing key (RS384 = 2048-bit). */
export function rsaEscrowKeys(alg = 'RS384'): { publicKey: Jwk; secretKey: Jwk } {
  const secretKey = macKeyGen(alg);
  const publicKey: Jwk = {
    kty: 'RSA',
    n: secretKey.n as string,
    e: secretKey.e as string,
    alg: 'RSA-OAEP',
    kid: secretKey.kid as string,
  };
  return { publicKey, secretKey };
}

/** An ML-KEM (AKP) escrow key pair for tests; JWK alg is the unsuffixed variant. */
export function mlKemEscrowKeys(variant = 'ML-KEM-768'): { publicKey: Jwk; secretKey: Jwk } {
  return mlKemKeyGen(variant);
}

/** The committed location of an escrow inside a vault. */
export function escrowDir(vaultDir: string, escrowId: string): string {
  return join(vaultDir, escrowId.slice(0, 4), escrowId);
}

/** Parsed escrow.json shape (as far as the tests need it). */
export interface Manifest {
  metadata: {
    id: string;
    kid: string;
    iat: number;
    exp?: number;
    ref?: string;
    payload: string;
  };
  data?: Record<string, { ref?: string; payload: string }>;
  file?: Record<string, { ref?: string; payload: string }>;
}

export function readManifest(dir: string): Manifest {
  return JSON.parse(readFileSync(join(dir, 'escrow.json'), 'utf8')) as Manifest;
}

/** Container header fields of one TRDE vault file. */
export function readVaultFileHeader(path: string): { version: number; enc: number; comp: number } {
  const buf = readFileSync(path);
  if (buf.subarray(0, 4).toString('ascii') !== 'TRDE') {
    throw new Error('vault file: bad magic');
  }
  return { version: buf[4] as number, enc: buf[5] as number, comp: buf[6] as number };
}

/**
 * Decrypts (and decompresses) one TRDE vault-file container using its per-file
 * A256GCM key JWK. Header: magic(4) version(1) enc(1) comp(1) ivlen(1) iv.
 */
export function readVaultFile(path: string, fileKeyJwk: { k: string }): Buffer {
  const buf = readFileSync(path);
  if (buf.subarray(0, 4).toString('ascii') !== 'TRDE') {
    throw new Error('vault file: bad magic');
  }
  const comp = buf[6] as number;
  const ivLen = buf[7] as number;
  const headerLen = 8 + ivLen;
  const iv = buf.subarray(8, headerLen);
  const header = buf.subarray(0, headerLen);
  const tag = buf.subarray(buf.length - 16);
  const ciphertext = buf.subarray(headerLen, buf.length - 16);
  const key = Buffer.from(fileKeyJwk.k, 'base64url');
  const d = createDecipheriv('aes-256-gcm', key, iv);
  d.setAAD(header);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(ciphertext), d.final()]);
  switch (comp) {
    case 0:
      return plain;
    case 1:
      return inflateSync(plain);
    case 2:
      return gunzipSync(plain);
    case 3:
      return brotliDecompressSync(plain);
    default:
      throw new Error(`vault file: unsupported compression code ${comp}`);
  }
}

export interface OpenedMetadata {
  id: string;
  kid: string;
  iat: number;
  exp?: number;
  ref?: string;
  cref?: string;
}

export interface OpenedItem {
  id: string;
  manifestRef?: string;
  claims: { iat: number; id: string; ref?: string; cref?: string };
}

export interface OpenedData extends OpenedItem {
  data: unknown;
}

export interface OpenedFile extends OpenedItem {
  name: string;
  bytes: Buffer;
}

export interface OpenedEscrow {
  metadata: OpenedMetadata;
  data: OpenedData[];
  files: OpenedFile[];
}

/**
 * Acts as the (future, out-of-scope) escrow reader: opens a committed escrow
 * directory with the escrow private key. Unwraps the wrapping key from the
 * metadata payload, decrypts every data/file payload, and decrypts each
 * physical blob in `files/`.
 */
export function openEscrow(dir: string, secretKey: Jwk): OpenedEscrow {
  const m = readManifest(dir);
  const meta = decrypt(m.metadata.payload, secretKey) as OpenedMetadata & {
    key: Record<string, unknown>;
  };
  const wrappingKey = meta.key;

  const data: OpenedData[] = Object.entries(m.data ?? {}).map(([id, e]) => {
    const claims = decrypt(e.payload, wrappingKey) as OpenedData['claims'] & { data: unknown };
    return { id, manifestRef: e.ref, claims, data: claims.data };
  });

  const files: OpenedFile[] = Object.entries(m.file ?? {}).map(([id, e]) => {
    const claims = decrypt(e.payload, wrappingKey) as OpenedFile['claims'] & {
      name: string;
      key: { k: string };
    };
    const bytes = readVaultFile(join(dir, 'files', id), claims.key);
    return { id, manifestRef: e.ref, claims, name: claims.name, bytes };
  });

  const { key: _key, ...metadata } = meta;
  return { metadata, data, files };
}
