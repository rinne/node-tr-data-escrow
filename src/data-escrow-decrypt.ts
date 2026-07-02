import { decrypt as jweDecrypt, unwrap as jweUnwrap } from 'tr-jwe';
import {
  EscrowIntegrityError,
  UnknownEscrowKeyError,
} from './decrypt-errors';
import {
  DataEscrowDecryptOperation,
  type DecryptedItem,
  type DecryptedManifest,
} from './data-escrow-decrypt-operation';

/** Construction options for {@link DataEscrowDecrypt}. */
export interface DataEscrowDecryptOptions {
  /**
   * One escrow **secret** JWK or a non-empty array of them, each with a
   * unique non-empty `kid` (escrows select their key by kid). Accepted forms
   * mirror the writer's public-key rules plus the private member:
   *   - RSA: `{ kty:'RSA', kid, n, e, d, ... }`, modulus >= 2048 bits,
   *     `alg` (when present) must be `"RSA-OAEP"`
   *   - EC:  `{ kty:'EC', crv:'P-256'|'P-384'|'P-521', kid, x, y, d }`
   */
  escrowSecretKey: Record<string, unknown> | Record<string, unknown>[];
}

const EC_CURVES = ['P-256', 'P-384', 'P-521'];

/** Validates one escrow secret key; returns its kid and a private deep copy. */
function validateEscrowSecretKey(key: unknown): { kid: string; jwk: Record<string, unknown> } {
  if (!key || typeof key !== 'object' || Array.isArray(key)) {
    throw new TypeError('escrowSecretKey must be a JWK object');
  }
  const k = key as Record<string, unknown>;
  if (typeof k.kid !== 'string' || k.kid.length === 0) {
    throw new TypeError('escrowSecretKey.kid must be a non-empty string');
  }
  if (typeof k.d !== 'string' || k.d.length === 0) {
    throw new TypeError('escrowSecretKey must be a private key (missing "d")');
  }
  if (k.kty === 'RSA') {
    if (k.alg !== undefined && k.alg !== 'RSA-OAEP') {
      throw new TypeError('RSA escrowSecretKey alg, when present, must be "RSA-OAEP"');
    }
    if (typeof k.n !== 'string' || typeof k.e !== 'string') {
      throw new TypeError('RSA escrowSecretKey must have string "n" and "e"');
    }
    const modulusBits = Buffer.from(k.n, 'base64url').length * 8;
    if (modulusBits < 2048) {
      throw new TypeError(
        `RSA escrowSecretKey modulus too small (${modulusBits} bits; need >= 2048)`,
      );
    }
  } else if (k.kty === 'EC') {
    if (typeof k.crv !== 'string' || !EC_CURVES.includes(k.crv)) {
      throw new TypeError('EC escrowSecretKey crv must be one of P-256, P-384, P-521');
    }
    if (typeof k.x !== 'string' || typeof k.y !== 'string') {
      throw new TypeError('EC escrowSecretKey must have string "x" and "y"');
    }
  } else {
    throw new TypeError('escrowSecretKey.kty must be "RSA" or "EC"');
  }
  return { kid: k.kid, jwk: structuredClone(k) };
}

/** `decrypt`'s options are reserved: an object with no (known) keys yet. */
function validateDecryptOptions(options: unknown): void {
  if (options === undefined) return;
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('decrypt options must be an object');
  }
  const keys = Object.keys(options);
  if (keys.length > 0) {
    throw new TypeError(`unknown decrypt option(s): ${keys.join(', ')}`);
  }
}

interface ManifestEntryShape {
  ref?: string;
  payload: string;
}

interface ManifestShape {
  metadata: {
    id?: unknown;
    kid: string;
    iat?: unknown;
    exp?: unknown;
    ref?: unknown;
    payload: string;
  };
  data?: Record<string, ManifestEntryShape>;
  file?: Record<string, ManifestEntryShape>;
}

/** Rough manifest-shape validation (step 1 of `decrypt`); throws `TypeError`. */
function validateManifestShape(escrow: unknown): ManifestShape {
  if (!escrow || typeof escrow !== 'object' || Array.isArray(escrow)) {
    throw new TypeError('escrow must be the object parsed from escrow.json');
  }
  const e = escrow as Record<string, unknown>;
  if (!e.metadata || typeof e.metadata !== 'object' || Array.isArray(e.metadata)) {
    throw new TypeError('escrow.metadata must be an object');
  }
  const m = e.metadata as Record<string, unknown>;
  if (typeof m.kid !== 'string' || m.kid.length === 0) {
    throw new TypeError('escrow.metadata.kid must be a non-empty string');
  }
  if (typeof m.payload !== 'string' || m.payload.length === 0) {
    throw new TypeError('escrow.metadata.payload must be a non-empty string');
  }
  for (const section of ['data', 'file'] as const) {
    const map = e[section];
    if (map === undefined) continue;
    if (!map || typeof map !== 'object' || Array.isArray(map)) {
      throw new TypeError(`escrow.${section} must be an object map`);
    }
    for (const [id, entry] of Object.entries(map)) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        throw new TypeError(`escrow.${section}[${JSON.stringify(id)}] must be an object`);
      }
      const en = entry as Record<string, unknown>;
      if (typeof en.payload !== 'string' || en.payload.length === 0) {
        throw new TypeError(
          `escrow.${section}[${JSON.stringify(id)}].payload must be a non-empty string`,
        );
      }
      if (en.ref !== undefined && (typeof en.ref !== 'string' || en.ref.length === 0)) {
        throw new TypeError(
          `escrow.${section}[${JSON.stringify(id)}].ref must be a non-empty string when present`,
        );
      }
    }
  }
  return e as unknown as ManifestShape;
}

function formatBindingValue(value: unknown): string {
  return value === undefined ? 'absent' : JSON.stringify(value);
}

/** One sealed-vs-cleartext field comparison; absence must match too. */
function verifyBinding(field: string, sealed: unknown, clear: unknown): void {
  if (sealed !== clear) {
    throw new EscrowIntegrityError(
      field,
      `sealed ${formatBindingValue(sealed)} vs manifest ${formatBindingValue(clear)}`,
    );
  }
}

/**
 * Decrypts escrows produced by `DataEscrow` using the escrow **secret** keys.
 * Holds only the configured secret keys; `decrypt()` opens one manifest object
 * and returns a {@link DataEscrowDecryptOperation} for everything further.
 * Lives behind the `tr-data-escrow/decrypt` subpath — the writer entry point
 * never loads this code.
 */
export class DataEscrowDecrypt {
  /** Secret keys indexed by kid; null once destroyed. */
  #keys: Map<string, Record<string, unknown>> | null;

  /**
   * @param options see {@link DataEscrowDecryptOptions}. Synchronous, no I/O;
   *                throws `TypeError` on invalid configuration.
   */
  constructor(options: DataEscrowDecryptOptions) {
    if (!options || typeof options !== 'object') {
      throw new TypeError('options object with escrowSecretKey is required');
    }
    const raw = options.escrowSecretKey;
    const list = Array.isArray(raw) ? raw : [raw];
    if (list.length === 0) {
      throw new TypeError('escrowSecretKey array must not be empty');
    }
    const keys = new Map<string, Record<string, unknown>>();
    for (const key of list) {
      const { kid, jwk } = validateEscrowSecretKey(key);
      if (keys.has(kid)) {
        throw new TypeError(`duplicate escrowSecretKey kid ${JSON.stringify(kid)}`);
      }
      keys.set(kid, jwk);
    }
    this.#keys = keys;
  }

  /**
   * Opens one escrow manifest (the object JSON-parsed from `escrow.json`;
   * this method performs no filesystem I/O). Selects the secret key by
   * `metadata.kid`, decrypts every payload, verifies the sealed/cleartext
   * binding of all duplicated fields, and returns a
   * {@link DataEscrowDecryptOperation} over an augmented deep copy — the
   * input object is never mutated. `options` is reserved for future use;
   * unknown keys are rejected. The advisory `exp` is **not** enforced.
   *
   * Throws {@link UnknownEscrowKeyError} when no configured key matches,
   * {@link EscrowIntegrityError} on a binding mismatch, `TypeError` on an
   * invalid manifest shape, and propagates token decryption failures
   * (wrapped with context).
   */
  async decrypt(
    escrowObject: unknown,
    options?: Record<string, never>,
  ): Promise<DataEscrowDecryptOperation> {
    if (this.#keys === null) {
      throw new TypeError('DataEscrowDecrypt instance is destroyed');
    }
    validateDecryptOptions(options);
    const shape = validateManifestShape(escrowObject);
    const secretKey = this.#keys.get(shape.metadata.kid);
    if (secretKey === undefined) {
      throw new UnknownEscrowKeyError(shape.metadata.kid);
    }

    const original = structuredClone(escrowObject) as Record<string, unknown>;
    const augmented = structuredClone(escrowObject) as unknown as DecryptedManifest;

    let metaClaims: Record<string, unknown>;
    let metaCek: Record<string, unknown>;
    try {
      metaClaims = asClaimsObject(jweDecrypt(shape.metadata.payload, secretKey));
      metaCek = jweUnwrap(shape.metadata.payload, secretKey);
    } catch (err) {
      throw new Error('failed to decrypt escrow metadata payload', { cause: err });
    }
    augmented.metadata.payloadData = metaClaims;
    augmented.metadata.payloadContentKey = metaCek;

    // Sealed metadata claims must match their cleartext duplicates, absence
    // included (the sealed cref has no cleartext counterpart by design).
    verifyBinding('metadata.id', metaClaims.id, shape.metadata.id);
    verifyBinding('metadata.kid', metaClaims.kid, shape.metadata.kid);
    verifyBinding('metadata.iat', metaClaims.iat, shape.metadata.iat);
    verifyBinding('metadata.exp', metaClaims.exp, shape.metadata.exp);
    verifyBinding('metadata.ref', metaClaims.ref, shape.metadata.ref);

    const wrappingKey = metaClaims.key;
    if (!wrappingKey || typeof wrappingKey !== 'object') {
      throw new EscrowIntegrityError('metadata.payloadData.key', 'wrapping key missing');
    }

    const fileKeys = new Map<string, Record<string, unknown>>();
    for (const section of ['data', 'file'] as const) {
      const map = augmented[section];
      if (map === undefined) continue;
      for (const [id, entry] of Object.entries(map) as [string, DecryptedItem][]) {
        let claims: Record<string, unknown>;
        let cek: Record<string, unknown>;
        try {
          claims = asClaimsObject(jweDecrypt(entry.payload, wrappingKey as Record<string, unknown>));
          cek = jweUnwrap(entry.payload, wrappingKey as Record<string, unknown>);
        } catch (err) {
          throw new Error(`failed to decrypt ${section} payload ${JSON.stringify(id)}`, {
            cause: err,
          });
        }
        entry.payloadData = claims;
        entry.payloadContentKey = cek;
        verifyBinding(`${section}.${id}.id`, claims.id, id);
        verifyBinding(`${section}.${id}.ref`, claims.ref, entry.ref);
        if (section === 'file') {
          const contentKey = claims.key;
          if (!contentKey || typeof contentKey !== 'object') {
            throw new EscrowIntegrityError(`file.${id}.payloadData.key`, 'content key missing');
          }
          fileKeys.set(id, structuredClone(contentKey) as Record<string, unknown>);
        }
      }
    }

    return new DataEscrowDecryptOperation(original, augmented, fileKeys);
  }

  /**
   * Clears the internal references to the configured escrow secret keys and
   * invalidates the object: `decrypt()` throws afterwards. Operations already
   * returned are unaffected — they hold their own key material. Synchronous,
   * idempotent.
   */
  destroy(): void {
    this.#keys?.clear();
    this.#keys = null;
  }
}

function asClaimsObject(claims: unknown): Record<string, unknown> {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new Error('payload claims are not an object');
  }
  return claims as Record<string, unknown>;
}
