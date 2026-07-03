# JWE Key Embedding

A convention for embedding a cryptographic key into a JWE.

## 1. Abstract

This document specifies a minimal convention for transporting a JSON Web
Key (JWK, [RFC 7517]) inside the encrypted payload of a JSON Web Encryption
object (JWE, [RFC 7516]), together with an optional cleartext header
property that MAY describe the embedded key without decrypting the token.

The convention is deliberately simple: the encrypted payload is a JSON
claims object whose only mandatory claim is `key`, and the JWE protected
header MAY carry an `embedded_key_info` object whose members are all
optional.

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT",
"MAY", and "OPTIONAL" in this document are to be interpreted as described
in [RFC 2119].

"Producer" is the party creating the JWE; "consumer" is the party
decrypting and processing it. Timestamps follow the JWT NumericDate
convention ([RFC 7519], Section 2): integer seconds since the unix epoch.

## 3. The encrypted payload

The JWE plaintext MUST be a JSON object (a claims object in the JWT
sense).

### 3.1. The `key` claim

- The claims object MUST contain the claim **`key`**.
- The value of `key` MUST be a JWK object ([RFC 7517]) representing the
  embedded key.
- The key object SHOULD have a **`kid`** property. An application profile
  of this convention MAY make `kid` REQUIRED.

### 3.2. Other claims

All other claims inside the encrypted payload are OPTIONAL. Applications
MAY include any additional claims (for example `iat`, `exp`, `nbf`,
`kid`, or application-specific claims) following ordinary JWT claim
conventions. This document assigns no processing rules to them; their
semantics and enforcement are application policy.

## 4. The header: `embedded_key_info`

The JWE header MAY include the property **`embedded_key_info`**. When
present, its value MUST be a JSON object with the following properties,
each of which is OPTIONAL:

```jsonc
{
  "iat": 1783007751,     // issued-at, JWT NumericDate convention
  "exp": 1787007751,     // expires, JWT NumericDate convention
  "nbf": 1783007751,     // not-before, JWT NumericDate convention
  "kid": "key-2026",     // key identifier of the embedded key
  "kty": "EC",           // key type of the embedded key
  "alg": "ECDH-ES",      // algorithm of the embedded key
  "public_key": { "…": "…" }  // public JWK of the embedded private key
}
```

- `iat`, `exp`, and `nbf` describe the embedded key and follow the JWT
  convention for the same-named claims. Their enforcement is application
  policy.
- `kid`, `kty`, and `alg` expose the corresponding properties of the
  embedded key object.
- `public_key` exposes the public part of the embedded private key; see
  Section 4.1.
- Properties not listed above MUST NOT appear inside
  `embedded_key_info`.

### 4.1. The `public_key` property

`embedded_key_info` MAY include the property **`public_key`**, whose
value is a JWK object representing the public part of the embedded
private key.

- `public_key` is strictly OPTIONAL, and SHOULD be used only when the
  public key part is particularly something that the user wants to have
  directly visible from the JWE without decrypting it.
- `public_key` MUST only be used when the embedded key is an asymmetric
  **private** key, and its value MUST be the public JWK corresponding to
  that private key. It MUST NOT contain private key material.
- If a `public_key` is revealed and the embedded private key has a
  `kid`, the public key SHOULD also include the matching `kid`. The
  public key MUST NOT include a conflicting `kid`.
- If `embedded_key_info` itself includes the `kid` property, the public
  key MUST NOT include a `kid` conflicting with it.

### 4.2. Usage patterns

- It is typical to use `embedded_key_info` to expose only a subset — for
  example only `kty` — and it is also very usual to omit
  `embedded_key_info` entirely.
- Attaching the empty object `{}` as `embedded_key_info` is allowed and
  MAY be used as a signal that this JWE includes an embedded key, without
  revealing any information about the key itself.
- The absence of `embedded_key_info` carries no meaning: a JWE without it
  may or may not contain an embedded key.

### 4.3. Consistency

When `embedded_key_info` carries a value, the producer MUST ensure it is
consistent with the embedded key: `kid`, `kty`, and `alg` MUST equal the
same-named properties of the `key` claim's JWK (when those properties are
present in the JWK), `iat`/`exp`/`nbf` MUST equal the same-named claims
of the encrypted payload when the payload carries them, and `public_key`
MUST be the public counterpart of the embedded private key (Section 4.1).
A consumer MAY verify this consistency after decryption and MAY treat a
mismatch as an error.

### 4.4. Header placement

`embedded_key_info` MUST be placed in the JWE **protected** header, so
that it is integrity-protected by the JWE itself. It MUST NOT appear in
an unprotected header. Note that protection is integrity only: everything
in the header — including a `public_key` — is readable by anyone holding
the token.

## 5. Examples

A full token is an ordinary compact JWE; only the JSON structures are
shown here.

Encrypted payload — minimal (only the mandatory claim):

```json
{
  "key": { "kty": "oct", "alg": "A256GCM", "k": "…", "kid": "content-key-1" }
}
```

Encrypted payload — with optional application claims:

```json
{
  "kid": "auto:678ebcc5-45cb-4d50-8704-e5d1b297ddf8",
  "iat": 1783007751,
  "exp": 1787007751,
  "key": {
    "kty": "EC",
    "crv": "P-521",
    "x": "…",
    "y": "…",
    "d": "…",
    "kid": "auto:678ebcc5-45cb-4d50-8704-e5d1b297ddf8"
  }
}
```

Protected header — exposing only the key type:

```json
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "epk": { "…": "…" },
  "embedded_key_info": { "kty": "EC" }
}
```

Protected header — signalling an embedded key while revealing nothing:

```json
{
  "alg": "RSA-OAEP",
  "enc": "A256GCM",
  "kid": "escrow-key-2026",
  "embedded_key_info": {}
}
```

Protected header — deliberately revealing the public half of an embedded
private key (with the matching `kid`):

```json
{
  "alg": "RSA-OAEP",
  "enc": "A256GCM",
  "kid": "escrow-key-2026",
  "embedded_key_info": {
    "kid": "auto:678ebcc5-45cb-4d50-8704-e5d1b297ddf8",
    "public_key": {
      "kty": "EC",
      "crv": "P-521",
      "x": "…",
      "y": "…",
      "kid": "auto:678ebcc5-45cb-4d50-8704-e5d1b297ddf8"
    }
  }
}
```

## 6. Security considerations

- The confidentiality of the embedded key is exactly the confidentiality
  of the JWE. The key management algorithm and the recipient key of the
  JWE SHOULD be at least as strong as the embedded key they protect.
- Everything in `embedded_key_info` is cleartext metadata visible to any
  holder of the token. Exposing `kid`, `kty`, or `alg` leaks information
  about the embedded key; producers SHOULD expose only what consumers
  genuinely need, and omit `embedded_key_info` (or use the empty object)
  otherwise.
- A `public_key` reveals the entire public half of the embedded private
  key to every holder of the token — including the ability to encrypt to
  it or verify signatures made with it, and to correlate the token with
  other uses of the same key pair. Producers MUST treat this as a
  deliberate disclosure decision, never a default.
- An `embedded_key_info` outside the protected header would be malleable,
  which is why Section 4.3 forbids it. A consumer encountering one in an
  unprotected header MUST NOT rely on its contents.
- Embedded keys are frequently private or symmetric keys. Tokens
  following this convention SHOULD be handled with the same care as the
  key material itself (storage, transport, logging).

## 7. References

- [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels
- [RFC 7516] JSON Web Encryption (JWE)
- [RFC 7517] JSON Web Key (JWK)
- [RFC 7519] JSON Web Token (JWT)

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 7516]: https://www.rfc-editor.org/rfc/rfc7516
[RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
[RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
