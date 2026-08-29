# B14 — Digital signatures: asymmetric encryption run backwards

**Part B · Crypto foundations** · *Builds on [B11](B11-asymmetric-encryption.md), [B13](B13-message-authentication-hmac.md)*
---

## The idea

Take [B11](B11-asymmetric-encryption.md) and run it the other way.

```
   ENCRYPTION                          SIGNATURE
   ───────────                         ─────────
   encrypt with PUBLIC                 sign with PRIVATE
   decrypt with PRIVATE                verify with PUBLIC

   "anyone can send me a secret"       "anyone can check I sent this"
```

Because only one party holds the private key, only that party can produce a valid
signature. Because the public key is public, *everyone* can verify.

```
    ┌─────────────────────┐              ┌─────────────────────┐
    │       SIGNER        │              │      VERIFIER       │
    │                     │              │  (anyone at all)    │
    │  message            │              │                     │
    │     │               │              │  message            │
    │     ▼ SHA-256       │              │     │               │
    │  digest             │  ─────────>  │     ▼ SHA-256       │
    │     │               │  message +   │  digest             │
    │     ▼ sign(privkey) │  signature   │     │               │
    │  signature          │              │     ▼ verify(pubkey)│
    └─────────────────────┘              │  ✅ / ❌            │
                                         └─────────────────────┘
```

**You sign the digest, not the message.** Asymmetric operations are slow and size-limited
([B11](B11-asymmetric-encryption.md)); a hash turns any input into a fixed 32 bytes. This
is why [B04](B04-what-a-hash-function-is.md) had to come first, and why a broken hash
breaks signatures ([B06](B06-collisions.md)) even when the signature algorithm is perfect.

---

## What a signature proves

| Property | Meaning |
|---|---|
| **Authenticity** | Produced by the holder of the private key |
| **Integrity** | The message has not changed by one bit |
| **Non-repudiation** | The signer cannot credibly deny it — nobody else *could* have produced it |

**Non-repudiation is the property HMAC cannot give you**, and it is exactly what a shared HMAC secret cannot give you. With HMAC, six services shared the ability to produce. With
signatures, one service produces and six verify — and a breach of a verifier yields a
public key, which was already public.

### What a signature does *not* prove

Three things people assume and should not:

1. **Not confidentiality.** A signed message is readable by anyone. This is why a signed
   JWT's payload is plain base64url ([E05](../track-e/E05-jwt-part-1-three-parts.md)) and
   why "signed" never means "private."

2. **Not freshness.** A valid signature stays valid forever. Capture and resend it and it
   still verifies — a **replay attack**. Freshness comes from something *inside* the signed
   data: an expiry (`exp`), a nonce, a timestamp, a counter. This is why
   [G04](../track-g/G04-validate-an-id-token-by-hand.md) checks `exp` and `nonce` in
   addition to the signature, and why WebAuthn signs a server-supplied challenge
   ([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)).

3. **Not identity.** A signature proves *someone with this private key* signed. It does not
   say who they are. Binding a key to a name requires a certificate
   ([B15](B15-certificates-and-pki.md)) or a trusted registry of keys (a JWKS fetched from
   an issuer you already trust — [E07](../track-e/E07-jose-family.md)).

> **"The signature verified" is a much weaker statement than people hear it as.** It means:
> the bytes are unmodified since *someone* signed them. Everything else — who, when,
> for what audience — must be checked separately, from data inside the signed payload.
>
> The list of checks after signature verification is
> [G04](../track-g/G04-validate-an-id-token-by-hand.md), and it is longer than most people
> expect.

---

## The algorithms

| Algorithm | Basis | Signature size | Notes |
|---|---|---|---|
| **RSA-PKCS#1 v1.5** | Factoring | 256 B (2048-bit) | Legacy padding. Works; not for new designs. |
| **RSA-PSS** | Factoring | 256 B | Modern RSA padding. Provably secure. |
| **ECDSA** (P-256) | EC discrete log | 64 B | Compact, widely required. **Nonce-critical.** |
| **EdDSA** (Ed25519) | EC (Edwards) | 64 B | **Best default.** Deterministic, fast, misuse-resistant. |

In JOSE terms ([E07](../track-e/E07-jose-family.md)):

| `alg` | Means |
|---|---|
| `HS256` | **HMAC**-SHA256 — symmetric, *not* a signature |
| `RS256` | RSA-PKCS#1 v1.5 + SHA-256 |
| `PS256` | RSA-PSS + SHA-256 |
| `ES256` | ECDSA on P-256 + SHA-256 |
| `EdDSA` | Ed25519 |

Note that `HS256` sits in that list looking like the others and is a fundamentally
different thing. That confusion is precisely what **algorithm confusion attacks** exploit
([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)): an attacker takes your *public* RSA
key — which you published — and uses it as an *HMAC secret* to sign a token with `alg:
HS256`. A verifier that trusts the token's `alg` field looks up "the key," gets the RSA
public key, runs HMAC with it, and the forgery verifies.

The fix is one line: **the verifier decides the algorithm, from configuration. Never from
the token.**

### The ECDSA nonce, again

ECDSA needs a unique random nonce per signature. Reuse it across two signatures and the
private key falls out of simple algebra. Sony's PS3 (2010) used a constant. Android's
Bitcoin wallets (2013) used a weak PRNG.

**Ed25519 derives the nonce deterministically from the key and message.** There is no
random value to get wrong. Prefer it, for the same reason you prefer AEAD over
encrypt-then-MAC: the dangerous mistake is unavailable
([B11](B11-asymmetric-encryption.md)).

If you must use ECDSA, use an implementation with **deterministic nonces**
([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)).

---

## Sign and verify

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

private_key = Ed25519PrivateKey.generate()
public_key  = private_key.public_key()          # publish this freely

message = b"transfer 100 to bob"
signature = private_key.sign(message)           # 64 bytes

# Anyone with the public key:
public_key.verify(signature, message)           # no exception = valid ✅

try:
    public_key.verify(signature, b"transfer 100000 to mallory")
except InvalidSignature:
    print("rejected")                           # ✅
```

Note the API shape: **verification raises on failure rather than returning `False`.** That
is deliberate library design. A boolean return invites `if verify(...)` written without the
`if`, or a truthy object mistaken for success. An exception cannot be ignored by accident.

When you write your own verification wrapper, do the same — fail closed, loudly.

---

## Where signatures carry the design

| Use | Signer | Verifier | Chapter |
|---|---|---|---|
| **TLS certificates** | CA | Every browser | [B15](B15-certificates-and-pki.md) |
| **TLS handshake** | Server | Client | [B12](B12-key-exchange.md) |
| **JWT `RS256`/`ES256`** | Auth server | Every API | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| **ID tokens** | Identity provider | Relying party | [G04](../track-g/G04-validate-an-id-token-by-hand.md) |
| **SAML assertions** | IdP | Service provider | [G07](../track-g/G07-saml-survival-guide.md) |
| **Passkeys / WebAuthn** | The user's device | Your server | [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |
| **DPoP proofs** | Client | Resource server | [F16](../track-f/F16-sender-constrained-tokens.md) |
| **`private_key_jwt`** | OAuth client | Authorization server | [F09](../track-f/F09-public-vs-confidential-clients.md) |
| **Code / package signing** | Publisher | Every installer | — |

The passkey row is the best illustration in the book of why this primitive matters.

A passkey is a key pair. The private key never leaves the user's device — often never
leaves a hardware secure enclave ([D16](../track-d/D16-biometrics.md)). The server stores
**only the public key.**

So:

- **Your database breach leaks nothing usable.** No password hashes to crack, no shared
  secrets. Just public keys, which are public.
- **Phishing fails**, because the signature covers the origin the browser is actually on
  ([A09](../track-a/A09-redirects.md)). A wrong-origin signature does not verify, and the
  human's judgement is never consulted.
- **Server-side reuse is impossible.** With a password, the server briefly holds a
  credential that works elsewhere. With a passkey, the server never holds anything secret
  at all.

Every one of those properties is a direct consequence of "sign with private, verify with
public."

---

## Choosing: HMAC or signature?

The decision that matters:

```
                Who needs to VERIFY?
                        │
        ┌───────────────┴───────────────┐
   One party                      Multiple parties
   (or mutually trusting)         (or across a trust boundary)
        │                                │
       HMAC                          SIGNATURE
   fast, 32-byte tag              slower, but verifiers
   shared secret                  cannot forge
        │                                │
   ✅ session cookies             ✅ JWTs across services
   ✅ CSRF tokens                 ✅ ID tokens from an IdP
   ✅ your own webhooks           ✅ certificates
   ✅ TOTP                        ✅ passkeys
```

The trap is that HMAC works fine on day one, when there is one service. It fails on the day
someone adds a second verifier — and that day arrives without anyone re-examining the
choice. Ask "how many parties will eventually verify this?" at design time, not at the
second service.

---

## Terms defined in this chapter

`digital signature`, `non-repudiation`, `sign`, `verify`

---

## What to remember

1. **Sign with private, verify with public.** Verification is a strictly weaker capability
   than production — that is the entire value.
2. **You sign the digest**, so a broken hash breaks signatures.
3. A signature gives authenticity, integrity, and **non-repudiation**. HMAC does not give
   the third.
4. A signature does **not** give confidentiality, freshness, or identity. Check `exp`,
   `nonce`, `iss`, and `aud` separately.
5. `HS256` is HMAC, not a signature. **Algorithm confusion** exploits treating them alike —
   the verifier must choose the algorithm.
6. **Ed25519** by default. ECDSA nonce reuse leaks the private key.
7. Passkeys are this chapter applied to login: the server holds only a public key, so a
   breach yields nothing.

---

## Sources

- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [RFC 8017 — PKCS #1 v2.2](https://www.rfc-editor.org/rfc/rfc8017) (PSS, §8.1)
- [RFC 6979 — Deterministic Usage of DSA and ECDSA](https://www.rfc-editor.org/rfc/rfc6979)
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518) §3 (the `alg` values)
- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/)

---

**Next:** [B15 — Certificates and PKI: why your browser trusts a stranger](B15-certificates-and-pki.md)
