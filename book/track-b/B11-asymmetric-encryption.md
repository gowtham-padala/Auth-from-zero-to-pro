# B11 — Asymmetric encryption and one-way math

**Part B · Crypto foundations** · *Builds on [B10](B10-key-distribution-problem.md)*
---

## The idea

> Two keys, mathematically linked. What one does, only the other can undo. Publishing one
> of them reveals nothing about the other.

```
    ┌──────────────┐        ┌──────────────┐
    │  PUBLIC KEY  │        │ PRIVATE KEY  │
    │              │        │              │
    │  Give to     │        │  NEVER       │
    │  everyone    │        │  leaves      │
    │              │        │              │
    │  In a JWKS   │        │  On one      │
    │  In a cert   │        │  machine,    │
    │  In a repo   │        │  or in a KMS │
    └──────────────┘        └──────────────┘
             └──── linked ────┘
    You cannot derive the private key from the public one.
```

Two directions, two completely different purposes:

```
  ENCRYPT with public → DECRYPT with private       CONFIDENTIALITY
  ┌──────────────────────────────────────────────────────────────┐
  │ Anyone can encrypt to you. Only you can read it.             │
  └──────────────────────────────────────────────────────────────┘

  SIGN with private → VERIFY with public           AUTHENTICITY
  ┌──────────────────────────────────────────────────────────────┐
  │ Only you can produce it. Anyone can check it.                │
  └──────────────────────────────────────────────────────────────┘
```

**The second direction is the one this book cares about.** JWTs, certificates, passkeys,
SSO — every one of them is signature, not encryption. Encryption to a public key is
comparatively rare in web authentication. If you take one thing from this chapter, take
that the important use is signing, and that is [B14](B14-digital-signatures.md).

---

## The one-way math

The whole edifice rests on **trapdoor functions**: easy forwards, infeasible backwards,
unless you hold a specific secret.

### Multiplication vs factoring (RSA)

Multiply two large primes: instant.

```
  p = 61            q = 53
  n = p × q = 3233                                          ← seconds
```

Given only `n`, recover `p` and `q`: for a 2048-bit `n`, no known feasible method.

```
  n = 3233  →  p = ?, q = ?                                 ← at scale: infeasible
```

That asymmetry — trivial one way, impossible the other — *is* RSA. The private key is
built from `p` and `q`; the public key from `n` and a public exponent. Knowing the public
key means knowing `n`, and recovering the private key means factoring it.

### Discrete logarithms (Diffie–Hellman, DSA)

Given `g`, `p`, and `x`, computing `gˣ mod p` is fast. Given `g`, `p`, and the result,
recovering `x` is infeasible.

The modular arithmetic destroys the ordering information you would normally use — the
results jump around unpredictably, so there is no way to binary-search or hill-climb your
way to `x`.

### Elliptic curves (ECDSA, EdDSA, ECDH)

Same discrete-logarithm idea, over the points of an elliptic curve. "Adding" a point to
itself `k` times is fast; recovering `k` from the result is not.

The practical consequence is **key size**:

| Security level | RSA | Elliptic curve |
|---|---|---|
| 112-bit | 2048-bit | 224-bit |
| 128-bit | **3072-bit** | **256-bit** |
| 192-bit | 7680-bit | 384-bit |
| 256-bit | 15360-bit | 512-bit |

A 256-bit EC key matches a 3072-bit RSA key. Smaller keys, smaller signatures, faster
operations, less bandwidth. This is why modern systems default to elliptic curves and why
`ES256` is generally preferable to `RS256` for new JWT deployments
([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).

**Note what these problems have in common:** they are *believed* hard, not *proven* hard.
There is no proof that factoring is difficult. This is why post-quantum cryptography is a
live concern — Shor's algorithm solves both factoring and discrete logarithms efficiently
on a sufficiently large quantum computer. That migration is real, moving quickly, and
deliberately out of scope here ([appendix/excluded.md](../../appendix/excluded.md)).

---

## The algorithms you will meet

| Algorithm | Type | Use | Verdict |
|---|---|---|---|
| **RSA** | Factoring | Signing, encryption, TLS | Fine at ≥2048; 3072 for new keys |
| **ECDSA** (P-256) | EC discrete log | Signing, TLS | Good. Widely required. |
| **EdDSA** (Ed25519) | EC (Edwards) | Signing | **Best choice** where supported |
| **ECDH** (X25519) | EC | Key exchange | Standard in TLS 1.3 |
| DSA | Discrete log | Signing | Obsolete |

### Why Ed25519 where you can

It is **misuse-resistant**, which matters more than raw speed.

ECDSA requires a fresh random nonce for every signature. Reuse one and the private key can
be computed algebraically from two signatures. This is not hypothetical:

- **Sony PlayStation 3 (2010)** — the same nonce for every signature. The console's master
  signing key was extracted, and the platform's code-signing was permanently broken.
- **Android Bitcoin wallets (2013)** — a weak `SecureRandom` produced repeated nonces.
  Wallets were emptied.

Ed25519 derives its nonce **deterministically** from the message and the private key. There
is no random value to get wrong. The failure mode is designed out rather than documented.

This is the recurring theme of modern cryptographic engineering: **prefer the primitive
where the dangerous mistake is impossible**, not the one where it is merely discouraged.
Same reasoning as AEAD over encrypt-then-MAC ([B09](B09-symmetric-encryption.md)), and
Argon2id over hand-rolled iteration ([B08](B08-salts-peppers-slow-hashes.md)).

---

## What asymmetric encryption is *not* good at

**It is slow.** RSA-2048 does a few thousand operations per second; AES does gigabytes.
Three or more orders of magnitude.

**It has size limits.** RSA-2048 with OAEP padding encrypts at most ~190 bytes. You cannot
encrypt a file with RSA.

Hence **hybrid encryption**, exactly as [B10](B10-key-distribution-problem.md) described:
generate a random symmetric key, encrypt the data with AES-GCM, encrypt *the key* with the
public key. This is what JWE does ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)),
what PGP does, and what envelope encryption in a KMS does
([I05](../track-i/I05-secrets-management.md)).

**Raw RSA is dangerous.** Textbook RSA is deterministic and malleable. Real use requires
padding — **OAEP** for encryption, **PSS** for signatures. PKCS#1 v1.5 padding has a
history of oracle attacks (Bleichenbacher, 1998, and repeatedly resurrected since).

**And critically: asymmetric cryptography does not tell you *whose* key it is.**

A public key is a number. It arrives with no name attached. Verifying a signature proves
*someone holding the corresponding private key produced it* — and nothing about who that
someone is.

That gap is what certificates fill ([B15](B15-certificates-and-pki.md)), and skipping it is
the most common structural error in identity systems. "The signature verified" and "this
came from Google" are different statements, and the second requires binding a key to a
name through something you already trust. It is why
[G04](../track-g/G04-validate-an-id-token-by-hand.md) checks `iss` and fetches the JWKS
*from a URL derived from `iss`*, rather than from a key embedded in the token.

---

## Where asymmetric cryptography carries the design

| Use | Which direction | Chapter |
|---|---|---|
| TLS server authentication | Sign, verify with cert | [B17](B17-what-https-protects.md) |
| TLS key agreement | ECDH | [B12](B12-key-exchange.md) |
| JWT `RS256`/`ES256` | Sign private, verify public | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| **Passkeys / WebAuthn** | Sign private (on device), verify public (server) | [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |
| SAML assertions | Sign private (IdP), verify public (SP) | [G07](../track-g/G07-saml-survival-guide.md) |
| `private_key_jwt` client auth | Sign private (client), verify public (AS) | [F09](../track-f/F09-public-vs-confidential-clients.md) |
| DPoP proofs | Sign private, verify public | [F16](../track-f/F16-sender-constrained-tokens.md) |
| mTLS | Both sides prove key possession | [J04](../track-j/J04-mtls.md) |
| SSH, code signing, package signing | Sign, verify | — |

The passkey row is the one to dwell on. A passkey is *exactly* this chapter: a key pair
where the private key never leaves your device — often never leaves a secure enclave — and
the server stores only the public key.

Which means **a breach of the server yields nothing usable.** There is no password hash to
crack, no shared secret to steal. The attacker gets a list of public keys, which they were
welcome to anyway. That is the strongest argument for passkeys, and it is a direct
consequence of the asymmetry introduced in this chapter.
([D16](../track-d/D16-biometrics.md) closes the loop on the biometric part.)

---

## Terms defined in this chapter

`asymmetric encryption`, `public key`, `private key`, `trapdoor function`, `RSA`,
`elliptic curve`, `ECDSA`, `Ed25519`

---

## What to remember

1. Two linked keys. Publishing one reveals nothing about the other.
2. **Encrypt with public / decrypt with private** = confidentiality. **Sign with private /
   verify with public** = authenticity. Auth almost always wants the second.
3. Security rests on trapdoor functions — factoring, discrete logs — believed hard, not
   proven hard.
4. **EC keys are far smaller for equal strength.** 256-bit EC ≈ 3072-bit RSA.
5. **Ed25519 removes the nonce footgun that broke the PS3 and emptied Bitcoin wallets.**
   Prefer primitives where the mistake is impossible.
6. Asymmetric is slow and size-limited → hybrid encryption everywhere.
7. **A public key has no name on it.** Verifying a signature says nothing about *who*.
   That is what [B15](B15-certificates-and-pki.md) is for.

---

## Sources

- Diffie & Hellman, [*New Directions in Cryptography*](https://ee.stanford.edu/~hellman/publications/24.pdf) (1976)
- [RFC 8017 — PKCS #1: RSA Cryptography Specifications v2.2](https://www.rfc-editor.org/rfc/rfc8017) (OAEP and PSS)
- [RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/rfc/rfc8032)
- [NIST SP 800-57 Part 1 Rev. 5 — Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) (the key-size equivalence table)
- Jean-Philippe Aumasson, *Serious Cryptography*, 2nd ed., Ch. 10–12

---

**Next:** [B12 — Key exchange: agreeing on a secret in public](B12-key-exchange.md)
