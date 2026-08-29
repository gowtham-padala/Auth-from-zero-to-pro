# B12 — Key exchange: agreeing on a secret in public

**Part B · Crypto foundations** · *Builds on [B11](B11-asymmetric-encryption.md)*
---

## The problem

You and a stranger, no prior contact, on a channel where every byte is public. You must end
up with the same secret number. The eavesdropper sees everything you say and must not be
able to compute it.

Stated that way it sounds impossible. It is not.

---

## Diffie–Hellman, with paint

The standard analogy, and it is genuinely faithful to the mathematics.

Mixing paint is easy. **Un**-mixing paint is hard. That is a one-way function you already
have intuitions about.

```
        ALICE                    PUBLIC                     BOB
                                 (visible)

   ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
   │              │         │  yellow      │         │              │
   │              │<────────┤  (agreed)    ├────────>│              │
   │              │         └──────────────┘         │              │
   │ + RED        │                                  │ + BLUE       │
   │  (secret)    │                                  │  (secret)    │
   │      ▼       │                                  │      ▼       │
   │  ORANGE      ├───────────> ORANGE ──────────────┤              │
   │              │                                  │              │
   │              │<───────────  GREEN <─────────────┤  GREEN       │
   │      +       │                                  │      +       │
   │   RED        │                                  │   BLUE       │
   │      ▼       │                                  │      ▼       │
   │  ┌────────┐  │                                  │  ┌────────┐  │
   │  │ BROWN  │  │        ═══ SAME COLOUR ═══       │  │ BROWN  │  │
   │  └────────┘  │                                  │  └────────┘  │
   └──────────────┘                                  └──────────────┘

   The eavesdropper has: yellow, orange, green.
   To get brown they would need red or blue — which requires un-mixing paint.
```

Alice computes `yellow + red + blue`. Bob computes `yellow + blue + red`. Same mixture,
different order. Neither ever transmitted their own secret colour.

### The actual arithmetic

Replace paint with modular exponentiation, which is one-way in the same practical sense
([B11](B11-asymmetric-encryption.md)).

```
Public, agreed in the clear:   p = 23   (a large prime, in reality 2048+ bits)
                               g = 5    (a generator)

Alice picks secret a = 6        Bob picks secret b = 15

Alice sends:  A = g^a mod p = 5^6  mod 23 = 8
Bob sends:    B = g^b mod p = 5^15 mod 23 = 19

Alice computes:  s = B^a mod p = 19^6  mod 23 = 2
Bob computes:    s = A^b mod p = 8^15  mod 23 = 2
                                                 ▲
                          the shared secret ─────┘
```

Both arrive at 2, because `(g^b)^a = g^(ab) = (g^a)^b`. Commutativity of exponents is the
whole trick.

The eavesdropper has `p=23`, `g=5`, `A=8`, `B=19`. To find `s` they must solve
`5^x mod 23 = 8` for `x` — the **discrete logarithm problem**. At 23 you can do it by
inspection. At 2048 bits, nobody can.

In practice this is done over an elliptic curve — **ECDH**, usually X25519 — which gets the
same security from far smaller numbers.

---

## Ephemeral, and why it is the whole point

The `a` and `b` above are chosen **fresh for every connection** and discarded when it ends.
Hence **ECDHE** — the final E is "ephemeral."

```
   NON-EPHEMERAL (RSA key transport, TLS ≤1.2)      EPHEMERAL (ECDHE, TLS 1.3)

   Client picks the session key                     Both derive it via DH
   Encrypts it with the server's public key         Nothing secret is transmitted
   Sends it                                         Ephemeral keys destroyed after use
        │                                                 │
        ▼                                                 ▼
   Steal the server key later                        Steal the server key later
        │                                                 │
        ▼                                                 ▼
   ❌ Decrypt every recorded session,               ✅ Decrypt nothing.
      retroactively, forever                            Past sessions are safe.
```

> **Forward secrecy:** compromising a long-term key does not compromise past sessions.

This is why **TLS 1.3 removed RSA key transport entirely.** It is not configurable. The
only key agreement mechanisms are ephemeral, so forward secrecy is mandatory rather than a
setting a tired administrator forgets.

The stored-data equivalent is worth noticing: *harvest now, decrypt later* is a real
adversary strategy. Nation-state actors record encrypted traffic today in the expectation
of decrypting it eventually. Forward secrecy defeats the version of that which relies on
future key theft. (It does not defeat the version that relies on future quantum computers —
that is a different migration, deliberately out of scope.)

---

## What key exchange does not do

Here is the gap that makes the rest of Track B necessary.

Diffie–Hellman gives you a shared secret with **someone**. It says nothing about **who**.

```
   Alice                    Mallory                      Bob
     │                         │                          │
     │──── DH exchange ───────>│                          │
     │<─── shared secret S₁ ───│                          │
     │                         │──── DH exchange ────────>│
     │                         │<─── shared secret S₂ ────│
     │                         │                          │
     │  encrypted with S₁      │      encrypted with S₂   │
     │────────────────────────>│─────────────────────────>│
     │                    decrypts, reads,                │
     │                    re-encrypts                     │
```

Both connections are perfectly encrypted. Mallory sits in the middle reading everything.
Neither party can detect it from the exchange alone, because a **man-in-the-middle** attack
does not break the mathematics — it satisfies it, twice.

Unauthenticated Diffie–Hellman protects against a **passive** eavesdropper and is useless
against an **active** one.

### The fix: authenticate the exchange

The server **signs** its Diffie–Hellman parameters with the private key belonging to its
certificate. Now:

- Mallory can substitute her own DH values, but she cannot sign them as `example.com` —
  she has no private key for that name.
- The client verifies the signature against the certificate, and verifies the certificate
  chains to a trusted CA ([B15](B15-certificates-and-pki.md)).

```
  ECDHE  ──── gives you ────>  a shared secret, forward-secret
  Signature ── gives you ───>  proof of WHO you shared it with
  ─────────────────────────────────────────────────────────────
  Together                     an authenticated, encrypted channel
```

**This is the shape of TLS.** Key exchange for confidentiality, signature for authenticity,
certificate for identity, symmetric cipher for the bulk data. Four primitives, each doing
exactly one job, none of them sufficient alone.

That decomposition is worth memorising, because it recurs. It is the same separation that
distinguishes a JWT's signature (authenticity) from a JWT's encryption (confidentiality),
and the same reason [G04](../track-g/G04-validate-an-id-token-by-hand.md) must check `iss`
in addition to verifying a signature.

---

## The TLS 1.3 handshake, briefly

```
Client                                                          Server
  │                                                                │
  │── ClientHello ────────────────────────────────────────────────>│
  │   supported ciphers, key_share (ephemeral X25519 public)       │
  │                                                                │
  │<───────────────────────────────────────────── ServerHello ─────│
  │   chosen cipher, key_share (ephemeral X25519 public)           │
  │   {Certificate}              ← from here, encrypted             │
  │   {CertificateVerify}        ← signature over the transcript    │
  │   {Finished}                                                    │
  │                                                                │
  │── {Finished} ─────────────────────────────────────────────────>│
  │                                                                │
  │<══════════ application data, AES-GCM / ChaCha20 ══════════════>│
```

**One round trip.** Notice:

- Both key shares are sent immediately — the exchange completes in the first exchange of
  messages.
- `CertificateVerify` is a signature **over the entire handshake transcript**, so it cannot
  be replayed into a different handshake.
- Even the certificate is encrypted, which is a privacy improvement over TLS 1.2.
- The derived secret is not used directly. It is run through **HKDF** to produce separate
  keys for each direction and purpose — key separation, so that a weakness in one use
  cannot affect another.

TLS 1.2 needed two round trips and offered many ways to configure it insecurely. TLS 1.3
removed RSA key transport, static DH, CBC modes, RC4, compression, and renegotiation. It is
a good example of a specification getting safer by **deleting options**, which is a design
principle worth carrying into your own systems.

---

## Where key exchange appears in auth

Mostly it is underneath you, and that is correct:

| Use | Notes |
|---|---|
| Every HTTPS connection | ECDHE, forward-secret. [B17](B17-what-https-protects.md) |
| mTLS between services | Same handshake, both sides present certificates. [J04](../track-j/J04-mtls.md) |
| SSH | Its own exchange, same principles |
| Signal / end-to-end messaging | X3DH + Double Ratchet — forward secrecy per *message* |
| JWE key agreement (`ECDH-ES`) | Encrypting a JWT to a recipient's public key |

**You will essentially never implement a key exchange.** What you will do is *choose*
whether the one underneath you is ephemeral — and after TLS 1.3, even that is decided for
you. The value of this chapter is understanding what forward secrecy buys, why TLS 1.3
deleted the alternative, and why a signature must accompany the exchange.

---

## Terms defined in this chapter

`key exchange`, `Diffie–Hellman`, `ECDH`, `forward secrecy`

---

## What to remember

1. Two strangers **can** agree on a secret over a fully public channel. Commutative
   exponents make it work.
2. **Ephemeral keys give forward secrecy.** Stealing the long-term key does not decrypt
   past traffic.
3. **TLS 1.3 removed RSA key transport**, making forward secrecy mandatory rather than
   optional.
4. Key exchange alone is **defenceless against an active attacker**. A man in the middle
   satisfies the maths twice.
5. **Signature + certificate is what turns "a secret with someone" into "a secret with
   Google."**
6. TLS = key exchange + signature + certificate + symmetric cipher. Four jobs, four
   primitives.

---

## Sources

- [RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748) (X25519)
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/) — every byte of a real handshake, annotated
- David Wong, *Real-World Cryptography*, Ch. 5 and Ch. 9

---

**Next:** [B13 — Message authentication: hashing with a secret, and HMAC](B13-message-authentication-hmac.md)
