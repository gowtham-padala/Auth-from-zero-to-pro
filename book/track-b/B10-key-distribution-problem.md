# B10 — The key distribution problem

**Part B · Crypto foundations** · *Builds on [B09](B09-symmetric-encryption.md)*
---

## Why it matters

You have AES-256. Unbreakable. You want to send an encrypted message to someone you have
never met, over a network where everything is observed.

You encrypt the message. Now you need to send them the key.

Over the same network. Where everything is observed.

```
    You                       The wire                     Them
     │                            │                          │
     │  "here is the key: 8f14…" ─┼─────────────────────────>│
     │                            │                          │
     │                       👁 attacker                      │
     │                       now has the key                  │
     │                                                        │
     │  encrypted message ────────┼─────────────────────────>│
     │                            │                          │
     │                       👁 attacker decrypts it          │
```

Your cipher is perfect and provides no security whatsoever, because the key had to travel
the same road as the message.

This is the **key distribution problem**, and for most of the history of cryptography it
was simply unsolved. You met in person, or you used a trusted courier, or you did not
communicate securely.

---

## Why it is not a small problem

### It is circular

To share a key securely you need a secure channel. To have a secure channel you need a
shared key. The requirement is its own prerequisite.

For millennia, the only exits were physical: diplomatic pouches, codebooks distributed by
hand, one-time pads printed and carried. The German Enigma operators received monthly key
sheets on paper. Naval codebooks were weighted so they would sink.

That works when you have a state, a schedule, and a small set of known counterparties. It
does not work for a browser connecting to a website it has never heard of, half a second
after the user typed the name.

### It does not scale

Symmetric encryption needs a key **per pair of communicating parties**. With *n* parties:

```
                n(n − 1)
    keys  =  ──────────
                   2
```

| Parties | Keys | Keys each party holds |
|---|---|---|
| 2 | 1 | 1 |
| 10 | 45 | 9 |
| 100 | 4,950 | 99 |
| 1,000 | 499,500 | 999 |
| 1,000,000 | **~500 billion** | 999,999 |

This is the **n² problem**. The web has billions of clients and hundreds of millions of
servers. Pre-shared symmetric keys are not merely inconvenient there; they are
arithmetically impossible.

And it gets worse: **every new participant requires a key exchange with every existing
one.** A new website would need to establish a shared secret with every browser on Earth
before anyone could visit it.

### Revocation is worse still

Someone leaves the organisation. They knew every key they held. Every one must be replaced,
and every replacement must be distributed — over a secure channel you do not have, which is
the original problem again, now under time pressure. ([I03](../track-i/I03-deprovisioning.md)
is the modern version of this pain.)

---

## The three exits

There are only three ways out, and every real system uses one or more.

### 1. Out-of-band distribution

Use a *different* channel: meet in person, post a hardware token, print a QR code, read
digits over the phone.

Still used, and correctly:

- **TOTP enrolment.** The shared secret is delivered as a QR code on a screen you are
  already authenticated to. Out-of-band, one time, then never transmitted again.
  ([D12](../track-d/D12-build-totp.md).)
- **API keys.** Shown once in a dashboard, copied by a human.
  ([J02](../track-j/J02-api-keys.md).)
- **Recovery codes.** Printed. ([D13](../track-d/D13-recovery-codes.md).)
- **Certificate pinning.** The expected key ships inside the application binary.

The pattern: out-of-band works when there is a **one-time bootstrap moment** and a small
number of parties. It does not work for arbitrary strangers at scale.

### 2. A trusted third party

Everyone shares a key with one central authority. To talk to Bob, ask the authority to
mint a session key for you both.

*n* keys instead of *n²*. This is **Kerberos**, and it is why Windows domains work
([G13](../track-g/G13-enterprise-directories.md)).

The costs are real: the authority sees everything, must be online, is a single point of
failure, and is the most valuable target in the network. It works beautifully inside one
administrative domain. It cannot work across the open internet, because there is no
authority everyone trusts.

Note the structural echo — an **identity provider** ([C05](../track-c/C05-build-vs-buy.md))
is the same architecture applied to identity rather than keys, with the same trade: fewer
relationships, one very concentrated trust.

### 3. Public-key cryptography

Change the problem. Instead of one shared secret, use a **key pair**: one key you publish
to the entire world, one you never share.

Now nothing secret needs to travel. The public key can go anywhere — printed in a
newspaper, served over plain HTTP, shouted across a room. The private key never leaves the
machine that generated it.

This is the answer the internet actually runs on, and it is
[B11](B11-asymmetric-encryption.md) and [B12](B12-key-exchange.md).

---

## Why this took until 1976

The idea sounds obvious in retrospect. It was not.

Every cipher for three thousand years had been symmetric. The *definition* of a cipher
included that both parties held the same secret. Asking "what if they held different keys?"
was not a hard problem to solve so much as a hard question to ask.

The mathematics needed was a **one-way function with a trapdoor**: easy to compute,
infeasible to reverse, *unless* you hold a specific piece of information. Nobody had
looked for such a thing because nobody had needed one.

- **1976** — Diffie and Hellman, *New Directions in Cryptography*. Key exchange without a
  shared secret.
- **1977** — Rivest, Shamir, and Adleman publish RSA.
- **1997** — GCHQ declassifies work by Ellis, Cocks, and Williamson showing they had
  discovered equivalent techniques between 1969 and 1974 — and could tell nobody.

The parallel discovery is a good reminder that the mathematics was ready before the
application was. The *problem* is what was hard to see.

---

## What actually happens today

Modern systems use **both**, because each has the property the other lacks.

Asymmetric cryptography is slow — orders of magnitude slower than AES — and has awkward
size limits. Symmetric cryptography is fast and unlimited, but cannot bootstrap.

So: use asymmetric to establish a symmetric key, then use symmetric for everything else.
This is **hybrid encryption**, and it is what every TLS connection does:

```
1. Asymmetric  ──>  agree on a shared secret          (expensive, once per connection)
                    and verify the server's identity

2. Symmetric   ──>  encrypt all the actual traffic    (cheap, for the whole session)
                    with AES-GCM or ChaCha20-Poly1305
```

Step 1 is [B12](B12-key-exchange.md) and [B15](B15-certificates-and-pki.md). Step 2 is
[B09](B09-symmetric-encryption.md). Put together, they are
[B17](B17-what-https-protects.md).

The same shape appears in **envelope encryption** ([I05](../track-i/I05-secrets-management.md)):
encrypt the data with a fast data key, encrypt the data key with a master key that never
leaves the KMS. Same trade, different layer.

---

## Where key distribution still bites, in auth

The problem is solved for the *web*. It is not solved everywhere, and recognising it is
useful:

| Situation | The distribution problem | How it is handled |
|---|---|---|
| Signing your own JWTs (HS256) | Every verifier needs the same secret | Fine within one service; **breaks the moment a second party must verify** |
| Multiple services verifying JWTs | Sharing an HMAC secret means any of them can *forge* tokens | Switch to **RS256/ES256** — verifiers get only the public key ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) |
| Publishing verification keys | How does a client learn the key? | **JWKS** over HTTPS ([E07](../track-e/E07-jose-family.md)) |
| Rotating a signing key | Verifiers cache the old one | **`kid` + overlap window** ([I06](../track-i/I06-key-rotation.md)) |
| Webhook signing | Both sides need the secret | Out-of-band via dashboard ([J06](../track-j/J06-signing-webhooks.md)) |
| Service-to-service identity | Every service needs a credential | **SPIFFE/SPIRE**, or mTLS with a private CA ([J05](../track-j/J05-workload-identity-spiffe.md)) |

The row worth internalising is the second one. **A shared HMAC secret gives every holder
the power to forge, not just to verify.** The moment more than one party needs to check a
signature, symmetric signing is the wrong tool — and the reason is exactly the key
distribution problem, wearing a different hat.

---

## Terms defined in this chapter

`key distribution problem`, `n² problem`

---

## What to remember

1. A perfect cipher is useless if the key must travel the same channel as the message.
2. The problem is **circular**: a secure channel needs a shared key; a shared key needs a
   secure channel.
3. Symmetric keys scale as **n(n−1)/2**. For the web, that is arithmetically impossible.
4. Three exits: **out-of-band** (works for one-time bootstrap), **trusted third party**
   (works inside one domain — Kerberos), **public-key** (works everywhere).
5. Real systems are **hybrid**: asymmetric to establish a key, symmetric for the data.
6. **A shared HMAC secret lets every holder forge.** Multi-party verification requires
   asymmetric signatures.

---

## Sources

- Diffie & Hellman, [*New Directions in Cryptography*](https://ee.stanford.edu/~hellman/publications/24.pdf) (1976) — still the clearest statement of the problem
- David Wong, *Real-World Cryptography*, Ch. 5–6
- [MIT Kerberos: The Network Authentication Protocol](https://web.mit.edu/kerberos/)

---

**Next:** [B11 — Asymmetric encryption and one-way math](B11-asymmetric-encryption.md)
