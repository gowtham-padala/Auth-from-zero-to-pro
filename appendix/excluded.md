# Deliberately excluded

Stating the boundary keeps the scope from growing without limit. Here is what this book leaves out,
and why — so you know the edges of what you've learned, and where to go if you hit them.

---

## Cryptographic implementation

You learned **what** AES does ([B09](../book/track-b/B09-symmetric-encryption.md)), what a hash is
([B04](../book/track-b/B04-what-a-hash-function-is.md)), what a signature is
([B14](../book/track-b/B14-digital-signatures.md)) — never **how to implement** them. That's
deliberate. "Don't roll your own crypto" is taught here by *not teaching it*: every code example
calls a library ([B08](../book/track-b/B08-salts-peppers-slow-hashes.md),
[D15](../book/track-d/D15-build-passkeys.md)), and the one time you build a primitive by hand — HMAC
in [B13](../book/track-b/B13-message-authentication-hmac.md) — the chapter tells you to use the
library in production. If you want to implement cryptography, that's a different curriculum: start
with *Serious Cryptography* (Aumasson) and [Cryptopals](https://cryptopals.com/), and understand that
production crypto requires constant-time implementation, side-channel resistance
([B16](../book/track-b/B16-timing-attacks.md)), and expert review.

## Post-quantum migration

Real, and important — Shor's algorithm breaks RSA and elliptic-curve crypto
([B11](../book/track-b/B11-asymmetric-encryption.md)) on a sufficiently large quantum computer, and
"harvest now, decrypt later" is a live adversary strategy ([B12](../book/track-b/B12-key-exchange.md)).
But the migration is moving too fast for evergreen material: standards (ML-KEM, ML-DSA), hybrid
schemes, and browser/library support are changing quarter to quarter. **This belongs in a dated blog
post, not a book chapter.** Track it via [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography)
and your TLS library's release notes.

## Blockchain and decentralized identity

DIDs (Decentralized Identifiers) and verifiable credentials are a genuinely separate curriculum with
a different audience, a different trust model, and different primitives. They occasionally intersect
this book's world (a verifiable credential is, loosely, a signed claim —
[C03](../book/track-c/C03-the-vocabulary.md)), but the architecture, incentives, and failure modes
are distinct enough that mixing them in would confuse both. If DIDs are your problem, go learn them
from the [W3C DID](https://www.w3.org/TR/did-core/) and [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
specs directly.

## Specific vendor configuration

No "how to set up Auth0/Okta/Cognito" tutorials. They rot in months as UIs and APIs change, and the
vendor already wrote them (better, and maintained). This book teaches the *concepts* underneath —
[C05](../book/track-c/C05-build-vs-buy.md) tells you *when* to buy a provider and what to keep in
your own hands ([G09](../book/track-g/G09-multi-tenant-sso.md)), which is the durable knowledge. The
button-clicking is the vendor's docs' job.

## Physical and hardware security

HSMs get a mention ([I05](../book/track-i/I05-secrets-management.md)); secure enclaves get a mention
([D16](../book/track-d/D16-biometrics.md)). No more. Tamper-resistant hardware design, side-channel
lab attacks on physical devices, and secure supply chains are their own deep fields, mostly relevant
to a small set of practitioners building the hardware itself rather than the software on top of it.

## Anything network-layer below TLS

Referenced ([A01](../book/track-a/A01-what-happens-when-you-type-a-url.md),
[B17](../book/track-b/B17-what-https-protects.md)), never taught. TCP/IP security, BGP, DNSSEC,
firewalls, network segmentation, and DDoS mitigation are infrastructure security — adjacent to auth,
but a different discipline. This book starts at "you have a TLS connection"
([B17](../book/track-b/B17-what-https-protects.md)) and builds up from there.

## Kerberos / AD internals and their attacks

[G13](../book/track-g/G13-enterprise-directories.md) tells you what LDAP, Kerberos, and Active
Directory *are* and how you integrate (via SAML/OIDC, never the raw protocols). It deliberately does
**not** cover Kerberoasting, golden tickets, pass-the-hash, or the rest of the domain-attack
literature — those are *infrastructure* security (attacking the domain), not *application* auth
(building your product's login). If you're a domain administrator or a red-teamer, that's a different
and excellent body of knowledge.

---

## Terms this book therefore never defines

Because it never uses them ([GLOSSARY.md](../GLOSSARY.md)'s closing note): `DID`,
`verifiable credential`, `zero-knowledge proof`, `homomorphic encryption`, `post-quantum KEM`,
`Feistel network`, `S-box`, `HSM partition`, `SAML artifact binding`, `WS-Federation`,
`OAuth 1.0a signature base string`, `Kerberoasting`, `golden ticket`.

If you meet one of these, you're at a different edge of the identity graph. This book gave you the
core; those are the branches, and each has its own primary sources.

---

**Back to:** [README](../README.md) · [GLOSSARY.md](../GLOSSARY.md) · [K06](../book/track-k/K06-where-to-go-next.md)
