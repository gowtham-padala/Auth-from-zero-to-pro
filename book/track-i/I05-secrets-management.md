# I05 — Secrets management: KMS, vaults, and never in git

**Part I · Identity lifecycle & operations** · *Builds on [A10](../track-a/A10-where-secrets-live.md)*
---

## The insight: don't hold the key, use it remotely

The env-var approach fails because the key is *in the application*, so compromising the
application compromises the key. A **key management service (KMS)** or **hardware security
module (HSM)** inverts this:

```
   ENV VAR:  app holds the key  ──▶  attacker who reaches the app  ──▶  TAKES the key forever
   KMS:      app SENDS data to the KMS, KMS returns a signature
             app never holds the key  ──▶  attacker who reaches the app  ──▶  can USE the key
                                          while inside — logged, revocable — but CANNOT TAKE it
```

With a KMS, the private key **has no exportable form** ([D16](../track-d/D16-biometrics.md),
[B11](../track-b/B11-asymmetric-encryption.md)). Your app calls `kms.sign(data)` and gets back a
signature; the key never leaves the KMS. So a full application compromise becomes a *bounded*
incident:

- The attacker can *use* the key while they're inside — but every use is **logged**
  ([H13](../track-h/H13-audit-logging.md)), **rate-limitable**, and **revocable**
  ([I10](I10-incident-response.md)).
- The moment you detect and evict them, the key is safe — no offline forging, because they never
  had the key material.

That difference — "take it forever" vs "use it while present" — turns a permanent catastrophe
into an incident you can respond to. It is the same reasoning as secure enclaves for passkeys
([D16](../track-d/D16-biometrics.md)): a key that can be used but not extracted.

---

## Two kinds of secret management

| | **Secret store** (Vault, cloud secret managers) | **KMS / HSM** |
|---|---|---|
| Holds | Arbitrary secrets (DB passwords, API keys) | Cryptographic **keys** |
| Returns | The secret value (your app then holds it) | **Operations** (sign, encrypt) — key never leaves |
| Use for | Config secrets you must *have* | Keys you must *use* but never *hold* |
| Example | `vault kv get db-password` → the password | `kms.sign(digest)` → a signature |

The distinction matters ([B05](../track-b/B05-hashing-vs-encryption.md)): a database password is
a secret you *need the value of* (to connect), so a secret store gives it to you. A signing key
is a secret you only need to *use*, so a KMS never gives you the value — which is strictly safer.

**Use each for what it's for:** secret stores for values you must possess, KMS for keys you can
avoid possessing.

---

## Envelope encryption — encrypting a lot with a key that never leaves

A KMS operates on small data. To encrypt a large document with a key that never leaves the KMS,
use **envelope encryption** — the hybrid pattern from [B10](../track-b/B10-key-distribution-problem.md),
applied to key management:

```python
# ENCRYPT
data_key_plain, data_key_encrypted = kms.generate_data_key(key_id=MASTER_KEY)
#   KMS returns: a random data key (plaintext) AND that key encrypted under the master key.

ciphertext = aes_gcm_encrypt(data_key_plain, document)      # B09 — fast, local
del data_key_plain                                          # discard the plaintext key NOW
store(ciphertext, data_key_encrypted)                       # store both; NOT the plaintext key

# DECRYPT
data_key_plain = kms.decrypt(data_key_encrypted)            # KMS unwraps it
document = aes_gcm_decrypt(data_key_plain, ciphertext)
del data_key_plain
```

```
   MASTER KEY (in the KMS, never leaves)
        │ encrypts
        ▼
   DATA KEY (random, per-object) ──encrypts──▶ your actual data
```

The master key never leaves the KMS; the per-object data keys are protected *by* it. You get
KMS-grade key protection at bulk-encryption speed ([B09](../track-b/B09-symmetric-encryption.md)).
This is how cloud "encryption at rest" works, and how you should encrypt anything sensitive you
must store reversibly ([B05](../track-b/B05-hashing-vs-encryption.md)) — TOTP secrets
([D12](../track-d/D12-build-totp.md)), third-party refresh tokens ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).

---

## How the application authenticates to the secret manager

A puzzle: the app needs a credential to fetch its secrets — but where does *that* credential
live? If it's in a `.env`, you've just moved the problem ([A10](../track-a/A10-where-secrets-live.md)).

The answer is **workload identity** ([J05](../track-j/J05-workload-identity-spiffe.md),
[F10](../track-f/F10-client-credentials.md)): the platform *attests* what the workload is, and
the secret manager trusts that attestation — **no bootstrap secret to store**:

- **Cloud IAM** — an AWS instance/pod assumes a role; the metadata service provides short-lived
  credentials the platform vouches for. No static key.
- **SPIFFE/SPIRE** ([J05](../track-j/J05-workload-identity-spiffe.md)) — the workload gets a
  short-lived certificate based on platform attestation.
- **Kubernetes service account tokens** federated to the cloud IAM.

This closes the loop: the app proves *what it is* (from where it runs), the secret manager
issues short-lived access, and there is no long-lived secret sitting in a file to be stolen. It
is the same lesson as [F10](../track-f/F10-client-credentials.md) — the best client credential is
no static credential.

---

## Secret sprawl and rotation

Two operational realities:

**Secret sprawl** ([A10](../track-a/A10-where-secrets-live.md)). Secrets multiply — copied into
`.env` files, CI variables, developer laptops, Slack messages, tickets. Every copy is a leak
surface, and you lose track of who holds what. Centralising secrets in one manager (with access
control and audit) is what *un*-sprawls them: there is one authoritative copy, fetched at
runtime, never persisted to disk in the repo.

**Rotation.** Secrets must be rotatable ([I06](I06-key-rotation.md)) — because a secret you
*can't* rotate is a secret you can't recover from when it leaks. A good secret manager supports
versioning and rotation with overlap, so you can roll a secret without an outage (the whole of
[I06](I06-key-rotation.md)). If your architecture makes a secret un-rotatable (hardcoded in a
hundred places, or baked into an image), fix that *before* you need to rotate it under incident
pressure.

---

## The practical hierarchy

Restating [A10](../track-a/A10-where-secrets-live.md)'s ladder as operational guidance:

```
   For a KEY you only USE (signing, encryption):
     → KMS/HSM. Never hold it. Envelope-encrypt bulk data.        ✅✅✅

   For a SECRET VALUE you must POSSESS (DB password, API key):
     → Secret manager, fetched at runtime via workload identity.   ✅✅
     → NOT a committed file, NOT a baked-in image layer.

   Authenticate to the manager via WORKLOAD IDENTITY, not a bootstrap secret.  J05

   Everywhere: no secret in git (scan for it — A10), rotatable by design,
   least-privilege access, and audited.                           H13
```

**Scan continuously** for leaked secrets ([A10](../track-a/A10-where-secrets-live.md)) — gitleaks
/ trufflehog in CI, GitHub push protection — because the ladder only helps for secrets you
*manage*; the ones that slip into a commit bypass all of it.

---

## Terms defined in this chapter

`KMS`, `vault`, `envelope encryption`, `HSM`, `secret sprawl`

---

## What to remember

1. **The best secret is one your app never holds.** A **KMS** performs operations (sign,
   encrypt) without releasing the key.
2. This turns a server compromise from **"take the key forever"** into **"use it while present"**
   — logged, rate-limitable, revocable ([I10](I10-incident-response.md)).
3. **Secret stores return values** you must possess; **KMS returns operations** on keys you
   never possess. Use each for its purpose.
4. **Envelope encryption** ([B10](../track-b/B10-key-distribution-problem.md)) encrypts bulk data
   with a data key that's protected by a master key that never leaves the KMS.
5. **Authenticate to the secret manager via workload identity** ([J05](../track-j/J05-workload-identity-spiffe.md)),
   not a bootstrap secret in a `.env`.
6. **Centralise secrets to fight sprawl**, and design every secret to be **rotatable**
   ([I06](I06-key-rotation.md)) before you need to.
7. **Scan for leaked secrets continuously** — the ladder can't protect what slips into a commit.

---

## Sources

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [AWS KMS](https://docs.aws.amazon.com/kms/) / [GCP KMS](https://cloud.google.com/kms/docs) / [HashiCorp Vault](https://developer.hashicorp.com/vault/docs) documentation
- [NIST SP 800-57 — Key Management](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

---

**Next:** [I06 — Key rotation without downtime: kid, JWKS, overlap windows](I06-key-rotation.md)
