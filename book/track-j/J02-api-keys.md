# J02 — API keys: why they persist, and how to do them properly

**Part J · Machine, workload & agent identity** · *Builds on [B13](../track-b/B13-message-authentication-hmac.md), [F10](../track-f/F10-client-credentials.md)*
> Practical and almost never taught: hashed storage, prefixes for scanning, and the `sk_live_`
> convention that lets GitHub secret-scanning find leaks.

---

## Why it matters

A company issues API keys and stores them like this:

```sql
CREATE TABLE api_keys (id, user_id, key TEXT);   -- key stored in plaintext
```

Two things go wrong, at different times:

1. **A database leak** ([I10](../track-i/I10-incident-response.md)) hands the attacker every
   customer's live API key, in plaintext. No cracking needed
   ([B05](../track-b/B05-hashing-vs-encryption.md)).
2. **A customer accidentally commits their key** to a public repo, and it sits there for months
   because the key `k3j2h4g5f6d7s8a9` looks like any other random string — no scanner can
   recognise it ([A10](../track-a/A10-where-secrets-live.md)).

Both are entirely preventable with two techniques that almost no in-house implementation uses:
**hash the key at rest** and **give it a recognisable prefix.** This chapter is API keys done
properly.

---

## Why API keys persist despite OAuth

OAuth exists ([Track F](../track-f/F01-the-problem-oauth-solves.md)), yet every API provider —
Stripe, OpenAI, GitHub, AWS — still offers API keys. They persist because they're **simple**:

- No flow, no redirects, no token endpoint ([F03](../track-f/F03-authorization-code-flow.md)) —
  one string in a header.
- No authorization server to run ([F14](../track-f/F14-build-an-authorization-server.md)).
- A developer can `curl` an API in ten seconds.

The trade ([F10](../track-f/F10-client-credentials.md)): API keys are **long-lived bearer
secrets** ([C03](../track-c/C03-the-vocabulary.md)) — possession is access, and they don't expire
on their own. Client credentials ([F10](../track-f/F10-client-credentials.md)) are more secure
(short-lived tokens, the long secret goes only to the AS) but need infrastructure. So: **client
credentials when you have an authorization server; API keys done properly when you want
simplicity.** Both are legitimate; the mistake is doing API keys *badly*.

---

## API keys done properly

### 1. Generate: CSPRNG + a recognisable prefix

```python
import secrets

def generate_api_key(environment="live") -> tuple[str, str]:
    random_part = secrets.token_urlsafe(32)              # 256 bits — B03
    prefix = f"sk_{environment}_"                        # ← the scannable convention
    full_key = f"{prefix}{random_part}"
    key_id = full_key[:12]                               # a lookup hint (prefix + a few chars)
    return full_key, key_id
    # sk_live_8f14e45fceea167a5a36dedd4bea2543...
```

The prefix is not decoration — it's **the single most useful operational feature of a modern API
key**:

- **`sk_`** = "secret key" (vs `pk_`, a publishable key that's safe to expose —
  [A10](../track-a/A10-where-secrets-live.md)). It tells a developer at a glance which keys are
  dangerous.
- **`live`/`test`** = environment, so a test key can't accidentally hit production.
- **The recognisable pattern is what makes secret-scanning work.** GitHub, GitLab, and scanners
  like gitleaks/trufflehog ([A10](../track-a/A10-where-secrets-live.md)) have *registered
  patterns* for `sk_live_...`. When a customer commits one to a public repo, the scanner
  recognises it, and GitHub's **push protection** can *block the push* or alert the provider to
  auto-revoke it. A random string with no prefix is invisible to all of this.

**Register your key format** with GitHub's secret-scanning partner program if you're a provider —
it turns "a leaked key sits exposed for months" into "the leak is caught in seconds."

### 2. Store: hash it, show it once

```python
import hashlib

def create_key(user_id, scopes):
    full_key, key_id = generate_api_key()
    db.insert_api_key(
        key_id=key_id,                                   # for lookup + display ("sk_live_8f14...")
        key_hash=hashlib.sha256(full_key.encode()).digest(),   # ← store the HASH  B05
        user_id=user_id,
        scopes=scopes,                                   # least privilege  H01
        created_at=now(),
        last_used_at=None,
    )
    return full_key      # shown ONCE — never retrievable again
```

Two rules, both from earlier chapters:

**Hash the key** ([B05](../track-b/B05-hashing-vs-encryption.md)). You never need the key's value
back — you only need to check whether a presented key matches. So store `SHA256(key)`, and a
database leak yields uncrackable digests instead of live keys. Note: **SHA-256, not Argon2id** —
the key has 256 bits of entropy, so there's nothing to brute-force
([B07](../track-b/B07-fast-hashes-wrong-for-passwords.md), [J06](J06-signing-webhooks.md)); a slow
hash would add latency to every API call for no benefit.

**Show it once.** After creation, you *can't* show it again (you only stored the hash) — and that's
correct. Every good provider does this: "copy this now, you won't see it again." A provider that
can email you your key later is storing it reversibly ([B05](../track-b/B05-hashing-vs-encryption.md)).

### 3. Verify: lookup by prefix, constant-time compare

```python
def verify_api_key(presented: str) -> ApiKey | None:
    key_id = presented[:12]                              # narrow the lookup by prefix
    record = db.get_api_key_by_id(key_id)
    if record is None:
        return None
    presented_hash = hashlib.sha256(presented.encode()).digest()
    if not hmac.compare_digest(presented_hash, record.key_hash):   # constant-time — B16
        return None
    db.touch_last_used(record.id)                        # for orphan detection — I03
    return record
```

The `key_id` prefix gives you an indexed lookup without scanning the whole table, and the
**constant-time comparison** ([B16](../track-b/B16-timing-attacks.md)) prevents a timing side
channel from revealing the hash. (An indexed lookup on the *stored hash* would also work and
avoids the comparison entirely — either is fine.)

---

## The operational essentials

An API key isn't done at "generate and verify." The lifecycle ([I01](../track-i/I01-identity-lifecycle.md)):

**Scopes — least privilege** ([H01](../track-h/H01-where-does-authz-live.md),
[F07](../track-f/F07-access-refresh-scopes.md)). A key for reading invoices should not be able to
issue refunds. Let users create narrowly-scoped keys, and default to minimal scope. An
over-scoped key is a bigger blast radius when it leaks ([I10](../track-i/I10-incident-response.md)).

**Rotation** ([I06](../track-i/I06-key-rotation.md)). Users must be able to roll a key without
downtime — support *multiple active keys* per account so they can create the new one, migrate,
then revoke the old one (the overlap pattern — [I06](../track-i/I06-key-rotation.md)).

**Revocation** ([E11](../track-e/E11-revocation.md)). Instant — delete the row. This is why keys
are stored server-side and looked up: unlike a stateless token, revoking a key is immediate.

**Expiry.** Offer optional expiry dates. A key with no expiry lives forever, which is the leaver
problem ([I03](../track-i/I03-deprovisioning.md)) for machines.

**Last-used tracking** (the `touch_last_used` above). This is what catches the orphaned-key
problem ([I01](../track-i/I01-identity-lifecycle.md), [I03](../track-i/I03-deprovisioning.md)): a
key unused for 90 days is flagged and can be auto-disabled — an unused, long-lived, high-privilege
key is exactly what an attacker looks for.

**Rate limiting per key** ([D08](../track-d/D08-rate-limiting-and-stuffing.md)) — so a compromised
key can't be used to hammer your API, and so you can detect abuse.

**Audit** ([H13](../track-h/H13-audit-logging.md)) — creation, use, rotation, revocation, all
attributable to the key and its owner.

---

## When it leaks (and it will)

API keys leak — committed to repos, pasted in tickets, logged ([I08](../track-i/I08-observability.md)).
Design for it ([I10](../track-i/I10-incident-response.md)):

- **The scannable prefix** means many leaks are caught automatically (above).
- **Secret-scanning partnership** — providers like Stripe receive alerts from GitHub when their
  keys are found in public repos, and **auto-revoke** them before the customer even notices. This
  is only possible *because* of the recognisable prefix.
- **Anomaly detection** ([I09](../track-i/I09-detecting-account-takeover.md)) — a key suddenly used
  from a new location or at high volume.
- **Instant revocation + rotation** ([E11](../track-e/E11-revocation.md), [I06](../track-i/I06-key-rotation.md))
  when a leak is confirmed.

The `sk_live_` convention ties the whole chapter together: it's a UX feature (developers know
which keys are dangerous), a security feature (scanners find leaks), and an incident-response
feature (auto-revocation) — all from a prefix.

---

## Terms defined in this chapter

`API key`, `key prefix`, `secret scanning`

---

## What to remember

1. **API keys persist because they're simple** — one header string, no flow. The trade: long-lived
   bearer secrets. Use **client credentials** when you have an AS; **API keys done properly** for
   simplicity.
2. **Give keys a recognisable prefix** (`sk_live_...`) — it's a UX signal *and* what makes
   secret-scanning and auto-revocation work.
3. **Hash the key at rest** (SHA-256 — high entropy, no slow hash needed) and **show it once.** A
   provider that can email you your key stores it wrong.
4. **Verify with a constant-time compare** ([B16](../track-b/B16-timing-attacks.md)); look up by
   prefix.
5. **Scope keys to least privilege**, support **rotation** (multiple active keys), **instant
   revocation**, optional **expiry**, and **last-used tracking** to catch orphans.
6. **Register your key format** with secret-scanning programs — it turns a months-long exposure
   into a seconds-long one.
7. **Design for leaks:** scannable prefix + partnership auto-revocation + anomaly detection +
   instant revocation.

---

## Sources

- [Stripe: API keys and secret scanning](https://docs.stripe.com/keys) — the `sk_live_`/`pk_live_` model
- [GitHub: Secret scanning partner program](https://docs.github.com/en/code-security/secret-scanning/secret-scanning-partner-program)
- [OWASP: API Key management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

---

**Next:** [J03 — Service accounts and their failure modes](J03-service-accounts.md)
