# D04 — Password policies that help, and the ones NIST removed

**Part D · Authentication** · *Builds on [D03](D03-how-to-store-passwords.md)*
---

## Why it matters

A company enforces the classic policy: minimum 8 characters, one uppercase, one lowercase,
one number, one symbol, changed every 90 days, no reuse of the last 5.

Their users' passwords are:

```
Summer2025!
Summer2026!
Winter2026!
Company1!
Password1!
```

Every one satisfies the policy. Every one is in the first ten thousand entries of any
cracking wordlist, because cracking tools model **exactly these rules** — capitalise the
first letter, append a number and a punctuation mark, iterate the season and year.

The policy did not produce strong passwords. It produced *predictable* passwords, and told
the attacker the pattern to search.

This is why NIST removed the rules.

---

## What NIST removed, and why

**SP 800-63B-4**, finalised 31 July 2025, superseding the previous revision on 1 August
2025. The changes are the accumulated result of two decades of measuring what people
actually do.

### ❌ Composition rules — removed

> *"Verifiers and CSPs SHALL NOT impose other composition rules (e.g., requiring mixtures
> of different character types) for passwords."*

**Why:** they do not increase entropy in practice, they increase predictability, and they
push users toward patterns cracking tools already model. `P@ssw0rd!` satisfies every
composition rule and is in every wordlist.

Worse, they cause users to write passwords down, reuse them, and hate you.

### ❌ Periodic expiry — removed

> *"SHALL NOT require users to change passwords periodically. However, verifiers SHALL
> force a change if there is evidence of compromise of the authenticator."*

**Why:** forced rotation produces incremental passwords — `Summer2025!` → `Summer2026!` —
which is worse than a stable strong one. It also makes users *less* likely to choose
something memorable and strong, because they know they will discard it in 90 days.

And the security logic never worked. If a password is compromised, 90 days of attacker
access is not an acceptable window. If it is not compromised, rotation achieves nothing.

**This is the single most-resisted change in the document**, usually because an auditor's
checklist still says otherwise. The correct response is to point at the standard.

### ❌ Password hints — removed

Hints are visible to anyone who reaches the login page. Adobe's 2013 breach was cracked
largely *through the hints*, which were stored unencrypted alongside the passwords
([B05](../track-b/B05-hashing-vs-encryption.md)).

### ❌ Knowledge-based questions — removed

> *"Verifiers SHALL NOT prompt subscribers to use knowledge-based authentication."*

Mother's maiden name, first school, first pet — all findable on social media, in public
records, or in a previous breach of another site. They are not secrets; they are a weaker
second password that cannot be changed.

Full treatment in [D09](D09-account-recovery.md), where they do the most damage.

---

## What NIST requires instead

### ✅ Length

| Rule | Value |
|---|---|
| Minimum | **8 characters** |
| Minimum when the password is the **only** authenticator | **15 characters** |
| Maximum you must accept | **at least 64** |

That 15-character rule is new in revision 4 and is the most consequential requirement in
the document. The logic: with MFA, a password is one of several factors and 8 is tolerable.
Without MFA, it is the *entire* defence and needs real strength.

**Never impose a low maximum.** A `maxlength="16"` on a password field caps entropy and
breaks password managers. Accept 64+; you are hashing it, so length costs you nothing —
except with bcrypt, whose 72-byte limit is a real constraint
([D03](D03-how-to-store-passwords.md)).

### ✅ Accept everything

All printing ASCII, spaces, and Unicode. Normalise to NFC before hashing
([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).

Rejecting characters is a signal that you are storing the password somewhere you should not
be, or building a SQL query by concatenation. Users notice.

### ✅ Allow paste

Blocking paste breaks password managers, and password managers are the single most
effective consumer security intervention available. NIST calls it out explicitly. Do not
add `onpaste="return false"`.

### ✅ Check against a blocklist

> *"When processing requests to establish and change passwords, verifiers SHALL compare
> the prospective secrets against a blocklist."*

**This is the highest-value password control there is**, and it is the one most often
missing.

The list should include:

- Passwords from known breach corpora
- Common dictionary words
- Repetitive or sequential characters (`aaaaaa`, `123456`)
- **Context-specific words** — your service name, the username, the email local part, the
  company name

### ✅ Rate limiting

Limit failed attempts. [D08](D08-rate-limiting-and-stuffing.md).

### ✅ Rotate only on evidence of compromise

Which requires *having* evidence — breach monitoring, anomaly detection
([I09](../track-i/I09-detecting-account-takeover.md)).

---

## Checking against breaches, privately

The [Have I Been Pwned](https://haveibeenpwned.com/) Pwned Passwords API uses **k-anonymity**:
you send the first 5 hex characters of the SHA-1 hash and receive every matching suffix.
**The full hash never leaves your server**, and the API cannot determine which password you
checked.

```python
import hashlib, requests

def breach_count(password: str) -> int:
    """Returns how many times this password appears in known breaches."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true"},   # pads the response, defeating size analysis
        timeout=3,
    )
    resp.raise_for_status()

    for line in resp.text.splitlines():
        hash_suffix, _, count = line.partition(":")
        if hash_suffix == suffix:
            return int(count)
    return 0

def validate_password(password: str, email: str, username: str) -> list[str]:
    errors = []

    if len(password) < 8:
        errors.append("Must be at least 8 characters.")
    if len(password.encode("utf-8")) > 128:
        errors.append("Must be at most 128 characters.")

    # Context-specific blocklist
    local = email.split("@")[0].lower()
    lowered = password.lower()
    for term in (local, username.lower(), "example", "acme"):
        if term and len(term) > 3 and term in lowered:
            errors.append("Must not contain your name, email, or our service name.")
            break

    try:
        n = breach_count(password)
        if n > 0:
            errors.append(
                f"This password has appeared in {n:,} known data breaches. "
                "Please choose a different one."
            )
    except requests.RequestException:
        pass    # ← fail OPEN here. Availability of a third party must not block signup.

    return errors
```

Three deliberate decisions in that code:

**`Add-Padding: true`** stops an observer inferring which prefix you queried from the
response size ([B17](../track-b/B17-what-https-protects.md) — traffic analysis).

**Fail open on network error.** This is the rare case where failing open is right: a
third-party outage must not block registration. Log it, alert on a sustained failure rate,
and continue. (Contrast [H02](../track-h/H02-the-enforcement-point.md), where authorization
must always fail *closed*.)

**Tell the user the count.** *"This appeared in 23,547 breaches"* is dramatically more
persuasive than *"password too weak."* It converts an arbitrary rule into a fact about the
world.

### Self-hosting

If you cannot call an external API, HIBP publishes the full list for download (~40 GB,
~1 billion hashes). Load into a bloom filter or a database with an index on the prefix.
Refresh quarterly.

---

## The strength meter question

**Use [zxcvbn](https://github.com/dropbox/zxcvbn)** (or the maintained
`zxcvbn-ts` fork), not a rule-based meter.

Rule-based meters score `P@ssw0rd1!` as strong (four character classes, ten characters) and
`correct horse battery staple` as weak (no numbers, no symbols). Both judgements are
backwards.

zxcvbn estimates the number of *guesses* required, using dictionaries, common patterns,
keyboard walks, l33t substitutions, dates, and repeats. It scores what an attacker actually
does.

Use it **as guidance**, not as a hard gate. A blocklist check is a gate; a strength meter is
feedback. Combining them:

```
Hard requirements (block):     length ≥ 8, not in breach corpus, no context terms
Soft guidance (show, allow):   zxcvbn score, with the specific reason it is weak
```

---

## What actually helps, ranked

Ordered by real reduction in account takeover per unit of effort:

| # | Control | Effect |
|---|---|---|
| **1** | **Breach corpus blocklist** | Blocks the attack that actually succeeds — credential stuffing |
| **2** | **Support passkeys** | Removes the password entirely ([D14](D14-webauthn-and-passkeys-concepts.md)) |
| **3** | **Offer and encourage MFA** | Survives a compromised password ([D12](D12-build-totp.md)) |
| **4** | **Rate limiting and stuffing defence** | Bounds online guessing ([D08](D08-rate-limiting-and-stuffing.md)) |
| **5** | **Allow long passwords and paste** | Makes password managers work |
| **6** | **Argon2id storage** | Bounds the damage of a breach ([D03](D03-how-to-store-passwords.md)) |
| **7** | **Detect takeover signals** | Catches what gets through ([I09](../track-i/I09-detecting-account-takeover.md)) |
| — | Composition rules | **Negative** |
| — | Periodic expiry | **Negative** |
| — | Security questions | **Negative** |

The last three are not merely useless. They actively reduce security while consuming the
user's patience — which is a limited resource you will want later, when you ask them to
enrol a second factor.

---

## Terms defined in this chapter

`password spraying`, `blocklist (passwords)`, `composition rules`

---

## What to remember

1. **NIST SP 800-63B-4 (July 2025) removed composition rules, periodic expiry, hints, and
   security questions.** They make passwords more predictable, not less.
2. **8 characters minimum; 15 if the password is the only factor.** Accept at least 64.
3. **Allow paste.** Password managers are the best consumer security intervention there is.
4. **The breach blocklist is the highest-value control.** HIBP's k-anonymity API keeps it
   private. Fail open on network error.
5. Tell the user the breach count. It persuades where "too weak" does not.
6. zxcvbn for guidance; the blocklist for gating.
7. If an auditor demands 90-day rotation, point at the standard.

---

## Sources

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.1.1 — the normative source for every claim in this chapter
- [Have I Been Pwned — Pwned Passwords API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [zxcvbn: Low-Budget Password Strength Estimation](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler) (Wheeler, USENIX 2016)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

**Next:** [D05 — Build a login, part 1: registration](D05-build-login-part-1-registration.md)
