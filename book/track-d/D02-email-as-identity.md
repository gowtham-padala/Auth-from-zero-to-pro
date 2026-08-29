# D02 — Email as identity: verification, plus-addressing, homoglyphs

**Part D · Authentication** · *Builds on [D01](D01-identifiers.md)*
---

## Verification is not optional

An unverified email address is a **claim**, not a fact
([C03](../track-c/C03-the-vocabulary.md)). Anyone can type anyone's address.

Until verified, an email address must not:

- be used to link accounts ([G12](../track-g/G12-account-linking.md))
- receive password resets ([D09](D09-account-recovery.md))
- grant access to anything scoped by domain ([G10](../track-g/G10-home-realm-discovery.md))
- appear as a confirmed identity to other users
- be trusted from an IdP whose `email_verified` claim is `false` or missing

That last one bears repeating: **OIDC has an `email_verified` claim precisely because the
IdP may not have verified it either.** Accepting `email_verified: false` and linking on it
is the same bug with an extra hop.

### Doing it correctly

```
1. Registration → create the account, mark email unverified
2. Generate a token:  secrets.token_urlsafe(32)        (B03: 256 bits)
3. Store SHA256(token) with a 24-hour expiry           (B05: hash it)
4. Email a link containing the RAW token
5. On click: hash the presented token, look it up, check expiry,
   compare in constant time (B16), mark verified, DELETE the token
```

Six properties, each of which is a real bug when missing:

| Property | Missing it means |
|---|---|
| High entropy | Guessable, so anyone verifies anyone's address |
| **Hashed at rest** | A database read gives an attacker live verification links |
| Expiring | An old email forwarded years later still works |
| **Single-use** | The link in an inbox works forever |
| Bound to one account | A token for account A verifies account B |
| Constant-time compare | Timing leaks the token byte by byte |

The **single-use** property is the most commonly missed. Email lives in inboxes, gets
forwarded, gets synced to a departed employee's laptop backup. Delete the token on
redemption.

---

## Canonicalisation: the same mailbox, many strings

The specifications and reality disagree here, and you must pick a position deliberately.

**Formally** ([RFC 5321](https://www.rfc-editor.org/rfc/rfc5321)): the domain is
case-insensitive; the local part is case-*sensitive* and its interpretation belongs to the
receiving server.

**In practice**: essentially no mail provider treats the local part as case-sensitive.
`Alice@` and `alice@` reach the same person everywhere that matters.

### The variations

| Variation | Example | Same mailbox? |
|---|---|---|
| Case | `Alice@example.com` | Yes, in practice |
| Plus-addressing | `alice+shopping@example.com` | **Yes** — Gmail, Fastmail, Outlook, most |
| Gmail dots | `a.l.i.c.e@gmail.com` | **Yes**, on Gmail specifically |
| Googlemail | `alice@googlemail.com` | Yes, aliases `gmail.com` |
| Subaddressing with `-` | `alice-shop@example.com` | Sometimes (Qmail-style) |
| Unicode / homoglyph | `аlice@example.com` (Cyrillic а) | **No — a different address** |

### The decision

```python
def canonicalize(email: str) -> str:
    """A conservative canonical form for UNIQUENESS checks."""
    email = unicodedata.normalize("NFC", email.strip())
    local, _, domain = email.rpartition("@")
    domain = domain.lower()
    local = local.lower()                  # near-universal in practice

    # Provider-specific rules. Apply knowingly, not by default.
    if domain in ("gmail.com", "googlemail.com"):
        local = local.split("+", 1)[0].replace(".", "")
        domain = "gmail.com"

    return f"{local}@{domain}"
```

**Store both.** The address the user typed (for sending mail, and for display), and the
canonical form (for the unique index).

```sql
CREATE TABLE users (
  id                uuid PRIMARY KEY,
  email             text NOT NULL,          -- as typed: alice+shop@gmail.com
  email_canonical   text NOT NULL UNIQUE,   -- for uniqueness: alice@gmail.com
  email_verified_at timestamptz
);
```

### Should you strip plus-addressing?

A genuine trade-off with no universally right answer:

**Strip it** if a free tier is abused by one person creating hundreds of accounts. Fraud
teams generally want this.

**Do not strip it** if you respect that plus-addressing is a legitimate, widely-taught
privacy practice. Users who use it are often your most technical, and blocking it reads as
hostile.

**The middle path, which is usually correct:** allow plus-addressing for registration; use
the canonical form for **abuse detection and rate limiting**, not for hard blocking. You get
the signal without the hostility.

Do not extend Gmail's dot rule to other providers. It is Gmail-specific, and applying it
generally will merge two genuinely different people's accounts.

---

## Homoglyphs

Different Unicode code points that render identically
([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).

```
  a  U+0061  LATIN SMALL LETTER A
  а  U+0430  CYRILLIC SMALL LETTER A       ← visually identical
  ɑ  U+0251  LATIN SMALL LETTER ALPHA
  ａ U+FF41  FULLWIDTH LATIN SMALL LETTER A
```

`аdmin@example.com` with a Cyrillic `а` is a completely different string that looks exactly
like the real one — in support tickets, in approval emails, in an audit log a human is
reading.

Internationalised domain names make it worse. `xn--80ak6aa92e.com` renders as `аpple.com`.
Browsers now show Punycode when a domain mixes scripts, which mitigates the phishing case
but not the *identity confusion* case in your own system.

**Defences:**

1. **Restrict what you accept.** Most services can require the local part to be ASCII. This
   is the simplest effective control, and it is what the majority of large platforms do.
2. **Detect mixed scripts.** Flag any address whose local part mixes Unicode scripts. Almost
   nobody legitimately writes `аlice` with one Cyrillic letter.
3. **Normalise and compare.** Unicode's [UTS #39](https://www.unicode.org/reports/tr39/)
   defines a "skeleton" transformation that maps confusables to a canonical form. Compare
   skeletons to detect near-collisions with existing accounts.
4. **Never show a raw address as the sole identity signal** in a security-relevant UI.

Applies equally to usernames and display names, where impersonation is often the actual
goal.

---

## Validating an address

**Do not write an email regex.** The full grammar in RFC 5322 is famously not regular, and
every "correct" regex you find either rejects valid addresses or accepts invalid ones.

```python
def is_plausible(email: str) -> bool:
    if len(email) > 254:           # RFC 5321 §4.5.3.1
        return False
    if email.count("@") != 1:
        return False
    local, domain = email.split("@")
    if not local or len(local) > 64:
        return False
    if "." not in domain or domain.startswith(".") or domain.endswith("."):
        return False
    if any(c.isspace() for c in email):
        return False
    return True
```

That is the whole of syntactic validation worth doing. Everything else — does the domain
exist, does the mailbox exist, will it accept mail — is answered by **sending an email and
seeing whether someone clicks**. Verification *is* the validation.

Two further points:

- **Do not block "disposable" domains by default.** The lists are always stale, they block
  legitimate privacy-conscious users, and Apple's Hide My Email is on some of them.
  Consider a soft signal instead — limit a free trial, require verification before a
  sensitive action.
- **`example.com`, `test`, `invalid`, and `localhost`** are reserved and will never receive
  mail. Rejecting those specifically is cheap and correct.

---

## Email as a security channel

If you use email for password reset ([D09](D09-account-recovery.md)) or magic links
([D10](D10-magic-links-and-email-otp.md)), you have made a security dependency on:

- The user's mailbox provider
- Every device where that mailbox is open
- Anyone with access to that mailbox
- Whoever controls the domain
- Every mail server on the path, and every scanner that follows links in messages

That last one causes real bugs: **corporate security scanners follow links in emails**,
which consumes single-use tokens before the user clicks. Mitigations: require a `POST` or
a click-through confirmation on the landing page rather than acting on the `GET`, and keep
the window short enough that a re-request is cheap.

**Email is a moderately-trusted channel.** Good enough for verification and recovery.
Not good enough to be the *only* factor for a high-value action
([D18](D18-step-up-auth-and-aal.md)).

Deploy **SPF, DKIM, and DMARC** on your sending domain. Without them, anyone can send mail
that appears to come from you — including a fake password reset. This is table stakes and
routinely missing.

---

## Terms defined in this chapter

`canonicalisation`, `plus-addressing`, `homoglyph`, `Punycode`,
`double-submit verification`

---

## What to remember

1. **An unverified email is a claim, not an identity.** Never link accounts on one.
   Pre-account-takeover is real.
2. Verification tokens: high entropy, **hashed at rest**, expiring, **single-use**, bound
   to one account, constant-time compared.
3. Store the address as typed **and** a canonical form. Unique-index the canonical.
4. Plus-addressing: use it for abuse *signals*, not hard blocks. Gmail's dot rule is
   Gmail-only.
5. **Homoglyphs** make identical-looking, different addresses. Restrict to ASCII, or detect
   mixed scripts.
6. **Do not write an email regex.** Sanity-check the shape, then verify by sending.
7. Email scanners consume single-use links. Do not act on the `GET`.
8. SPF, DKIM, DMARC. Non-negotiable.

---

## Sources

- [RFC 5321 — SMTP](https://www.rfc-editor.org/rfc/rfc5321) §4.5.3.1 (size limits)
- [RFC 5322 — Internet Message Format](https://www.rfc-editor.org/rfc/rfc5322) §3.4.1
- [Unicode UTS #39 — Security Mechanisms](https://www.unicode.org/reports/tr39/) (confusables, skeletons)
- Microsoft Security Response Center, [*Pre-hijacking attacks on web user accounts*](https://arxiv.org/abs/2205.10174) (Sudhodanan & Paverd, 2022)

---

**Next:** [D03 — How to store passwords in 2026](D03-how-to-store-passwords.md)
