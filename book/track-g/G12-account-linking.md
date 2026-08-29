# G12 — Account linking: same human, three identity providers

**Part G · Federated identity & SSO** · *Builds on [G06](G06-claims-vs-scopes-userinfo.md)*
> The unglamorous chapter that saves viewers from a production disaster: two accounts, one
> human, and no way to merge them — or worse, one account, two humans, because of a linking
> bug.

---

## Why it matters

**Direction 1: accidental duplicates.** A user signs up with `alice@example.com` and a
password. Months later they click "Sign in with Google," which returns the same email. Your
app does not recognise them, creates a *second* account, and now Alice has two — with her
documents split across them and no way to merge.

**Direction 2: account takeover.** The dangerous one. Your app links accounts by matching
email. An attacker:

```
1. Registers on your app with victim@example.com (never verifies it — you allow that).
2. The real victim later logs in via "Sign in with Google" as victim@example.com.
3. Your app sees a matching email and LINKS the Google identity to the
   attacker's pre-existing account.
4. The attacker, still holding that account's password, now has access to
   everything the victim does.
```

This is **pre-account-takeover** ([D02](../track-d/D02-email-as-identity.md)), and it is a
documented, exploited class of bug. The naive fix for direction 1 — "match on email" —
*causes* direction 2.

---

## The core rule

> **Identity is `(issuer, subject)`, not email. Email is for matching *candidates*; a
> `verified` email is required to *link*.**

From [C03](../track-c/C03-the-vocabulary.md): `sub` is unique only within an issuer, and it is
stable where email is not. So one human maps to *many* `(iss, sub)` pairs — one per IdP — all
pointing at one local account.

```
   ┌─────────────────────── ONE HUMAN, ONE LOCAL ACCOUNT ────────────────────┐
   │  users.id = u_4471                                                       │
   ├─────────────────────────────────────────────────────────────────────────┤
   │  identities:                                                            │
   │    (google.com,  110169484...)      ← "Sign in with Google"            │
   │    (login.microsoftonline.com, ...) ← "Sign in with Microsoft"        │
   │    (local, alice@example.com)       ← password                        │
   └─────────────────────────────────────────────────────────────────────────┘
```

The schema that makes this correct ([C05](../track-c/C05-build-vs-buy.md),
[D01](../track-d/D01-identifiers.md)):

```sql
CREATE TABLE users (
  id     uuid PRIMARY KEY,
  email  citext UNIQUE,          -- display / contact; NOT the join key for identities
  ...
);

CREATE TABLE identities (
  user_id  uuid REFERENCES users(id),
  issuer   text NOT NULL,        -- 'google.com', 'local', ...
  subject  text NOT NULL,        -- the IdP's `sub`
  email    citext,               -- as asserted by THIS issuer
  verified boolean NOT NULL,     -- did THIS issuer verify it?
  PRIMARY KEY (issuer, subject)  -- the real identity key
);
```

Login looks up `(issuer, subject)` first, exactly, before anything else.

---

## Safe account resolution

```python
def resolve_or_link(issuer: str, subject: str, email: str,
                    email_verified: bool, current_session_user=None):
    # ① Known identity? Log straight in. The common, safe path.
    ident = db.get_identity(issuer, subject)
    if ident:
        return db.get_user(ident.user_id)

    # ② Is the user ALREADY LOGGED IN and explicitly linking? (Safest linking.)
    if current_session_user is not None:
        # They proved control of the existing account by being logged in,
        # and initiated the link deliberately.
        db.create_identity(current_session_user.id, issuer, subject,
                           email, email_verified)
        return current_session_user

    # ③ New identity, not logged in. Consider auto-linking by email —
    #    but ONLY under strict conditions.
    if email_verified:                                    # ★ THIS issuer verified it
        candidate = db.find_user_by_verified_email(email) # ★ and OUR record is verified too
        if candidate:
            # Both sides verified the same email → same human. Safe to link.
            db.create_identity(candidate.id, issuer, subject, email, verified=True)
            notify_user(candidate.id,
                        f"{issuer} sign-in was linked to your account.")   # ★ tell them
            return candidate

    # ④ No safe link. Create a NEW account.
    user = db.create_user(email=email)
    db.create_identity(user.id, issuer, subject, email, email_verified)
    return user
```

The three checks (★) that make auto-linking safe, and each is a real vulnerability without it:

| Guard | Missing it means |
|---|---|
| **The incoming email is `verified` by the issuer** | You link on an email the IdP itself doesn't trust ([G06](G06-claims-vs-scopes-userinfo.md)) |
| **The existing local account's email is also verified** | Pre-account-takeover: attacker's unverified account gets linked ([D02](../track-d/D02-email-as-identity.md)) |
| **Notify the user of the link** | A silent link is an undetectable takeover if the guards fail |

If you cannot satisfy both verification conditions, **do not auto-link.** Either create a
separate account or require the user to log in to the existing one first (path ②) — the
gold-standard linking, because the user *proves* they control both.

---

## The linking UX

Two flows, and the safe one is deliberate:

**Explicit linking (preferred).** From account settings, while logged in:

```
   Connected sign-in methods
     ✓ Password              alice@example.com
     ✓ Google                alice@example.com     [ Disconnect ]
     + Connect Microsoft
     + Connect a passkey
```

The user is authenticated, clicks "Connect Microsoft," completes that IdP's flow, and you link
`(microsoft, sub)` to their current account (path ②). Safe, because control of the existing
account is already proven.

**Implicit linking (careful).** During login, when a new IdP returns a verified email matching
a verified local account (path ③). Only with the guards above, and always with notification.

**Never** link based on an unverified email, and never link silently when the guards are not
met.

---

## Unlinking, and the lockout trap

Users must be able to disconnect a provider — but disconnecting the *last* one is a
self-lockout ([D13](../track-d/D13-recovery-codes.md), [D15](../track-d/D15-build-passkeys.md)):

```python
@app.post("/settings/identities/<issuer>/<subject>/unlink")
@require_recent_authentication()          # step-up — D18
def unlink(issuer, subject):
    remaining = db.count_identities(current_user.id)
    if remaining <= 1:
        return error("You can't remove your only sign-in method. Add another first."), 400
    db.delete_identity(current_user.id, issuer, subject)
    notify_user(current_user.id, f"{issuer} was disconnected from your account.")
    ...
```

- **Never allow removing the last identity** without a replacement.
- **Require step-up** ([D18](../track-d/D18-step-up-auth-and-aal.md)) — an attacker with a
  hijacked session should not be able to strip the real owner's login methods.
- **Notify.**

---

## Merging existing duplicates

When a user *already* has two accounts (the direction-1 failure), merging is genuinely hard
and rarely fully automatable:

- **Which data survives?** Documents, settings, subscriptions, history from both accounts.
- **Conflicts.** Both accounts edited the same resource; both have a subscription.
- **Ownership and sharing.** Merging changes who owns what, which ripples into authorization
  ([Track H](../track-h/H01-where-does-authz-live.md)).

Because it is hard, **prevent duplicates rather than merge them**: the resolution logic above,
applied consistently, is what stops them forming. Where merges are unavoidable, make them
explicit, reversible where possible, audited ([H13](../track-h/H13-audit-logging.md)), and
require the user to authenticate to *both* accounts first — the same "prove control of both"
principle as safe linking.

---

## Terms defined in this chapter

`account linking`, `pre-account-takeover`

---

## What to remember

1. **Identity is `(issuer, subject)`, not email.** One human → many `(iss, sub)` → one local
   account.
2. Store identities in a separate table keyed on `(issuer, subject)`; the user's email is
   display/contact, not the join key.
3. **Match candidates by email; link only on a `verified` email — from both the issuer and
   your own record.** This is what prevents pre-account-takeover.
4. **Safest linking is explicit, while logged in** — the user proves control of the existing
   account.
5. **Auto-linking requires both verification guards *and* a notification.** If you can't meet
   them, create a separate account.
6. **Never allow removing the last sign-in method**; require step-up to unlink; notify.
7. **Prevent duplicates rather than merge them** — merging is hard, lossy, and touches
   authorization.

---

## Sources

- Microsoft Security Response Center, [*Pre-hijacking attacks on web user accounts*](https://arxiv.org/abs/2205.10174) (Sudhodanan & Paverd, 2022)
- [OWASP Authentication Cheat Sheet — Account linking](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed.

---

**Next:** [G13 — Enterprise directories you'll meet: LDAP, Kerberos, Active Directory](G13-enterprise-directories.md)
