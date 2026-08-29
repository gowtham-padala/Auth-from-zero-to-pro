# D01 — Identifiers: what should a user actually log in with?

**Part D · Authentication** · *Builds on [C03](../track-c/C03-the-vocabulary.md)*
---

## Two jobs, one field

The mistake at the root of most identifier problems is using one value for two purposes:

| | **Login identifier** | **Internal identity key** |
|---|---|---|
| Purpose | What the human types | What your database joins on |
| Changes? | **Often** | **Never** |
| Chosen by | The user | You |
| Visible? | Yes | Ideally not |
| Example | `alice@example.com` | `user_01H8XK...` |

> **Rule: your primary key is an opaque, immutable value you generate. The login
> identifier is a mutable attribute *pointing at* it.**

```sql
CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),   -- never changes
  email       citext UNIQUE,                                -- can change
  username    citext UNIQUE,                                -- can change
  created_at  timestamptz NOT NULL DEFAULT now()
);
```

Every foreign key in your application points at `users.id`. Now an email change is one
`UPDATE`, not a migration. And an email *reassignment* is caught, because the new person
gets a new `id`.

This is the same reasoning as `(iss, sub)` in [C03](../track-c/C03-the-vocabulary.md):
key on the stable thing, display the friendly thing.

---

## The candidates

### Email

**For:** universal, verifiable, doubles as your recovery channel, no separate field to
choose.

**Against:**

- **Changes.** People switch jobs and providers.
- **Reassignable.** Corporate addresses especially — reassigned to the next hire with that name.
- **Not owned by the user.** `sarah@company.com` belongs to the company. So does everything
  they did with it.
- **Enumerable.** "Is this email registered?" leaks membership
  ([D07](D07-user-enumeration.md)).
- **Ambiguous.** Case, plus-addressing, dots, homoglyphs — all of
  [D02](D02-email-as-identity.md).
- **Blocks multiple accounts.** One person, personal and work accounts, same address? Not
  possible.

**Verdict:** the correct default for consumer products. Use it as a *login identifier*, and
know exactly what it does not guarantee.

### Username

**For:** chosen by the user, stable if you want it to be, no leak of a contact address,
allows several accounts per person, works as a public handle.

**Against:**

- Another thing to remember, and people forget them.
- Contested namespace — every good one is taken.
- **Impersonation via homoglyphs.** `paypa1_support` and `pаypal_support` (Cyrillic а).
- You still need email for recovery, so it is an *extra* field, not a replacement.

**Verdict:** right when the handle is part of the product (social, gaming, developer
tools). Otherwise it is a second thing to lose.

### Phone number

**For:** high-value in mobile-first markets, harder to create in bulk, doubles as a channel.

**Against:**

- **Recycled aggressively.** Carriers reassign disconnected numbers in months.
- **SIM swap** is a real and common attack ([D11](D11-sms-second-factor.md)).
- Formatting is genuinely hard — country codes, leading zeros, E.164.
- Costs money to verify, and SMS delivery is unreliable internationally.

**Verdict:** viable where it is the market norm. Never as the *only* recovery channel.

### Federated identity only

Let Google/Microsoft/Apple own the identifier ([G01](../track-g/G01-sign-in-with-google.md)).

**For:** no passwords, no recovery flow, the IdP's MFA, enterprise-ready.

**Against:**

- Users without an account at your chosen providers cannot sign up.
- Losing the IdP account loses your account.
- You are dependent on their availability and their policies.
- **Account linking** becomes a hard requirement ([G12](../track-g/G12-account-linking.md) in
  Track G).

**Verdict:** excellent for B2B. Risky as the sole option for consumer products.

### Passkey-first

The user's identifier *is* their credential; a discoverable credential lets them log in
with no username at all ([D15](D15-build-passkeys.md)).

**For:** the best security available, no password, no phishing.

**Against:** account recovery becomes the entire design problem
([D13](D13-recovery-codes.md)), and support burden is real when someone loses every device.

**Verdict:** the direction the field is going. Offer it; do not yet make it the only path.

---

## Uniqueness is harder than it looks

Whatever you choose, "unique" needs defining. Three traps:

**1. Case.** `Alice@Example.com` and `alice@example.com` are the same mailbox in every
practical mail system. Two rows in a case-sensitive column.

Fix: store lowercase, or use a case-insensitive type (`citext` in Postgres) with a unique
index. Do it at the **database** level, not in application code — application-level checks
lose races.

**2. The check-then-insert race.**

```python
if not User.query.filter_by(email=email).first():   # ❌ two requests both pass here
    db.add(User(email=email))
    db.commit()
```

Two simultaneous registrations both see "no existing user," and both insert. Now you have
duplicate accounts and a data integrity problem no application logic can resolve after the
fact.

Fix: a **database unique constraint**, and handle the violation:

```python
try:
    db.add(User(email=normalize(email)))
    db.commit()
except IntegrityError:
    return generic_registration_response()     # D07: do not reveal it exists
```

The constraint is the only correct place for uniqueness. Everything else is advisory.

**3. Normalisation.** `café@example.com` in NFC and NFD are different byte sequences
([B01](../track-b/B01-bits-bytes-text-as-numbers.md)). Normalise to NFC before storing and
before comparing. Same rule as passwords.

---

## Changing an identifier

Email changes are routine and are a genuine account-takeover vector if done casually.

```
1. User requests change to new@example.com
2. Send a verification link to the NEW address
3. Send a NOTIFICATION to the OLD address        ← the important one
   "Your email is being changed to n***@example.com.
    If this wasn't you, click here."
4. Only on clicking the link in the new address: change it
5. Optionally require the current password or a second factor
6. Write an audit record  (H13)
```

**Step 3 is the one that gets skipped, and it is the one that catches the attack.** An
attacker with a hijacked session changes the email, then triggers a password reset to their
own address, and now owns the account permanently. The notification to the old address is
often the only signal the real owner ever gets.

Same shape for phone numbers.

And: **do not free the old identifier immediately.** Hold it for a cooling-off period, so a
user who reverts the change gets their account back rather than colliding with someone who
grabbed it.

---

## Choosing, in practice

| Product | Login identifier | Notes |
|---|---|---|
| Consumer SaaS | **Email** | Plus social login. Passkeys as an upgrade. |
| B2B SaaS | **Email**, plus SSO per tenant | Enterprise customers will require SSO ([G09](../track-g/G09-multi-tenant-sso.md)) |
| Social / community | **Username**, email for recovery | The handle is product surface |
| Developer tool | **Email** or GitHub SSO | GitHub identity is often the natural one |
| Mobile-first, emerging markets | **Phone** | Plus email as a backup channel |
| Internal tools | **SSO only** | No local accounts at all. Simplest, safest. |

The last row is worth calling out. For internal applications, **do not build login.** Put
them behind your existing corporate IdP. No passwords, no reset flow, no orphaned accounts,
and deprovisioning works automatically ([I03](../track-i/I03-deprovisioning.md)). This is
the cheapest correct answer in the whole book, and teams still build local admin logins.

---

## Terms defined in this chapter

`username`, `account`, `identifier` (from C03, applied here)

---

## What to remember

1. **Separate the login identifier from the primary key.** The key is opaque and immutable;
   the identifier is a mutable attribute.
2. **Email addresses are reassigned.** Corporate ones especially. Key on your own ID or
   people inherit accounts.
3. Enforce uniqueness with a **database constraint**, not an application check. The race is
   real.
4. Normalise: lowercase, NFC, at the boundary. Once, consistently.
5. On email change: **notify the old address.** That is the control that catches takeover.
6. **Internal tools should have no login at all.** Put them behind SSO.

---

## Sources

- [OWASP Authentication Cheat Sheet — Usernames](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.1
- [RFC 5321 §2.4](https://www.rfc-editor.org/rfc/rfc5321#section-2.4) — the local part is case-sensitive *in principle*

---

**Next:** [D02 — Email as identity: verification, plus-addressing, homoglyphs](D02-email-as-identity.md)
