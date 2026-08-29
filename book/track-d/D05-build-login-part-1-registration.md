# D05 — Build a login, part 1: registration

**Part D · Authentication** · *Builds on [D03](D03-how-to-store-passwords.md), [A06](../track-a/A06-cookies.md)*
---

## Why it matters

A registration endpoint, written the obvious way:

```python
@app.post("/register")
def register():
    user = User(email=request.form["email"],
                password_hash=ph.hash(request.form["password"]),
                is_admin=request.form.get("is_admin", False))   # ← from the form
    db.save(user)
    return redirect("/dashboard")
```

```bash
curl -X POST https://app.example.com/register \
  -d 'email=attacker@evil.com&password=hunter2&is_admin=true'
```

The attacker is an administrator, thirty seconds after your product launched.

This is **mass assignment** ([H14](../track-h/H14-attack-your-own-authorization.md)) — the
endpoint bound request fields directly to model attributes, including one that was never
meant to be user-controlled. The frontend form has no `is_admin` field, which is why nobody
noticed. The frontend is not the client ([A07](../track-a/A07-client-vs-server.md)).

We are going to build this properly.

---

## What registration actually has to do

More than "insert a row." Nine things:

1. Validate the input — **allowlist**, never denylist
2. Canonicalise the email ([D02](D02-email-as-identity.md))
3. Check the password against the breach corpus ([D04](D04-password-policies.md))
4. Hash the password with Argon2id ([D03](D03-how-to-store-passwords.md))
5. Insert, relying on a **database unique constraint** ([D01](D01-identifiers.md))
6. Respond **identically** whether or not the account existed
   ([D07](D07-user-enumeration.md))
7. Send a verification email with a single-use, hashed, expiring token
8. Rate limit ([D08](D08-rate-limiting-and-stuffing.md))
9. Do **not** log the user in yet

Item 6 is the one that separates a competent implementation from a naive one, and item 9 is
the one people argue about.

---

## The schema

```sql
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email              text        NOT NULL,          -- as typed
  email_canonical    citext      NOT NULL UNIQUE,   -- for uniqueness — D02
  password_hash      text        NOT NULL,          -- the whole PHC string — D03
  email_verified_at  timestamptz,
  is_admin           boolean     NOT NULL DEFAULT false,   -- never settable by a form
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_verification_tokens (
  token_hash  bytea       PRIMARY KEY,             -- SHA-256 of the token — B05
  user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON email_verification_tokens (user_id);
```

Four decisions in that schema, each of which is a chapter:

- **`UNIQUE` on `email_canonical`.** The only correct place to enforce uniqueness — an
  application check loses the race ([D01](D01-identifiers.md)).
- **`token_hash`, not `token`.** A read-only SQL injection against this table would
  otherwise hand over live verification links ([B05](../track-b/B05-hashing-vs-encryption.md)).
- **`is_admin` has a `DEFAULT false`** and appears in no form handler.
- **`ON DELETE CASCADE`** so deleting a user takes their tokens with them
  ([I03](../track-i/I03-deprovisioning.md)).

---

## The handler

```python
from dataclasses import dataclass
import secrets, hashlib, hmac, unicodedata
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher

ph = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)
VERIFICATION_TTL = timedelta(hours=24)

# 1. An explicit input type. This is the allowlist.
@dataclass(frozen=True)
class RegistrationInput:
    email: str
    password: str

    @classmethod
    def parse(cls, form) -> "RegistrationInput":
        # Only these two fields exist. `is_admin` cannot get through
        # because there is nowhere for it to go.
        return cls(email=form["email"].strip(), password=form["password"])

@app.post("/register")
@rate_limit(key=lambda: client_ip(), limit="5/hour")          # D08
def register():
    try:
        data = RegistrationInput.parse(request.form)
    except KeyError:
        return render("register.html", error="Email and password are required."), 400

    # 2. Validate
    errors = []
    if not is_plausible_email(data.email):                     # D02
        errors.append("Enter a valid email address.")
    errors += validate_password(data.password, data.email, "")  # D04
    if errors:
        return render("register.html", errors=errors), 400

    canonical = canonicalize(data.email)                       # D02
    password  = unicodedata.normalize("NFC", data.password)    # B01

    # 3. Insert, letting the DATABASE decide uniqueness.
    user = None
    try:
        with db.transaction():
            user = db.insert_user(
                email=data.email,
                email_canonical=canonical,
                password_hash=ph.hash(password),               # D03
                # is_admin is not mentioned. It cannot be set.
            )
    except UniqueViolation:
        user = None            # the account already exists — we say nothing

    # 4. Side effects, outside the transaction
    if user is not None:
        token = secrets.token_urlsafe(32)                      # B03 — 256 bits
        db.insert_verification_token(
            token_hash=hashlib.sha256(token.encode()).digest(),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + VERIFICATION_TTL,
        )
        send_verification_email(data.email, token)
    else:
        # The address is already registered. Tell THAT person, not the
        # person who just submitted the form.
        send_account_exists_email(canonical)

    # 5. The SAME response either way.  D07.
    return render("check-your-email.html", email=data.email), 200
```

---

## The three decisions worth defending

### 1. Identical responses, always

Both branches render `check-your-email.html`. The person filling in the form learns
**nothing** about whether that address is registered.

Without this, `/register` is a membership oracle. Submit a list of ten thousand addresses,
keep the ones that say "already registered," and you have a verified user list — valuable
for spear-phishing, and sometimes valuable in itself ("who has an account on this
dating/medical/political site?").

The nice property of this design: the person who *does* need to know still finds out, by
email. They get *"someone tried to register with your address — if it was you, here's a
login link; if not, ignore this."* Which is also a takeover warning.

Full treatment in [D07](D07-user-enumeration.md), including the timing side.

### 2. Do not log them in yet

Tempting for conversion metrics. Two reasons not to:

- **An unverified email is not an identity** ([D02](D02-email-as-identity.md)). Session
  before verification means you have a logged-in user whose identity is unconfirmed.
- **Spam and abuse.** Free-tier resources granted before verification get consumed by bots.

The pragmatic middle ground, used by many products: create the session, but keep the
account in a limited state until verification — can browse, cannot invite, cannot share
externally, cannot use the API. Verification unlocks it. Good conversion, contained abuse.

Whatever you choose, **never** let an unverified account be linked to by SSO
([G12](../track-g/G12-account-linking.md)).

### 3. The unique constraint is the check

```python
# ❌ Two concurrent requests both pass this.
if User.query.filter_by(email_canonical=canonical).first():
    return error("Already registered")
db.add(User(...))

# ✅ The database arbitrates.
try:
    db.insert_user(...)
except UniqueViolation:
    ...
```

Application-level checks are advisory. The constraint is the fact.

---

## Verification

```python
@app.get("/verify/<token>")
@rate_limit(key=lambda: client_ip(), limit="20/hour")
def verify_email(token: str):
    # Look up by HASH. We never stored the token itself.
    token_hash = hashlib.sha256(token.encode()).digest()

    with db.transaction():
        # DELETE ... RETURNING makes redemption atomic and single-use:
        # a concurrent second request finds nothing.
        row = db.delete_verification_token_returning(token_hash)

        if row is None or row.expires_at < datetime.now(timezone.utc):
            return render("verify-failed.html"), 400

        db.mark_email_verified(row.user_id)
        db.delete_all_verification_tokens_for(row.user_id)   # invalidate siblings

    return render("verified.html")
```

Note `DELETE ... RETURNING` inside the transaction. Single-use has to be **atomic**, or two
simultaneous clicks — which happens, because email clients prefetch links — both succeed.

### `POST`, not `GET`

Corporate mail scanners follow links in email ([D02](D02-email-as-identity.md)). A `GET`
that consumes the token means the user clicks and finds it already used.

The fix: the link lands on a page with a button, and the button `POST`s. Slightly more
friction, dramatically fewer support tickets. Same reasoning applies to password reset
links ([D09](D09-account-recovery.md)).

---

## Rate limiting registration

Three keys, three different abuses:

| Key | Limit | Stops |
|---|---|---|
| IP address | 5/hour | Bulk account creation |
| Email domain | 100/hour | One compromised domain flooding you |
| Global | Whatever your mail provider allows | Being used as a spam relay |

That third one matters more than people expect. **Your registration endpoint sends email to
an address the attacker chose.** Without a global cap you are a free, reputable-domain spam
relay, and your sending reputation is destroyed within a day.

Add a CAPTCHA (or a privacy-preserving alternative like Cloudflare Turnstile / Apple's
Private Access Tokens) if abuse is real. Not by default — it costs conversion and
accessibility.

---

## The checklist

```
✅  Explicit input type — no mass assignment
✅  Email canonicalised, uniqueness enforced by a DB constraint
✅  Password checked against the breach corpus
✅  Argon2id, salt from the library, whole PHC string stored
✅  Identical response whether or not the account exists
✅  Verification token: 256-bit, hashed at rest, 24h expiry, single-use, atomic
✅  Notification email to the address on a duplicate attempt
✅  Rate limited by IP, by domain, and globally
✅  Nothing sensitive logged (no password, no token)
✅  Email verified before the account is trusted as an identity
```

Repo tag `ep-D05-registration` has all of it, with tests.

---

## What to remember

1. **Parse into an explicit type.** Mass assignment is prevented by there being nowhere for
   the extra field to go.
2. Enforce uniqueness with a **database constraint**, and catch the violation.
3. **Respond identically** whether or not the account existed. Tell the real owner by
   email.
4. Verification tokens: high entropy, **hashed at rest**, expiring, **atomically
   single-use**, bound to one account.
5. Land the link on a page with a button. Mail scanners follow `GET`s.
6. Rate limit by IP, by domain, **and globally** — you are sending mail to attacker-chosen
   addresses.
7. Do not treat an unverified email as an identity.

---

## Sources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [The Copenhagen Book — Email verification](https://thecopenhagenbook.com/email-verification)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

---

**Next:** [D06 — Build a login, part 2: login and error handling](D06-build-login-part-2-login.md)
