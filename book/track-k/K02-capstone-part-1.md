# K02 — Build the capstone, part 1: authentication and sessions

**Part K · Capstone** · *Builds on Tracks D, E*
> Layers 1 and 2, assembled into one working application. This is Tracks D and E, wired together —
> not new material, but the *integration*, which is where the seams show.

---

## What we're building

The document-sharing app's foundation: registration, login, MFA, passkeys, and sessions — every
piece from Tracks D and E, composed. The architecture was reviewed in
[K01](K01-architecture-review.md); here we build it. Repo tag `ep-K02-capstone-1` has it complete
and runnable; this chapter is the wiring and the seams.

---

## The schema, whole

Every table from Tracks D and E, in one place ([D01](../track-d/D01-identifiers.md),
[D03](../track-d/D03-how-to-store-passwords.md), [E03](../track-e/E03-build-server-side-sessions.md)):

```sql
CREATE TABLE users (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),   -- stable key  D01
  tenant_id         uuid NOT NULL,                                -- multi-tenant  H09
  email             text NOT NULL,
  email_canonical   citext NOT NULL,                              -- uniqueness  D02
  password_hash     text,                                         -- Argon2id PHC  D03 (nullable: SSO-only users)
  email_verified_at timestamptz,
  totp_secret_enc   bytea,                                        -- encrypted  D12/B09
  is_disabled       boolean NOT NULL DEFAULT false,
  UNIQUE (tenant_id, email_canonical)                             -- unique per TENANT  H09
);

CREATE TABLE identities (                                         -- account linking  G12
  issuer text, subject text, user_id uuid REFERENCES users(id),
  email citext, verified boolean, PRIMARY KEY (issuer, subject)
);

CREATE TABLE webauthn_credentials (                              -- passkeys  D15
  credential_id bytea PRIMARY KEY, user_id uuid REFERENCES users(id),
  public_key bytea, sign_count bigint, backed_up boolean, nickname text
);

CREATE TABLE sessions (                                          -- E03/E04
  id bytea PRIMARY KEY,                                          -- sha256(token)  B05
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz, last_seen_at timestamptz,
  expires_at timestamptz, absolute_expires_at timestamptz,       -- two clocks  E04
  auth_time timestamptz, amr text[], acr text,                   -- assurance  D18
  ip inet, user_agent text, label text                          -- device list  E13
);

CREATE TABLE recovery_codes (code_hash bytea, user_id uuid, used_at timestamptz);   -- D13
```

The schema *is* the design decisions ([K01](K01-architecture-review.md)): `UNIQUE(tenant_id, ...)`
is multi-tenancy ([H09](../track-h/H09-multi-tenancy-isolation.md)); `sessions.id = sha256(token)`
is hashed-at-rest ([E04](../track-e/E04-session-ids.md)); `amr/acr` on the session is step-up
([D18](../track-d/D18-step-up-auth-and-aal.md)); `identities` separate from `users` is account
linking ([G12](../track-g/G12-account-linking.md)).

---

## Registration

Assembling [D05](../track-d/D05-build-login-part-1-registration.md):

```python
@app.post("/register")
@rate_limit(key=client_ip, limit="5/hour")                 # D08
def register():
    data = RegistrationInput.parse(request.form)           # allowlist — no mass assignment  D05
    errors = validate_password(data.password, data.email)  # length + breach blocklist  D04
    if errors: return render("register.html", errors=errors), 400

    try:
        with db.transaction():
            user = db.insert_user(
                tenant_id=resolve_tenant(data.email),      # H09
                email=data.email, email_canonical=canonicalize(data.email),  # D02
                password_hash=ph.hash(normalize(data.password)),             # D03
            )
        send_verification_email(user)                      # single-use, hashed token  D05
    except UniqueViolation:
        send_account_exists_email(canonicalize(data.email))  # tell the OWNER, not the form  D07
    return render("check-your-email.html"), 200            # IDENTICAL either way  D07
```

The seams: enumeration resistance ([D07](../track-d/D07-user-enumeration.md)) requires the identical
response *and* the unique-constraint-catches-duplicates pattern ([D05](../track-d/D05-build-login-part-1-registration.md));
the breach blocklist ([D04](../track-d/D04-password-policies.md)) fails *open* on a HIBP outage but
password hashing never does.

---

## Login → MFA → session

The full chain ([D06](../track-d/D06-build-login-part-2-login.md), [D12](../track-d/D12-build-totp.md),
[E03](../track-e/E03-build-server-side-sessions.md)), where the layer-1→layer-2 handoff happens:

```python
DUMMY_HASH = ph.hash("nobody")                             # constant-time enum defence  D07/B16

@app.post("/login")
@rate_limit(key=client_ip, limit="20/15min")               # D08
@rate_limit(key=submitted_email, limit="10/15min")         # both keys  D08
def login():
    user = db.find_user(canonicalize(request.form["email"]))
    # Constant work whether or not the user exists.  D07/B16
    try:
        ph.verify(user.password_hash if user else DUMMY_HASH, normalize(request.form["password"]))
        ok = user is not None and user.password_hash is not None
    except VerifyMismatchError:
        ok = False
    if not ok or user.is_disabled or not user.email_verified_at:
        return render("login.html", error=GENERIC_ERROR), 401   # one message  D07

    if ph.check_needs_rehash(user.password_hash):          # free upgrade  D03/I12
        db.update_password_hash(user.id, ph.hash(normalize(request.form["password"])))

    if user.totp_secret_enc or user.has_passkeys():        # → second factor  D12/D15
        return redirect(create_pending_mfa(user.id))       # short-lived, single-use, rate-limited  D06

    return complete_login(user, amr=["pwd"], acr="aal1")   # no MFA → weaker session  D18


def complete_login(user, amr, acr):
    token = create_session(user.id, request, amr=amr, acr=acr)   # NEW id (fixation)  E04
    resp = redirect(safe_next(request.args.get("next")))         # validated  A09
    resp.set_cookie("__Host-session", token, httponly=True, secure=True,
                    samesite="Lax", path="/", max_age=WEEKS_2)   # E02
    audit_log("login.success", user_id=user.id, amr=amr)         # H13
    return resp
```

**The `complete_login` function is the layer-1 → layer-2 boundary** ([C01](../track-c/C01-auth-is-five-different-problems.md)):
authentication (layer 1) finishes, and the session (layer 2) begins. The session records *how*
the user authenticated (`amr`/`acr`), so later step-up ([D18](../track-d/D18-step-up-auth-and-aal.md))
has something to reason about. Note the session ID is *new* at every privilege change — that single
`create_session` call defeats fixation ([E04](../track-e/E04-session-ids.md)).

---

## The session middleware — the layer-2 workhorse

Every authenticated request runs this ([E03](../track-e/E03-build-server-side-sessions.md)):

```python
@app.before_request
def attach_session():
    token = request.cookies.get("__Host-session")
    g.session = load_session(token)                        # lookup by sha256, check BOTH expiries  E04
    g.user = db.get_user(g.session.user_id) if g.session else None
    if g.user:
        db.set_tenant_context(g.user.tenant_id)            # RLS  H09/H10 — ready for K03

def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not g.user: return auth_challenge()             # 401  A03
        return fn(*a, **k)
    return w
```

**This establishes *who*, not *what*** ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).
`@login_required` is authentication; authorization is [K03](K03-capstone-part-2.md)'s job. Getting
that split right is the difference between a working app and an IDOR
([H14](../track-h/H14-attack-your-own-authorization.md)). The middleware also sets the tenant
context for RLS ([H10](../track-h/H10-row-level-security.md)) — layer 5's foundation, laid in
layer 2.

---

## Passkeys, TOTP, recovery, sessions-list

The rest of the layer, each a chapter, wired in:

- **Passkey registration/login** — the nine-check verification ([D15](../track-d/D15-build-passkeys.md)),
  `expected_origin` exact, credential-belongs-to-user checked. Conditional UI on the login form.
- **TOTP** — HMAC over the time counter ([D12](../track-d/D12-build-totp.md)), secret encrypted at
  rest ([B09](../track-b/B09-symmetric-encryption.md)), code submission rate-limited (the
  most-missed control — [D08](../track-d/D08-rate-limiting-and-stuffing.md), [D12](../track-d/D12-build-totp.md)).
- **Recovery codes** — shown once at enrolment, hashed, single-use, notify on use
  ([D13](../track-d/D13-recovery-codes.md)).
- **Session management UI** — list, revoke one, "log out everywhere" (which kills refresh families
  and trusted devices too — [E13](../track-e/E13-sessions-across-devices.md)).
- **Logout** — deletes the *server* session, not just the cookie ([E14](../track-e/E14-why-logout-is-hard.md)).
- **Password reset** — invalidates all sessions ([D09](../track-d/D09-account-recovery.md)).

---

## The integration checklist

The seams that only show when the pieces are wired together — verify each
([I07](../track-i/I07-testing-auth.md)):

```
☐ Session ID rotates on login AND MFA completion AND password change     E04/D06
☐ amr/acr recorded, so K03's step-up has data                            D18
☐ Login enumeration-resistant: message, status, length, TIMING           D07
☐ MFA code submission rate-limited (the most-missed)                     D08/D12
☐ Password reset kills all sessions                                      D09
☐ Logout deletes the server session                                     E14
☐ "Log out everywhere" reaches refresh families + trusted devices        E13
☐ TOTP secret encrypted at rest; recovery codes hashed                   D12/D13
☐ Middleware sets tenant context (RLS ready for K03)                     H10
☐ @login_required is authentication ONLY — authz is K03                  C02
```

That last line is the hand-off. This chapter established *who the user is and that they stay logged
in* (layers 1–2). [K03](K03-capstone-part-2.md) adds *what they may do* (layers 3–5) — and the two
must not be confused ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).

---

## What to remember

1. **This is Tracks D and E *integrated*** — not new material, but the wiring, where the seams show.
2. **The schema encodes the design decisions** — hashed session IDs, per-tenant uniqueness, amr/acr,
   separate identities table.
3. **`complete_login` is the layer-1 → layer-2 boundary** — authentication ends, the session begins,
   recording *how* they authenticated ([C01](../track-c/C01-auth-is-five-different-problems.md)).
4. **The session ID is new at every privilege change** — one `create_session` call defeats fixation
   ([E04](../track-e/E04-session-ids.md)).
5. **The middleware establishes *who*, not *what*** — `@login_required` is authentication only; authz
   is [K03](K03-capstone-part-2.md) ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).
6. **Verify the seams** — session rotation, enumeration resistance, MFA rate limiting, reset kills
   sessions — the bugs live in the integration, not the parts.

---

## Sources

- [The Copenhagen Book](https://thecopenhagenbook.com/) — the full first-party auth build
- *API Security in Action* (Neil Madden), Ch. 2–6
- [OWASP ASVS V2, V3](https://owasp.org/www-project-application-security-verification-standard/)

---

**Next:** [K03 — Build the capstone, part 2: OAuth, SSO, authorization](K03-capstone-part-2.md)
