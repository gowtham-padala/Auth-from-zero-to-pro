# D15 — Build passkey registration and login

**Part D · Authentication** · *Builds on [D14](D14-webauthn-and-passkeys-concepts.md)*
---

## Why it matters

A passkey implementation that "works" in testing and is a total bypass in production:

```python
# ❌ Every line of this is a vulnerability.
def verify_login(body):
    cred = db.get_credential(body["id"])
    return cred is not None          # never verified the signature at all
```

Or, subtler and far more common:

```python
# ❌ Verifies the signature. Checks nothing else.
public_key.verify(signature, authenticator_data + sha256(client_data_json))
return True
```

A verified signature proves *someone holding the private key signed something*
([B14](../track-b/B14-digital-signatures.md)). It does not prove:

- that they signed **your** challenge (→ **replay**)
- that they were on **your** origin (→ **phishing**, the whole point)
- that the credential belongs to **this** user (→ **impersonation**)
- that a human was present

**Nine checks are required.** Skipping any one of them removes a specific guarantee. This
chapter is those nine checks.

---

## Registration

### Server: options

```python
import secrets, base64

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")     # B02

@app.post("/webauthn/register/options")
@login_required
def registration_options():
    challenge = secrets.token_bytes(32)                          # B03
    session["reg_challenge"] = challenge                         # server-side only

    return jsonify({
        "rp": {"name": "Acme Docs", "id": "example.com"},        # RP ID — the binding
        "user": {
            # A random, stable, opaque handle. NEVER the email:
            # the user handle is stored on the authenticator and may be
            # displayed by the platform.
            "id":          b64url(current_user.webauthn_handle),
            "name":        current_user.email,                   # shown in the picker
            "displayName": current_user.display_name,
        },
        "challenge": b64url(challenge),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},                   # ES256 — required
            {"type": "public-key", "alg": -257},                 # RS256 — compatibility
        ],
        "timeout": 60_000,
        "attestation": "none",                                   # D14
        "excludeCredentials": [                                  # no duplicate enrolment
            {"type": "public-key", "id": b64url(c.credential_id)}
            for c in db.get_credentials(current_user.id)
        ],
        "authenticatorSelection": {
            "residentKey": "preferred",                          # discoverable
            "userVerification": "preferred",
        },
    })
```

Three decisions worth defending:

**`user.id` is an opaque random handle, not the email.** It is stored on the authenticator
and surfaces in platform UI. It must also be stable — changing it creates a *second*
passkey rather than replacing the first.

**`excludeCredentials`** stops the same authenticator enrolling twice, which otherwise
produces a confusing list of duplicate credentials the user cannot tell apart.

**`residentKey: "preferred"`** asks for a discoverable credential so usernameless login
works, without failing on authenticators that cannot store one
([D14](D14-webauthn-and-passkeys-concepts.md)).

### Browser

```js
const options = await (await fetch("/webauthn/register/options", {method: "POST"})).json();

// WebAuthn L3 helper — replaces a page of manual base64url conversion.
const credential = await navigator.credentials.create({
  publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
});

await fetch("/webauthn/register/verify", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify(credential.toJSON()),
});
```

Two lines of real work, thanks to the Level 3 JSON helpers. Before them, this was thirty
lines of `ArrayBuffer` ↔ base64url conversion and a reliable source of bugs.

### Server: verify

**Use a library.** `py_webauthn`, `SimpleWebAuthn` (JS), `webauthn4j` (Java),
`go-webauthn`. Parsing CBOR and COSE keys by hand is a large amount of code with sharp
edges, and unlike HMAC ([B13](../track-b/B13-message-authentication-hmac.md)) there is no
pedagogical payoff in reimplementing it.

```python
from webauthn import verify_registration_response
from webauthn.helpers.structs import RegistrationCredential

@app.post("/webauthn/register/verify")
@login_required
def registration_verify():
    challenge = session.pop("reg_challenge", None)
    if challenge is None:
        return error("Registration expired"), 400

    try:
        v = verify_registration_response(
            credential=RegistrationCredential.parse_raw(request.data),
            expected_challenge=challenge,
            expected_origin="https://example.com",      # ← EXACT. The anti-phishing check.
            expected_rp_id="example.com",
            require_user_verification=False,
        )
    except Exception:
        audit_log("passkey.registration_failed", user_id=current_user.id)
        return error("Registration failed"), 400

    db.insert_credential(
        user_id=current_user.id,
        credential_id=v.credential_id,
        public_key=v.credential_public_key,             # COSE-encoded
        sign_count=v.sign_count,
        transports=request.json.get("response", {}).get("transports", []),
        backed_up=v.credential_backed_up,               # is it a SYNCED passkey?
        nickname=request.json.get("nickname") or "Passkey",
        created_at=now(),
    )

    audit_log("passkey.registered", user_id=current_user.id)
    notify_user(current_user.id, "A new passkey was added to your account.")
    return jsonify({"ok": True})
```

Store `backed_up`. It tells you whether the credential is synced or device-bound — which
determines whether losing one device loses the account, and which assurance level it can
support ([D18](D18-step-up-auth-and-aal.md)).

---

## Login

### Server: options

```python
@app.post("/webauthn/login/options")
def login_options():
    challenge = secrets.token_bytes(32)
    session["auth_challenge"] = challenge

    return jsonify({
        "challenge": b64url(challenge),
        "rpId": "example.com",
        "timeout": 60_000,
        "userVerification": "preferred",
        # No allowCredentials → usernameless. The authenticator offers
        # whatever it holds for this RP ID.  D14.
        "allowCredentials": [],
    })
```

### Browser: conditional UI

```js
// Only if the browser supports it.
if (await PublicKeyCredential.isConditionalMediationAvailable?.()) {
  const options = await (await fetch("/webauthn/login/options", {method:"POST"})).json();

  const credential = await navigator.credentials.get({
    publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    mediation: "conditional",     // ← offers passkeys in the username field's autofill
  });

  await fetch("/webauthn/login/verify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(credential.toJSON()),
  });
  location.href = "/";
}
```

```html
<input name="email" autocomplete="username webauthn">
<input name="password" type="password" autocomplete="current-password">
```

The `webauthn` token in `autocomplete` is what activates it. A user with a passkey sees it
offered in the autofill dropdown; a user without one sees a normal login form. **No
branching UI, no "do you have a passkey?" question** — this is the single biggest usability
win available, and it is one attribute.

### Server: verify — the nine checks

```python
from webauthn import verify_authentication_response

@app.post("/webauthn/login/verify")
@rate_limit(key=lambda: client_ip(), limit="20/15min")
def login_verify():
    challenge = session.pop("auth_challenge", None)
    if challenge is None:
        return error("Login expired"), 400

    body = request.get_json()
    cred = db.get_credential_by_id(base64url_decode(body["rawId"]))
    if cred is None:
        return error("Login failed"), 401          # generic — D07

    try:
        v = verify_authentication_response(
            credential=AuthenticationCredential.parse_raw(request.data),
            expected_challenge=challenge,                  # ① replay
            expected_origin="https://example.com",         # ② phishing
            expected_rp_id="example.com",                  # ③ scope
            credential_public_key=cred.public_key,         # ④ signature
            credential_current_sign_count=cred.sign_count, # ⑤ cloning
            require_user_verification=False,               # ⑥ presence/verification
        )
    except Exception:
        audit_log("passkey.login_failed", credential_id=cred.id)
        return error("Login failed"), 401

    # ⑦ Does this credential belong to the user we think it does?
    user = db.get_user(cred.user_id)
    if user is None or user.disabled_at:
        return error("Login failed"), 401

    # ⑧ Sign counter regression = a possible clone.
    if v.new_sign_count and v.new_sign_count <= cred.sign_count:
        audit_log("passkey.sign_count_regression", credential_id=cred.id)
        # Do not necessarily block — many passkeys always report 0 — but ALERT.

    db.update_credential(cred.id, sign_count=v.new_sign_count, last_used_at=now())

    # ⑨ Record HOW they authenticated.  D18.
    amr = ["swk"] + (["mfa", "uv"] if v.user_verified else [])
    session_id = create_session(user.id, request, amr=amr)

    resp = jsonify({"ok": True})
    resp.set_cookie("__Host-session", session_id, httponly=True, secure=True,
                    samesite="Lax", path="/", max_age=60*60*24*14)
    return resp
```

| # | Check | Missing it means |
|---|---|---|
| ① | Challenge matches, single-use | **Replay** — a captured assertion works forever |
| ② | **Origin is exactly yours** | **Phishing works.** The entire point is gone |
| ③ | RP ID matches | Credentials from another scope are accepted |
| ④ | Signature verifies against the stored key | Anyone can log in as anyone |
| ⑤ | Sign counter did not go backwards | A cloned authenticator goes undetected |
| ⑥ | UP flag set (and UV if you require it) | No human was necessarily involved |
| ⑦ | **Credential belongs to the claimed user** | Impersonation |
| ⑧ | Counter updated | ⑤ stops working on the next login |
| ⑨ | `amr` recorded | Step-up decisions have nothing to reason about |

**Check ② is the whole chapter.** Everything else in WebAuthn is scaffolding around "the
origin was signed and the server checked it."

**Check ⑦ is the one people skip**, because the library returned success and that feels
conclusive. The library verified the *signature*. It has no idea which user you are about
to log in.

---

## Sign counter, honestly

The counter is meant to detect cloning: a duplicated authenticator eventually produces a
counter lower than one you have seen.

In practice:

- **Most synced passkeys always report 0.** There is nothing to compare.
- Apple's platform authenticator reports 0.
- Hardware security keys do maintain it.

So: **alert on regression, do not hard-block.** A false positive locks a user out of their
own account for a signal that is absent on the majority of modern authenticators.

---

## Operational essentials

**A management UI.** Users must be able to see their passkeys, name them ("MacBook",
"YubiKey"), see last-used dates, and delete them.

**Never allow deleting the last authenticator** without a replacement or a confirmed
password. Otherwise the delete button is a self-service lockout
([D13](D13-recovery-codes.md)).

**Enrol two at registration.** The single most effective recovery measure
([D09](D09-account-recovery.md)).

**Use conditional create** to upgrade password users silently: after a successful password
login, offer to create a passkey without a modal
([D14](D14-webauthn-and-passkeys-concepts.md)).

**Use the Signal API** (Level 3) to tell password managers when a credential is deleted, so
stale entries disappear from the user's autofill.

**Always keep a fallback.** Old browsers, locked-down corporate machines, assistive
technology.

---

## Terms defined in this chapter

`authenticator data`, `client data JSON`, `user verification`, `user presence`,
`discoverable credential`, `signature counter`

---

## What to remember

1. **A verified signature is not a verified login.** Nine checks, not one.
2. **`expected_origin` must be exact.** That single check is the phishing resistance.
3. **Check the credential belongs to the user you are about to log in.** The library does
   not.
4. **Use a library** for WebAuthn. Unlike HMAC, hand-rolling teaches nothing and breaks
   things.
5. `user.id` is an **opaque, stable, random handle** — never the email.
6. **`autocomplete="username webauthn"` + conditional UI.** The biggest usability win, one
   attribute.
7. **Alert on sign-counter regression; do not block.** Most synced passkeys report 0.
8. Enrol two authenticators, never allow deleting the last one, always keep a fallback.

---

## Sources

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) §7.1 (registration verification), §7.2 (authentication verification) — the normative nine checks
- [passkeys.dev — Server-side implementation](https://passkeys.dev/docs/use-cases/bootstrapping/)
- [SimpleWebAuthn](https://simplewebauthn.dev/) — the best-documented library in any ecosystem
- [MDN: Conditional mediation / passkey autofill](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get#conditional_mediation)

---

**Next:** [D16 — Biometrics: what your fingerprint actually proves](D16-biometrics.md)
