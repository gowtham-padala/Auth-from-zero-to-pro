# D18 — Step-up auth and assurance levels (NIST AAL)

**Part D · Authentication** · *Builds on [D12](D12-build-totp.md), [C04](../track-c/C04-threat-modeling.md)*
---

## Authentication is not a boolean

The mental model most systems ship with:

```
   authenticated?  ──> yes / no
```

The model you need:

```
   ┌──────────────────────────────────────────────────────────┐
   │  WHO       user 4471                                      │
   │  HOW       password + TOTP        ← amr                   │
   │  WHEN      3 days ago             ← auth_time             │
   │  STRENGTH  AAL2                   ← acr                   │
   │  WHERE     new country, new device                        │
   └──────────────────────────────────────────────────────────┘
```

A session is not a flag. It is a **record of an authentication event with properties**, and
different actions should require different properties.

Three claims carry this, and they come straight from OIDC
([G02](../track-g/G02-oidc-on-top-of-oauth.md)) — worth adopting even in a system with no
federation at all:

| Claim | Meaning | Example |
|---|---|---|
| **`auth_time`** | When the user last actually authenticated | `1756345200` |
| **`amr`** | Authentication Methods References — *how* | `["pwd", "otp"]` |
| **`acr`** | Authentication Context Class Reference — *how strong* | `"aal2"` |

Store all three on the session at login ([D06](D06-build-login-part-2-login.md)) and you can
express every policy below. Omit them and you cannot express any of them.

---

## NIST assurance levels

**SP 800-63B-4** defines three **Authenticator Assurance Levels**. The important thing is
not memorising them but recognising that assurance is a *scale*.

| Level | Requires | Examples | Phishing-resistant? |
|---|---|---|---|
| **AAL1** | One factor | Password alone; magic link | ❌ |
| **AAL2** | **Two distinct factors** | Password + TOTP; password + push; **synced passkey** | ❌ (except passkey) |
| **AAL3** | **Hardware-based, phishing-resistant, verifier-impersonation-resistant** | Device-bound security key; device-bound passkey with attestation | ✅ **Required** |

Points that matter in practice:

- **AAL3 requires a *hardware* cryptographic authenticator** and phishing resistance. SMS
  can never reach it ([D11](D11-sms-second-factor.md)); neither can TOTP, because both are
  relayable.
- **Synced passkeys generally sit at AAL2**, because the key is exportable to the platform
  account rather than bound to hardware ([D16](D16-biometrics.md)). Device-bound
  credentials with attestation can reach AAL3.
- **A password used alone now requires 15 characters** under SP 800-63B-4
  ([D04](D04-password-policies.md)), because at AAL1 it is the entire defence.

There is a parallel scale for identity proofing — **IAL** (SP 800-63A) — and one for
federation — **FAL** (SP 800-63C, [G02](../track-g/G02-oidc-on-top-of-oauth.md)). They are
independent. You can have a strongly authenticated (AAL3) user whose real-world identity was
never verified (IAL1). That is normal and correct for most consumer products.

---

## Step-up authentication

> **Demand a stronger proof for a more sensitive action, mid-session.**

Not "log in again." A targeted challenge, at the moment of risk, for that action only.

```python
from datetime import datetime, timezone

def require_recent_authentication(max_age_seconds: int = 300,
                                  min_acr: str = "aal2"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            s = current_session()
            age = (datetime.now(timezone.utc) - s.auth_time).total_seconds()

            if age > max_age_seconds or acr_rank(s.acr) < acr_rank(min_acr):
                # Not a failure — an interruption. Remember where we were.
                pending = store_pending_action(request, ttl_seconds=600)
                return redirect(f"/reauthenticate?next={pending.id}&acr={min_acr}")

            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.post("/settings/email")
@require_recent_authentication(max_age_seconds=300)
def change_email(): ...

@app.post("/workspace/<id>/delete")
@require_recent_authentication(max_age_seconds=60, min_acr="aal2")
def delete_workspace(id): ...

@app.post("/admin/users/<id>/impersonate")
@require_recent_authentication(max_age_seconds=60, min_acr="aal3")   # I04
def impersonate(id): ...
```

The interaction design matters as much as the mechanism:

- **Never lose the user's work.** Store the pending action, re-authenticate, then complete
  it. A step-up that discards a half-written form trains users to hate the feature.
- **Say why.** *"Confirm it's you before deleting this workspace"* — not a bare password
  prompt with no context.
- **Ask for the strongest factor they have.** A user with a passkey should be asked for the
  passkey, not a password.
- **Update `auth_time` and `amr` on success**, so a burst of sensitive actions does not
  re-prompt repeatedly.
- **Rate limit the re-auth endpoint.** It is a login endpoint
  ([D08](D08-rate-limiting-and-stuffing.md)).

---

## What deserves a step-up

Ordered roughly by how much damage the action does if it was not the real user:

| Action | Max age | Min AAL |
|---|---|---|
| View a document | — | AAL1 |
| Edit a document | — | AAL1 |
| Share externally | 15 min | AAL2 |
| **Change password** | 5 min | AAL2 |
| **Change email** | 5 min | AAL2 |
| **Add or remove MFA** | 5 min | AAL2 |
| **Regenerate recovery codes** | 5 min | AAL2 ([D13](D13-recovery-codes.md)) |
| **Create an API key** | 5 min | AAL2 ([J02](../track-j/J02-api-keys.md)) |
| **Authorize an OAuth app** | 5 min | AAL2 ([F13](../track-f/F13-consent-screens.md)) |
| Delete a workspace | 1 min | AAL2 |
| Bulk export | 1 min | AAL2 |
| **Grant admin to another user** | 1 min | AAL2 |
| **Impersonate a user** | 1 min | **AAL3** ([I04](../track-i/I04-admin-impersonation.md)) |
| Change billing details | 5 min | AAL2 |

The clustering is not arbitrary. **Everything that changes how the account is
authenticated** — password, email, MFA, recovery codes, API keys — belongs in the same tier,
because those are the actions an attacker with a stolen session performs first to make their
access permanent.

> **A stolen session is a temporary problem until the attacker uses it to change the
> credentials. Step-up on credential-changing actions is what keeps it temporary.**

---

## Continuous, not just at the gate

Assurance should also respond to what happens *during* a session
([I09](../track-i/I09-detecting-account-takeover.md)):

```python
def session_risk(session, request) -> str:
    signals = []
    if request.ip_country != session.ip_country:  signals.append("country_change")
    if impossible_travel(session, request):       signals.append("impossible_travel")
    if request.device_id != session.device_id:    signals.append("device_change")
    if ip_reputation(client_ip()) == "bad":       signals.append("bad_ip")

    if "impossible_travel" in signals or len(signals) >= 2:
        return "high"
    return "elevated" if signals else "normal"
```

| Risk | Response |
|---|---|
| Normal | Continue |
| Elevated | Step up on the next sensitive action; log |
| High | Step up now; notify the user |
| Critical | Terminate the session; force full re-authentication; alert |

The trick is to **escalate rather than block**. A legitimate user on a train crossing a
border should be asked to confirm, not logged out. Blocking generates support tickets and
teaches users that security is an obstacle.

---

## In OAuth and OIDC

Step-up is not only a first-party concern. OIDC has the parameters built in:

```
GET /authorize?
    response_type=code
    &acr_values=urn:mace:incommon:iap:silver     ← "I need at least this"
    &max_age=300                                 ← "authenticated in the last 5 min"
    &prompt=login                                ← "re-authenticate regardless"
```

The IdP responds with `acr` and `auth_time` in the ID token, and **you must verify them** —
an IdP may ignore a request it cannot satisfy, and returning a token is not confirmation
that it complied ([G04](../track-g/G04-validate-an-id-token-by-hand.md)).

For APIs, [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) defines step-up for OAuth
resource servers:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication",
                  acr_values="urn:...:aal3",
                  max_age="60"
```

The API tells the client exactly what it needs, and the client starts a new authorization
request with those parameters. Same shape as the scope challenge in
[J08](../track-j/J08-mcp-and-oauth-21.md): **the resource server states its requirement in
the `WWW-Authenticate` header, and the client satisfies it.**

---

## Terms defined in this chapter

`step-up authentication`, `AAL`, `assurance level`, `amr`, `acr`, `auth_time`

---

## What to remember

1. **Authentication is not a boolean.** Record `auth_time`, `amr`, and `acr` on every
   session — even without federation.
2. **AAL1/2/3.** AAL3 needs *hardware* and phishing resistance. Synced passkeys are AAL2;
   device-bound can be AAL3.
3. **Step up on the action, not the session.** Targeted, contextual, and never losing the
   user's work.
4. **Everything that changes how the account authenticates belongs in the same tier** —
   password, email, MFA, recovery codes, API keys.
5. Escalate on risk signals; do not block. Blocking makes users hostile.
6. In OIDC use `acr_values`, `max_age`, `prompt=login` — **and verify what came back.**
7. RFC 9470 lets an API state its assurance requirement in `WWW-Authenticate`.

---

## Sources

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.3 (AAL definitions), §5.2 (reauthentication)
- [RFC 9470 — OAuth 2.0 Step Up Authentication Challenge Protocol](https://www.rfc-editor.org/rfc/rfc9470)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §3.1.2.1 (`acr_values`, `max_age`, `prompt`)
- [RFC 8176 — Authentication Method Reference Values](https://www.rfc-editor.org/rfc/rfc8176) (the registered `amr` values)

---

This is the last chapter on authentication. Track E is a different problem: keeping that proof alive across requests.

**Next:** [E01 — Why HTTP needs sessions at all](../track-e/E01-why-http-needs-sessions.md)
