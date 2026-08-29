# E10 — Token lifetimes, refresh tokens, and rotation

**Part E · Sessions & tokens** · *Builds on [E08](E08-signed-cookies-vs-jwt-vs-opaque.md)*
---

## Why two tokens

```
   ACCESS TOKEN                          REFRESH TOKEN
   ────────────                          ─────────────
   Presented to APIs, constantly         Presented ONCE, to the auth server
   Short-lived: 5–15 minutes             Long-lived: days to months
   Often self-contained (JWT)            Always opaque, always server-side
   Widely distributed                    Held in exactly one place
   Hard to revoke                        Trivially revocable — DELETE
```

The split is a deliberate trade, and it is the resolution of
[E09](E09-should-you-use-jwts-for-sessions.md)'s tension:

- The credential that travels widely is **short-lived**, so a leak has a small window.
- The credential that lives long is **rarely transmitted and revocable**, so a leak is
  containable.

You get local verification for the common case and real revocation for the important one.

---

## Choosing lifetimes

| Token | Typical | Reasoning |
|---|---|---|
| **Access token** | **5–15 min** | Long enough to avoid churn; short enough that staleness and theft windows are small |
| Refresh token (web) | 8 h – 30 d | Matches how long a session should live |
| Refresh token (mobile) | 30–180 d | Users expect never to log in again |
| Refresh token (rotating) | Days, but **rotated on every use** | The window is between uses, not the total lifetime |
| ID token | 5–60 min | Consumed once at login; not a session ([G03](../track-g/G03-id-token-vs-access-token.md)) |

**Absolute cap on the refresh chain.** Rotation can extend a session indefinitely — each
refresh issues a new token with a fresh lifetime, so a chain started in January is still
alive in December. Set a hard maximum (30–90 days) after which full re-authentication is
required. Same reasoning as the absolute session timeout in
[E04](E04-session-ids.md).

---

## Rotation

> **Every time a refresh token is used, invalidate it and issue a new one.**

```
   Client                              Auth server
     │                                      │
     │── refresh_token: RT₁ ───────────────>│
     │                                      │  invalidate RT₁
     │<── access_token: AT₂, refresh: RT₂ ──│  issue RT₂
     │                                      │
     │── refresh_token: RT₂ ───────────────>│
     │                                      │  invalidate RT₂
     │<── access_token: AT₃, refresh: RT₃ ──│  issue RT₃
```

By itself this shortens the window in which a stolen token is useful. The real value comes
from what you can now detect.

## Reuse detection — the part that matters

If **RT₁ is presented after RT₂ was issued**, something is wrong. There are exactly two
possibilities, and both demand the same response:

1. An attacker stole RT₁ and is using it. The legitimate client already has RT₂.
2. The legitimate client stole nothing but never received RT₂ (a network failure), retried
   with RT₁, and an attacker has RT₂.

Either way, **one of the two holders is an attacker and you cannot tell which.**

```
   ┌──────────────────────────────────────────────────────────────┐
   │  RT₁ ──> RT₂ ──> RT₃ ──> RT₄        ← the token FAMILY        │
   │           ▲                                                   │
   │           │                                                   │
   │        RT₂ presented AGAIN                                    │
   │           │                                                   │
   │           ▼                                                   │
   │  🚨 INVALIDATE THE ENTIRE FAMILY. Both parties log in again.  │
   └──────────────────────────────────────────────────────────────┘
```

**Kill the whole family.** The legitimate user re-authenticates — mildly annoying. The
attacker is locked out — the point. And you have a high-confidence compromise signal to act
on ([I09](../track-i/I09-detecting-account-takeover.md)).

This is mandated by [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) (the OAuth Security
BCP) for public clients, and it is the single most valuable thing in this chapter.

---

## Implementation

```sql
CREATE TABLE refresh_tokens (
  token_hash   bytea       PRIMARY KEY,        -- SHA-256; never the raw token
  family_id    uuid        NOT NULL,           -- shared by the whole chain
  user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id   bytea,                          -- links to the session — E13

  issued_at    timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  family_expires_at timestamptz NOT NULL,      -- the absolute cap

  used_at      timestamptz,                    -- non-null once rotated
  replaced_by  bytea,

  client_id    text,
  scope        text,
  ip           inet,
  user_agent   text
);

CREATE INDEX ON refresh_tokens (family_id);
CREATE INDEX ON refresh_tokens (user_id);
```

```python
import secrets, hashlib, uuid
from datetime import datetime, timedelta, timezone

REFRESH_TTL   = timedelta(days=30)
FAMILY_MAX    = timedelta(days=90)

def _h(t: str) -> bytes:
    return hashlib.sha256(t.encode()).digest()

def issue_refresh_token(user_id, family_id=None, family_expires_at=None,
                        session_id=None, scope=None) -> str:
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)                      # B03

    db.insert_refresh_token(
        token_hash=_h(token),
        family_id=family_id or uuid.uuid4(),
        user_id=user_id,
        session_id=session_id,
        expires_at=now + REFRESH_TTL,
        family_expires_at=family_expires_at or (now + FAMILY_MAX),
        scope=scope,
        ip=client_ip(),
    )
    return token

def refresh(presented: str):
    now = datetime.now(timezone.utc)
    row = db.get_refresh_token(_h(presented))

    if row is None:
        raise InvalidGrant()                     # never existed, or family was killed

    # ── REUSE DETECTION ────────────────────────────────────────────────
    if row.used_at is not None:
        db.delete_refresh_family(row.family_id)          # kill everything
        db.delete_sessions_for_family(row.family_id)     # and the sessions
        audit_log("refresh.reuse_detected",
                  user_id=row.user_id, family_id=row.family_id, ip=client_ip())
        notify_user(row.user_id,
                    "We detected suspicious activity and signed you out everywhere.")
        raise InvalidGrant()
    # ───────────────────────────────────────────────────────────────────

    if row.expires_at < now or row.family_expires_at < now:
        db.delete_refresh_family(row.family_id)
        raise InvalidGrant()

    # Rotate, atomically.
    with db.transaction():
        new_token = issue_refresh_token(
            row.user_id, family_id=row.family_id,
            family_expires_at=row.family_expires_at,
            session_id=row.session_id, scope=row.scope,
        )
        db.mark_refresh_token_used(row.token_hash, replaced_by=_h(new_token), at=now)

    return {
        "access_token":  mint_access_token(row.user_id, row.scope, ttl_seconds=900),
        "refresh_token": new_token,
        "token_type":    "Bearer",
        "expires_in":    900,
    }
```

Four details that matter:

**Mark used; do not delete.** You need the row to *detect* reuse. Delete it after the family
window closes.

**Rotation must be atomic.** Two concurrent refreshes racing can otherwise both succeed, or
both fail and trigger a spurious family kill.

**Never log the token.** Log the `family_id` ([I08](../track-i/I08-observability.md)).

**A refresh failure is `400 invalid_grant`**, not `401`. That is what the OAuth
specification says and what clients handle.

---

## The concurrency problem

Real clients fire several requests at once. All get `401`. All call `/refresh` with the same
token. One succeeds and rotates; the rest present a used token — and your reuse detection
logs everyone out.

**Client-side fix (do this first):** a single-flight refresh.

```js
let refreshInFlight = null;

async function getAccessToken() {
  if (tokenIsFresh()) return accessToken;
  refreshInFlight ??= doRefresh().finally(() => { refreshInFlight = null; });
  return refreshInFlight;
}
```

**Server-side fix (defence in depth):** a short grace window.

```python
GRACE = timedelta(seconds=10)

if row.used_at is not None:
    if (now - row.used_at) < GRACE and row.replaced_by:
        # Almost certainly a concurrent retry, not an attack.
        # Return the SAME successor rather than rotating again.
        return response_for(row.replaced_by)
    kill_family_and_alert(row)
```

Ten seconds tolerates a network retry and gives an attacker essentially nothing. Without one
of these two fixes, rotation produces phantom logouts and teams disable it — which is the
worst outcome, because they lose the detection.

---

## Where refresh tokens live

| Client | Storage | Notes |
|---|---|---|
| **Web (BFF)** | **Server-side.** Browser holds only a session cookie | ✅ Best ([F17](../track-f/F17-oauth-for-spas-and-bff.md)) |
| Web (SPA, no BFF) | `HttpOnly` cookie, path-scoped to `/refresh` | ⚠️ Acceptable |
| Web (SPA) | `localStorage` | ❌ XSS = permanent access ([E12](E12-where-to-store-a-token.md)) |
| **Mobile** | Keychain / Keystore | ✅ Hardware-backed ([D16](../track-d/D16-biometrics.md)) |
| Mobile | Shared preferences / plist | ❌ Readable on a rooted device |
| **Desktop / CLI** | OS credential store | ✅ |
| Desktop / CLI | A plaintext file in `~` | ⚠️ Common; at minimum `chmod 600` |
| **Server-to-server** | Secret manager | ✅ ([I05](../track-i/I05-secrets-management.md)) |

**A refresh token is a long-lived credential.** Treat it like a password
([A10](../track-a/A10-where-secrets-live.md)), because that is what it is.

---

## Terms defined in this chapter

`access token`, `refresh token`, `rotation`, `reuse detection`, `token family`

---

## What to remember

1. **Short-lived access tokens + long-lived revocable refresh tokens.** Reach where you need
   it, revocation where it matters.
2. Access: **5–15 minutes**. Refresh: days to months, with an **absolute family cap**.
3. **Rotate on every use** — and **reuse detection is the point.**
4. **A reused token means one of two holders is an attacker.** Kill the family, notify, log
   in again.
5. Store the **hash**, mark **used** rather than deleting, and rotate **atomically**.
6. **Handle concurrency** — single-flight on the client, a 10-second grace on the server —
   or teams disable rotation and lose the detection.
7. Refresh failure is `400 invalid_grant`, not `401`.
8. A refresh token is a password. Store it accordingly.

---

## Sources

- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700) §4.14 (refresh token protection)
- [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6) — refreshing an access token
- [OAuth 2.0 Refresh Token Rotation (Auth0)](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)

---

**Next:** [E11 — Revocation: the thing stateless tokens are bad at](E11-revocation.md)
