# D17 — "Remember this device" is harder than it looks

**Part D · Authentication** · *Builds on [D12](D12-build-totp.md)*
---

## Why it matters

"Don't ask for a code on this device for 30 days." Users love it. It is implemented in an
afternoon:

```python
resp.set_cookie("trusted_device", "true", max_age=30*24*3600)
```

```js
document.cookie = "trusted_device=true";     // in any browser's console
```

MFA is now optional for everyone, forever, on any device.

The obvious fix is to make the cookie unguessable. That fixes the *forgery* and leaves the
harder problem: **"remember this device" is a decision to skip your second factor, and it
has to be as carefully designed as the factor it is skipping.**

---

## What the feature actually is

> A long-lived credential that substitutes for the second factor.

Once you say it that way, the design constraints follow:

- It must be **unguessable** — high entropy ([B03](../track-b/B03-randomness.md)).
- It must be **bound to one user**, or it is a universal bypass.
- It must be **revocable** — a lost laptop must be removable.
- It must **expire**.
- It must be **invalidated** on password change, MFA change, and any compromise signal.
- It must be **visible to the user**, so they can audit it.

That list is the same list as a session ([E04](../track-e/E04-session-ids.md)), because it
*is* a session-shaped thing — just one with a longer life and a narrower purpose.

---

## Doing it properly

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone

TRUST_TTL = timedelta(days=30)

def trust_this_device(user_id: str, request) -> str:
    token = secrets.token_urlsafe(32)                     # B03 — 256 bits

    db.insert_trusted_device(
        token_hash=hashlib.sha256(token.encode()).digest(),   # B05 — hashed
        user_id=user_id,                                       # bound to ONE user
        expires_at=datetime.now(timezone.utc) + TRUST_TTL,
        created_ip=client_ip(),
        user_agent=request.headers.get("User-Agent", ""),
        label=friendly_device_name(request),                   # "Chrome on macOS"
        last_seen_at=datetime.now(timezone.utc),
    )
    audit_log("device.trusted", user_id=user_id, ip=client_ip())
    return token

def device_is_trusted(user_id: str, request) -> bool:
    raw = request.cookies.get("__Host-device_trust")
    if not raw:
        return False

    row = db.get_trusted_device(hashlib.sha256(raw.encode()).digest())

    # Every one of these three checks matters.
    if row is None:
        return False
    if row.user_id != user_id:                # ← the token is for a DIFFERENT user
        audit_log("device.trust_user_mismatch", user_id=user_id)
        return False
    if row.expires_at < datetime.now(timezone.utc):
        db.delete_trusted_device(row.id)
        return False

    db.touch_trusted_device(row.id, last_seen_at=datetime.now(timezone.utc))
    return True
```

Set it like any other sensitive cookie ([E02](../track-e/E02-cookie-attributes.md)):

```python
resp.set_cookie(
    "__Host-device_trust", token,
    httponly=True, secure=True, samesite="Lax",
    path="/", max_age=int(TRUST_TTL.total_seconds()),
)
```

**The `row.user_id != user_id` check is the one that gets skipped.** Without it, a valid
trust token from *any* account bypasses MFA for *every* account — the original bug with more
entropy.

---

## Device fingerprinting is not the answer

The tempting alternative: identify the device by its characteristics — user agent, screen
size, fonts, canvas rendering, timezone.

**Do not use fingerprinting as an authentication control.**

- **It is forgeable.** Every input comes from the client
  ([A07](../track-a/A07-client-vs-server.md)). An attacker who has seen one request can
  replay every header.
- **It is unstable.** A browser update, a new monitor, a VPN, or a font install changes it,
  and your users are challenged at random.
- **It is a privacy and regulatory problem.** Browsers are actively degrading fingerprinting
  surfaces, and GDPR/ePrivacy treat it as tracking requiring consent.

**Use it as a *risk signal*, never as a credential.** A trust token that arrives with a
wildly different fingerprint is a reason to re-challenge — not a reason to trust
([I09](../track-i/I09-detecting-account-takeover.md)).

The correct architecture: **the token authenticates; the fingerprint informs.**

---

## When to break the trust

Trust must be revoked on every event that changes the security posture of the account:

| Event | Action |
|---|---|
| Password changed or reset | **Revoke all** ([D09](D09-account-recovery.md)) |
| MFA method added or removed | **Revoke all** |
| Recovery code used | **Revoke all** — high-signal compromise indicator |
| User clicks "log out everywhere" | **Revoke all** ([E13](../track-e/E13-sessions-across-devices.md)) |
| Suspicious login detected | Revoke all, notify |
| Email address changed | **Revoke all** |
| The device is deleted from settings | Revoke that one |
| Token expires | Delete |
| A sensitive action (payment, export, admin) | **Do not use trust at all** — step up ([D18](D18-step-up-auth-and-aal.md)) |

That last row is the most important design decision in the chapter. **Trusted-device status
should let a user skip MFA for ordinary use, and never for a sensitive action.** Keep the
convenience where it is cheap and require the factor where it matters.

---

## The management UI

If a user cannot see their trusted devices, they cannot revoke a lost one — and the feature
becomes a permanent, invisible MFA bypass.

```
Trusted devices                                   [ Remove all ]

  🖥  Chrome on macOS        London, UK       Last used: 2 hours ago   [Remove]
  📱  Safari on iPhone       London, UK       Last used: yesterday     [Remove]
  🖥  Firefox on Windows     Berlin, DE       Last used: 12 days ago   [Remove]
                                                     ⚠️ unrecognised
```

Show location, last-used time, and a friendly device name. Flag anything unusual. Make
"Remove all" prominent — it is the button a worried user is looking for.

Combine this with the session list ([E13](../track-e/E13-sessions-across-devices.md)) so
there is one place to answer "what has access to my account?"

---

## Duration, honestly

| Product | Trust duration | Reasoning |
|---|---|---|
| Consumer, low value | 30–90 days | Convenience dominates |
| Consumer, financial | 14–30 days | Balance |
| B2B SaaS | 30 days | Enterprise policy often dictates |
| Admin / privileged | **Never** | The blast radius is the whole system |
| Regulated (banking, health) | 7–14 days, or none | Policy-driven |

**Sliding vs absolute:** a sliding window (renew on each use) is friendlier and means a
device in daily use never re-challenges. An absolute cap is safer. Do both — slide on use,
with a hard maximum of 90 days regardless of activity. Same pattern as idle vs absolute
session timeouts ([E04](../track-e/E04-session-ids.md)).

---

## The better alternative

Much of the demand for "remember this device" is really demand for *"MFA is annoying."*

**Passkeys remove the demand entirely.** A passkey is one gesture — a touch, a glance — and
it is a *stronger* factor than the TOTP code it replaces
([D14](D14-webauthn-and-passkeys-concepts.md)). There is nothing to skip, because there is
nothing tedious.

If you are considering building trusted devices, consider whether shipping passkeys first
is the better use of the same effort. It usually is: it removes the friction *and* raises
the security ceiling, where trusted devices remove friction by lowering it.

---

## Terms defined in this chapter

`device binding`

---

## What to remember

1. "Remember this device" is **a long-lived credential that replaces your second factor.**
   Design it like one.
2. 256-bit token, **hashed at rest**, expiring, revocable, in a `__Host-` cookie.
3. **Check that the token belongs to the user logging in.** The most-skipped check, and a
   universal bypass without it.
4. **Fingerprinting is a risk signal, never a credential.** Forgeable, unstable, and a
   privacy problem.
5. **Revoke on password change, MFA change, recovery code use, and "log out everywhere."**
6. **Never honour device trust for sensitive actions.** Step up instead.
7. Show the user their devices, with location and last-used, and a prominent "remove all."
8. **Passkeys remove the demand for this feature** by making MFA fast instead of skippable.

---

## Sources

- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §5.2 (reauthentication)
- [W3C: Privacy and fingerprinting mitigations](https://www.w3.org/TR/fingerprinting-guidance/)

---

**Next:** [D18 — Step-up auth and assurance levels (NIST AAL)](D18-step-up-auth-and-aal.md)
