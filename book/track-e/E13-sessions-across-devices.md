# E13 — Sessions across devices: listing, remote logout, "log out everywhere"

**Part E · Sessions & tokens** · *Builds on [E03](E03-build-server-side-sessions.md)*
---

## What a session list is for

Three distinct jobs, and the third is the one that gets underrated:

**1. The user can end a session.** Lost laptop, shared computer, ex-partner's tablet.

**2. You can end sessions.** Password change, suspected compromise, employee offboarding
([I03](../track-i/I03-deprovisioning.md)).

**3. The user can *see* something wrong.** A device they do not recognise, a country they
have never visited. This is often the **only** way an account takeover is discovered
([I09](../track-i/I09-detecting-account-takeover.md)) — the attacker leaves no other trace
the user can perceive.

Job 3 makes this a detection mechanism, not merely a convenience.

---

## The data you need

Already present in [E03](E03-build-server-side-sessions.md)'s schema:

```sql
CREATE TABLE sessions (
  id            bytea PRIMARY KEY,          -- SHA-256 of the token
  user_id       uuid NOT NULL,
  created_at    timestamptz NOT NULL,
  last_seen_at  timestamptz NOT NULL,
  expires_at    timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  ip            inet,
  user_agent    text,
  label         text,                       -- "Chrome on macOS"
  auth_time     timestamptz NOT NULL,       -- D18
  amr           text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX ON sessions (user_id);
```

**This is why server-side sessions are the default recommendation.** With opaque sessions
you get this list for free — it *is* the store. With self-contained tokens you must build a
parallel registry, which is the same table plus the complexity
([E09](E09-should-you-use-jwts-for-sessions.md)).

### Deriving a useful label

```python
def friendly_device_name(request) -> str:
    ua = parse_user_agent(request.headers.get("User-Agent", ""))
    browser  = ua.browser.family or "Unknown browser"
    platform = ua.os.family or "Unknown OS"
    return f"{browser} on {platform}"          # "Safari on iPhone"
```

Imperfect and forgeable ([A04](../track-a/A04-headers.md)) — it is for **human
recognition**, never for a security decision. Combine with a coarse location:

```python
def coarse_location(ip) -> str:
    g = geoip_lookup(ip)
    return f"{g.city}, {g.country}" if g else "Unknown location"
```

**City-level, never precise.** Precise geolocation in a settings page is a stalking risk if
the account is shared or compromised.

---

## The interface

```
Where you're signed in                              [ Sign out everywhere else ]

  💻  Chrome on macOS              THIS DEVICE
      London, UK · Active now · Signed in 3 days ago with a passkey

  📱  Safari on iPhone
      London, UK · Last active 2 hours ago                        [ Sign out ]

  💻  Firefox on Windows                                    ⚠️ Unrecognised
      Lagos, NG · Last active 4 days ago · Password only         [ Sign out ]
```

Design decisions that matter:

- **Mark the current device**, so a user does not sign themselves out and panic.
- **"Sign out everywhere else"** as the prominent action. It is what a worried user wants,
  and it should not require them to work out which row is suspicious.
- **Show how they authenticated** (`amr`, from [D18](../track-d/D18-step-up-auth-and-aal.md)).
  "Password only" versus "passkey" is meaningful, and it teaches users why the stronger
  option matters.
- **Flag the unusual** — a new country, a new device, an unusual time.
- **Merge with trusted devices** ([D17](../track-d/D17-remember-this-device.md)) and
  connected applications ([F07](../track-f/F07-access-refresh-scopes.md)) into **one page**
  that answers *"what has access to my account?"*

```python
@app.get("/settings/sessions")
@login_required
def list_sessions():
    rows = db.query("""
        SELECT id, created_at, last_seen_at, ip, user_agent, label, amr
          FROM sessions
         WHERE user_id = %s AND expires_at > now()
      ORDER BY last_seen_at DESC
    """, (g.user.id,))

    current = sha256(request.cookies["__Host-session"].encode()).digest()

    return render("sessions.html", sessions=[{
        "id":        base64.urlsafe_b64encode(r.id).decode(),   # opaque handle
        "label":     r.label,
        "location":  coarse_location(r.ip),
        "last_seen": r.last_seen_at,
        "amr":       r.amr,
        "is_current": r.id == current,
        "suspicious": is_unusual(g.user.id, r),
    } for r in rows])

@app.post("/settings/sessions/<sid>/revoke")
@login_required
def revoke_session(sid):
    target = base64.urlsafe_b64decode(sid)

    # ← The check that makes this safe. Without it, any user ends any
    #   session by guessing an ID.  IDOR — H14.
    deleted = db.execute(
        "DELETE FROM sessions WHERE id = %s AND user_id = %s",
        (target, g.user.id),
    )
    if deleted:
        audit_log("session.revoked", user_id=g.user.id, session=sid)
    return redirect("/settings/sessions")

@app.post("/settings/sessions/revoke-all")
@login_required
@require_recent_authentication(max_age_seconds=300)      # D18
def revoke_all_sessions():
    current = sha256(request.cookies["__Host-session"].encode()).digest()

    with db.transaction():
        n = db.execute("DELETE FROM sessions WHERE user_id = %s AND id <> %s",
                       (g.user.id, current))
        db.delete_all_refresh_families_for(g.user.id)         # E10
        db.delete_all_trusted_devices_for(g.user.id)          # D17

    audit_log("session.revoked_all", user_id=g.user.id, count=n)
    notify_user(g.user.id, f"You signed out of {n} other devices.")
    return redirect("/settings/sessions")
```

Four things in that code:

**`AND user_id = %s`** in the delete. Without it, changing the ID in the request ends someone
else's session — an IDOR ([H14](../track-h/H14-attack-your-own-authorization.md)) that is
also a denial of service.

**Step-up on "revoke all."** An attacker with a hijacked session should not be able to lock
the real user out ([D18](../track-d/D18-step-up-auth-and-aal.md)).

**Revoke refresh families and trusted devices too.** Otherwise "log out everywhere" is
cosmetic — the attacker's refresh token mints a new session immediately
([E10](E10-token-lifetimes-and-rotation.md)), or their trusted-device cookie skips MFA
([D17](../track-d/D17-remember-this-device.md)).

**Notify.** The user should get an email confirming what happened.

---

## Everything "log out everywhere" must reach

This is the checklist people get wrong, and getting it wrong makes the feature a lie:

```
☐  All sessions except (optionally) the current one
☐  All refresh token families                         E10
☐  All trusted-device tokens                          D17
☐  All pending MFA states                             D06
☐  Any cached authorization decisions                 H12
☐  Any active WebSocket / SSE connections             ← the forgotten one
☐  Any long-running jobs started under a session
☐  Third-party OAuth grants?  ← a product decision; usually NOT
☐  A notification email
```

**Live connections are the one people forget.** A WebSocket authenticated at connect time
stays open after the session is deleted, because nothing re-checks. If you have real-time
features, you need a revocation channel:

```python
def revoke_session(session_hash):
    db.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
    pubsub.publish("session.revoked", {"session": session_hash.hex()})
    # Each WebSocket server closes any connection bound to that session.
```

Or, more simply: **re-validate the session periodically on long-lived connections** —
every 60 seconds, or on every inbound message.

---

## Automatic revocation

Revoke without being asked, on:

| Event | Scope |
|---|---|
| Password change or reset | **All** ([D09](../track-d/D09-account-recovery.md)) |
| MFA method added or removed | All |
| Recovery code used | All except current, plus notify |
| Email address changed | All |
| Account disabled or deleted | All |
| Role reduced | All (so new permissions apply immediately) |
| Refresh token reuse detected | The family, plus its sessions ([E10](E10-token-lifetimes-and-rotation.md)) |
| Impossible travel detected | Step up, or revoke ([I09](../track-i/I09-detecting-account-takeover.md)) |
| Employee offboarded (SCIM deprovision) | **All, immediately** ([I03](../track-i/I03-deprovisioning.md)) |

The offboarding row is the one auditors ask about, and it is why deprovisioning must reach
the session store rather than only setting a flag on the user record.

---

## Terms defined in this chapter

`device session`, `global logout`

---

## What to remember

1. Three jobs: the user ends a session, **you** end sessions, and the user **notices**
   something wrong. The third is often the only detection you get.
2. Server-side sessions give you the list for free. It *is* the store.
3. Device labels are for **human recognition**, never for security decisions. Location is
   **city-level only**.
4. **`AND user_id = ?` on the delete**, or revocation is an IDOR.
5. **Step up before "log out everywhere"**, so an attacker cannot lock the owner out.
6. **"Log out everywhere" must reach refresh families, trusted devices, and live WebSocket
   connections** — or it is a lie.
7. Revoke automatically on password change, MFA change, role reduction, and deprovisioning.

---

## Sources

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §5.2 (session termination)
- [The Copenhagen Book — Sessions](https://thecopenhagenbook.com/sessions)

---

**Next:** [E14 — Why logging out is genuinely hard](E14-why-logout-is-hard.md)
