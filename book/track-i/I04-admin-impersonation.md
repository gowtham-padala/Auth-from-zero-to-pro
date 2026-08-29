# I04 — Admin impersonation: letting support log in as a user, safely

**Part I · Identity lifecycle & operations** · *Builds on [F19](../track-f/F19-token-exchange.md), [H13](../track-h/H13-audit-logging.md)*
---

## The core rule: delegation, not impersonation

The naive version *replaces* the identity — the session becomes the customer, and nothing
records that an admin is really acting. This is **impersonation** in the
[F19](../track-f/F19-token-exchange.md) sense, and it destroys accountability.

The safe version is **delegation** ([F19](../track-f/F19-token-exchange.md)): the admin acts
*for* the user, and **both identities are recorded on every action**:

```
   ❌ IMPERSONATION:  session.user = customer          → "customer did it"
   ✅ DELEGATION:     session = {                       → "agent did it AS customer"
                        acting_as: customer,
                        real_actor: support_agent,      ← never lost
                      }
```

Every action carries both, exactly the `sub` / `act` distinction from
[F19](../track-f/F19-token-exchange.md): `sub` is who it's *for* (the customer), `act` is who's
*doing* it (the agent). The audit log ([H13](../track-h/H13-audit-logging.md)) records both, so
"the customer did it" is never a lie the system tells.

---

## Safe impersonation

```python
def start_impersonation(admin: User, target_user_id: str, reason: str):
    # 1. Authorize it — not every admin, and step up. D18.
    if not admin.can("support:impersonate"):
        raise Forbidden()
    require_recent_authentication(admin, max_age=60, min_acr="aal2")   # D18

    # 2. Require a REASON. No impersonation without a stated purpose.
    if not reason or len(reason) < 10:
        raise ValueError("a reason is required")

    # 3. Create a DELEGATION session — both identities, time-boxed.
    session = create_session(
        acting_as=target_user_id,           # sub — who it's FOR
        real_actor=admin.id,                # act — who's DOING it   F19
        is_impersonation=True,
        reason=reason,
        expires_at=now() + timedelta(minutes=30),   # short-lived
        read_only=default_read_only(admin),         # see below
    )

    # 4. Loud audit + notify the user. H13.
    audit_log("impersonation.start", actor=admin.id, target=target_user_id, reason=reason)
    notify_user(target_user_id,
                f"A support agent accessed your account to help with: {reason}")   # ★
    return session

def authorize_action(session, action, resource):
    # The real actor's identity is ALWAYS available and ALWAYS logged.
    allowed = authz.can(session.acting_as, action, resource)      # customer's permissions
    if session.is_impersonation:
        # Impersonation can't EXCEED the user's own access, and often less.
        if session.read_only and is_write(action):
            allowed = False                          # read-only impersonation
        audit_log("impersonated_action", real_actor=session.real_actor,
                  acting_as=session.acting_as, action=action, resource=resource)  # H13
    return allowed
```

Six controls, each closing a specific abuse:

| Control | Prevents |
|---|---|
| **Authorized + step-up** ([D18](../track-d/D18-step-up-auth-and-aal.md)) | Any staff member impersonating anyone |
| **Mandatory reason** | Casual, curiosity-driven access |
| **Delegation, not replacement** ([F19](../track-f/F19-token-exchange.md)) | The unauditable-backdoor failure |
| **Time-boxed** (30 min) | A standing impersonation session left open |
| **Read-only by default** | Support changing customer data |
| **Notify the user** (★) | Silent access — the customer *knows* |

---

## Read-only by default

Most support tasks are *diagnostic* — "what does the user see?" — and need only read access.
Making impersonation **read-only by default** means an agent can reproduce a display bug without
the ability to change anything, which removes the highest-risk actions from the common case.

Write access during impersonation should be a **separate, higher-friction escalation** —
additional authorization, a stronger reason, perhaps a second approver
([D09](../track-d/D09-account-recovery.md)'s two-person model) — and *never* for the most
sensitive actions:

```python
# Even with write impersonation, block the actions that redefine access.
NEVER_IMPERSONATE = {"password.change", "email.change", "mfa.remove",
                     "payment.change", "account.delete", "impersonate"}
```

An agent must not be able to, *as the customer*, change the customer's password, remove their
MFA, or start impersonating *someone else*. These are the actions that would let impersonation
become account takeover ([D18](../track-d/D18-step-up-auth-and-aal.md)).

---

## Make it obvious, everywhere

Two audiences must always know impersonation is active:

**The agent** — an unmissable banner, so they never forget they're acting as someone else and
never mistake the customer's data for a test account:

```
   ┌──────────────────────────────────────────────────────────────┐
   │ ⚠️ You are viewing as ALICE SMITH (alice@acme.com) · read-only │
   │    Reason: "reproduce export bug #4821"    [ Exit impersonation ]│
   └──────────────────────────────────────────────────────────────┘
```

**The customer** — the notification (★ above), and a visible entry in *their* account activity
([E13](../track-e/E13-sessions-across-devices.md)): "A support agent accessed your account on
[date] for [reason]." Transparency is both a trust feature and a control — a customer who can
see impersonation happening is a check on its misuse. Some regulated products *require* this
consent/visibility.

---

## Rotate the session on entry and exit

Impersonation is a privilege change ([E04](../track-e/E04-session-ids.md)) — treat it like one:

- **Regenerate the session ID** when impersonation starts *and* when it ends
  ([D06](../track-d/D06-build-login-part-2-login.md), [E04](../track-e/E04-session-ids.md)).
  This prevents a fixation-style confusion between the admin's real session and the
  impersonation session, and ensures exiting cleanly restores the admin's own identity.
- **On exit, return to the admin's identity** — not a logged-out state, and never a lingering
  "acting as" flag. Audit the exit too.

```python
def stop_impersonation(session):
    audit_log("impersonation.end", real_actor=session.real_actor,
              acting_as=session.acting_as, duration=session.age())   # H13
    return rotate_to_admin_session(session.real_actor)     # back to the admin, new session id
```

---

## The alternatives to impersonation

Impersonation is powerful and risky; sometimes a lower-risk tool fits the actual need:

- **A read-only "view as user" that renders the customer's UI from admin context** — shows what
  the user sees without an impersonation session at all. Good for diagnostic tasks.
- **Customer-initiated support access** — the customer clicks "grant support access for 24
  hours," so access is *consented* and time-boxed. Strongest model where the customer is
  available (Stripe, GitHub, and others use this).
- **Better diagnostics** — detailed, privacy-preserving logs and error reports
  ([I08](I08-observability.md)) that let support reproduce issues without account access.

Reach for full impersonation only when reproducing the user's exact authenticated state is
genuinely required — and even then, read-only, delegated, and consented where possible.

---

## Terms defined in this chapter

`impersonation (admin)`, `break-glass`

---

## What to remember

1. **Naive "login as user" is an unauditable backdoor.** The safe version is entirely in *how*
   it's built.
2. **Delegation, not impersonation:** record *both* the real actor and the acted-as user on
   every action ([F19](../track-f/F19-token-exchange.md), [H13](../track-h/H13-audit-logging.md)).
   "The customer did it" must never be a lie.
3. **Authorize it, step up, require a reason, time-box it** — impersonation is a privileged
   action, not a convenience.
4. **Read-only by default;** write is a separate escalation, and credential-changing actions are
   **never** impersonable.
5. **Notify the customer and show the agent a banner** — transparency is a control.
6. **Rotate the session on entry and exit**, and return cleanly to the admin's identity.
7. **Prefer lower-risk alternatives** — "view as," customer-consented access, better diagnostics
   — when they meet the need.

---

## Sources

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) §1.1 (delegation vs impersonation)
- [OWASP Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Stripe / GitHub: customer-consented support access patterns](https://docs.stripe.com/)

---

**Next:** [I05 — Secrets management: KMS, vaults, and never in git](I05-secrets-management.md)
