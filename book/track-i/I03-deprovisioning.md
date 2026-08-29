# I03 — Deprovisioning: the offboarding gap that fails audits

**Part I · Identity lifecycle & operations** · *Builds on [I02](I02-provisioning-and-scim.md)*
---

## Why deprovisioning is the audit failure

Auditors ask one question above all others about identity: **"When someone leaves, how quickly
and completely do they lose access?"** It is the question because:

- **The forcing function is weakest here** ([I01](I01-identity-lifecycle.md)). A missing joiner
  provision means someone can't work — noticed immediately. A missing deprovision means an
  ex-employee's access lingers — noticed by *no one*, because nothing breaks.
- **The risk is highest here.** A departed employee may have credentials *and* motive, and their
  lingering access is a standing, unmonitored entry point.
- **It's genuinely hard** — access is spread across many systems, credential types, and paths,
  and removing *all* of it requires knowing about all of it.

The result is the [I01](I01-identity-lifecycle.md) failure: 147 orphaned accounts, contractors
from three years ago, shared credentials nobody rotated.

---

## The many paths that must all close

The Saturday failure shows the shape: SSO is *one* path, and closing it leaves the others open.
Complete deprovisioning must reach **every** access path:

```
   ☐ SSO / IdP account          disabled (the one everyone does)         G11
   ☐ Application sessions        killed — SCIM active:false + revoke      I02 / E13
   ☐ Refresh tokens              revoked (families)                       E10
   ☐ Personal API keys / PATs    revoked                                  J02
   ☐ SSH keys                    removed
   ☐ Service accounts they owned  reassigned or disabled                  J03
   ☐ Shared account passwords    ROTATED (they know them)                 J03
   ☐ Cloud IAM credentials       removed
   ☐ VPN / network access        revoked
   ☐ Physical access (badges)    revoked
   ☐ SaaS tools outside central IT  the ones nobody tracked  ← the hard part
   ☐ Data they can still reach via delegated grants / shares  H03/H07
```

Two rows are the ones people miss:

**Shared account passwords must be *rotated*, not just "the person removed."** If four people
knew the `admin@` password ([J03](../track-j/J03-service-accounts.md)), removing one person's
name changes nothing — they still know the password. Departure of anyone who knew a shared
secret means **rotating** that secret ([I06](I06-key-rotation.md)). This is a strong argument
against shared accounts existing at all.

**SaaS tools outside central IT** — the marketing team's analytics tool, the design team's
Figma, the credential a developer created for a one-off integration. Central IT deprovisions
what it *knows about*; shadow IT is exactly what it doesn't. This is why SCIM
([I02](I02-provisioning-and-scim.md)) from a single source of truth matters: it reaches every
*connected* app automatically, shrinking the set that requires manual removal.

---

## Deprovisioning that actually removes access

Setting a flag is not deprovisioning. The account must be **prevented from future use AND cut
off from current use**:

```python
def deprovision_user(user_id: str, reason: str):
    with db.transaction():
        # 1. Prevent future logins.
        db.deactivate_user(user_id)                       # active = false

        # 2. Cut off CURRENT access — the step people skip.
        db.delete_all_sessions_for(user_id)               # E13 — every device
        revoke_all_refresh_families(user_id)              # E10
        revoke_all_personal_api_keys(user_id)             # J02
        revoke_all_trusted_devices(user_id)               # D17

        # 3. Handle what they OWNED (not just what they accessed).
        reassign_or_disable_service_accounts(owner=user_id)   # J03
        flag_shared_secrets_for_rotation(user_id)             # I06

        # 4. Prove it happened.
        audit_log("user.deprovisioned", user_id=user_id, reason=reason)   # H13

    # 5. Trigger downstream (SaaS tools via SCIM outbound, if you're the source).
    notify_downstream_systems(user_id, "deprovisioned")
```

**Steps 2 and 3 are what separate real deprovisioning from a flag.** Step 2 revokes *live*
access — the open sessions and long-lived tokens that outlive an SSO disable
([E10](../track-e/E10-token-lifetimes-and-rotation.md), [E13](../track-e/E13-sessions-across-devices.md)).
Step 3 handles what the user *owned* — service accounts and shared secrets that don't disappear
when the human does ([J03](../track-j/J03-service-accounts.md)).

Note how short session/token lifetimes ([E10](../track-e/E10-token-lifetimes-and-rotation.md),
[E11](../track-e/E11-revocation.md)) help: if access tokens live 5 minutes, the window between
"SSO disabled" and "all access gone" is small even before explicit revocation. This is another
reason the whole book favours short-lived credentials.

---

## Speed matters: the offboarding SLA

"Eventually" is not an answer. Deprovisioning has a time dimension, and different departures
need different urgency:

| Departure | Target |
|---|---|
| Planned, amicable | Same day / by end of last day |
| Immediate (for cause) | **Immediately, before they're told** — access cut *first* |
| Contractor / temp | On a scheduled end date, automatically |

The for-cause case is why deprovisioning must be *fast and coordinated*: HR and IT act in
lockstep so access is gone before the person has a chance to react. A deprovisioning process
measured in days fails this entirely.

Automation ([I02](I02-provisioning-and-scim.md)) is what makes speed achievable: one event at
the source (HR marks departed) triggers deprovisioning everywhere in seconds. Manual
deprovisioning across forty systems cannot be fast *or* complete.

---

## Machine deprovisioning: the silent orphans

Humans at least *leave* — there's an event. Machine identities
([Track J](../track-j/J01-machine-identity-is-not-user-identity.md)) have no such event, so their
deprovisioning is even more neglected ([I01](I01-identity-lifecycle.md)):

- A service is decommissioned but its **service account** stays valid ([J03](../track-j/J03-service-accounts.md)).
- An integration is removed but its **API key** is never revoked ([J02](../track-j/J02-api-keys.md)).
- A CI pipeline is deleted but its credential lives on.

Defence: **credentials with no recent use are the signal.** Track last-use on every credential
([J02](../track-j/J02-api-keys.md)), and automatically flag — then disable — anything unused for
N days. An unused, long-lived, high-privilege credential is an orphan waiting to be exploited.

---

## Verification: the audit-proof part

Auditors don't want to hear "we deprovision people." They want **evidence**:

- **A deprovisioning audit log** ([H13](../track-h/H13-audit-logging.md)) — who was
  deprovisioned, when, by what, and confirmation each system was reached.
- **Periodic access reviews** ("attestation") — managers confirm their reports' access is still
  appropriate, catching movers ([I01](I01-identity-lifecycle.md)) and any leavers the automation
  missed.
- **Orphaned-account scans** — a regular job that finds accounts with no matching active
  employee, and active credentials with no recent use.

These turn "we have a process" into "here is proof the process ran," which is what passing an
audit actually requires ([I11](I11-compliance.md)).

---

## Terms defined in this chapter

`deprovisioning`, `orphaned account`

---

## What to remember

1. **"Disabled the SSO account" ≠ "removed all access."** The gap — open sessions, personal
   tokens, SSH keys, shadow SaaS — is where deprovisioning fails.
2. It's **the audit failure** because the forcing function is weakest (nothing breaks) and the
   risk is highest (credentials + motive).
3. **Close every path:** sessions, refresh tokens, API keys, SSH keys, service accounts, shared
   secrets, cloud IAM, shadow IT.
4. **Rotate shared secrets** on any knower's departure — removing a name changes nothing.
5. **Kill live access, not just a flag** ([E10](../track-e/E10-token-lifetimes-and-rotation.md),
   [E13](../track-e/E13-sessions-across-devices.md)); handle what the user *owned*, not just
   accessed.
6. **Speed matters** — for-cause departures need access cut *before* the person is told.
   Automate ([I02](I02-provisioning-and-scim.md)) to make it fast and complete.
7. **Machine orphans are silent** — flag and disable credentials with no recent use.
8. **Verify with audit logs, access reviews, and orphan scans** — auditors want evidence, not a
   description.

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 10
- [NIST SP 800-53 — AC-2 Account Management](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [SOC 2 Common Criteria — logical access provisioning and deprovisioning](https://www.aicpa-cima.com/)

---

**Next:** [I04 — Admin impersonation: letting support log in as a user, safely](I04-admin-impersonation.md)
