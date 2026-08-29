# H13 — Audit logging: proving who did what

**Part H · Authorization** · *Builds on [H02](H02-the-enforcement-point.md)*
---

## Audit log ≠ application log

Two different things, constantly conflated:

| | Application log | **Audit log** |
|---|---|---|
| Purpose | Debugging, ops | **Accountability, forensics, compliance** |
| Audience | Developers | Security, auditors, the customer |
| Content | "cache miss", stack traces | **who / what / when / to what / allowed?** |
| Mutability | Rotates, gets deleted | **Append-only, retained, tamper-evident** |
| When written | Ad hoc | **On every security-relevant action** |
| If lost | Annoying | **You failed the audit / can't investigate** |

An application log is for *you*, to fix bugs. An audit log is for *others*, to answer "who did
what" — and it must survive, be trustworthy, and be complete. Treating your debug log as an
audit log is how audit trails fail exactly when you need them.

---

## What every audit entry must contain

The five W's, structured:

```
   WHO      the actor — user id, AND the real actor if impersonating   F19 / I04
   WHAT     the action — 'document.export', 'user.role.grant'
   WHEN     precise timestamp (UTC, with sub-second)
   WHICH    the target — resource type and id, tenant                  H09
   RESULT   allowed or denied — AND why
   + context: IP, user agent, session id (hashed), request id, auth level (amr/acr)  D18
```

```json
{
  "timestamp": "2026-08-28T14:03:22.481Z",
  "actor": { "user_id": "u_4471", "on_behalf_of": null },
  "action": "document.export",
  "target": { "type": "document", "id": "d_9182", "tenant_id": "t_88" },
  "result": "allowed",
  "context": {
    "ip": "203.0.113.9", "user_agent": "...",
    "session_id_hash": "a3f9...", "request_id": "req_...",
    "amr": ["pwd", "otp"], "acr": "aal2"
  }
}
```

Two fields punch above their weight:

- **`on_behalf_of`** — when support impersonates a user ([I04](../track-i/I04-admin-impersonation.md),
  [F19](../track-f/F19-token-exchange.md)), the audit log records *both* the user acted-as and
  the *real* actor. This is the difference between "the customer did it" and "our support agent
  did it," and it is exactly what impersonation-vs-delegation ([F19](../track-f/F19-token-exchange.md))
  is about. An impersonation audit that only logs the impersonated user is worthless.
- **`result` including denials** — logging *denied* actions is as important as allowed ones. A
  burst of denials is an attack in progress ([I09](../track-i/I09-detecting-account-takeover.md),
  [H14](H14-attack-your-own-authorization.md)); without them you see only the attacks that
  *succeeded*.

---

## Where to write it, and why at the enforcement point

The audit record belongs at the **PEP** ([H02](H02-the-enforcement-point.md)) — the moment the
authorized action happens — so it captures the *real* decision, not an inferred one:

```python
class DocumentService:
    def export(self, actor: User, doc_id: str):
        doc = self.repo.get(doc_id)
        allowed = self.authz.can(actor, "export", doc)

        # Audit BOTH outcomes, at the point of enforcement.
        self.audit.record(
            actor=actor, action="document.export",
            target=("document", doc_id, doc.tenant_id),
            result="allowed" if allowed else "denied",
            context=request_context(),
        )
        if not allowed:
            raise Forbidden()          # H02 — fail closed

        return self._do_export(doc)
```

Writing it at the service layer ([H02](H02-the-enforcement-point.md)) means every entry point —
API, GraphQL, CLI, job — that funnels through the service gets audited, once, correctly. Audit
at the edge and you miss internal paths; audit in the UI and you have nothing.

---

## Tamper-evidence: hash chaining

An audit log an attacker can edit proves nothing — after a breach, the first thing a
sophisticated attacker does is delete the evidence ([I10](../track-i/I10-incident-response.md)).
Make modification **detectable** with a hash chain ([B04](../track-b/B04-what-a-hash-function-is.md)):

```python
def append_entry(entry: dict, prev_hash: bytes) -> bytes:
    entry["prev_hash"] = prev_hash.hex()
    canonical = json.dumps(entry, sort_keys=True).encode()
    entry_hash = hashlib.sha256(canonical).digest()      # B04
    store.append(entry, entry_hash)
    return entry_hash
```

```
   entry₁ ─hash─▶ entry₂ ─hash─▶ entry₃ ─hash─▶ ...
   each entry includes the hash of the previous one.
```

Now removing or altering any entry breaks the chain from that point on — an auditor recomputing
the hashes detects it. This is the same construction as a blockchain and as Git's commit chain
([B06](../track-b/B06-collisions.md)), and it needs a collision-resistant hash for exactly the
reason [B06](../track-b/B06-collisions.md) gives (a collision would let an attacker swap an
entry without breaking the chain).

Stronger still: **write to append-only, access-controlled storage** — a WORM bucket, a separate
account an attacker who compromises the app cannot reach ([I10](../track-i/I10-incident-response.md)),
or a managed audit service (AWS CloudTrail-style). Defence in depth: hard to alter *and* hard to
delete.

---

## What NEVER goes in an audit log

The audit log is widely read (auditors, support, sometimes customers) and long-retained — so
putting secrets in it turns it into a credential store ([I08](../track-i/I08-observability.md)):

```
   ❌ passwords, tokens, session IDs (log a HASH if you need correlation)
   ❌ full authorization headers, cookies
   ❌ reset links, MFA codes, API keys
   ❌ unnecessary PII (log the user ID, not their whole profile)  I11
```

Log *identifiers*, not *secrets*: the user ID, not the token; the session ID's hash, not the
session ID; the resource ID, not its contents. This is the same rule as
[I08](../track-i/I08-observability.md), and it is violated constantly — "log the request for
debugging" quietly writes `Authorization: Bearer ...` into a permanent, searchable store.

---

## What to audit

Not everything — an audit log of every read is noise that hides the signal. Audit the
**security-relevant** and the **consequential**:

| Category | Examples |
|---|---|
| **Authentication** | login success/failure, MFA, password change, logout ([Track D](../track-d/D06-build-login-part-2-login.md)) |
| **Authorization changes** | role/permission granted or revoked, sharing, ownership transfer |
| **Sensitive data access** | export, bulk read, viewing another user's data |
| **Account lifecycle** | create, disable, delete, deprovision ([I03](../track-i/I03-deprovisioning.md)) |
| **Privileged actions** | impersonation ([I04](../track-i/I04-admin-impersonation.md)), config changes, key rotation ([I06](../track-i/I06-key-rotation.md)) |
| **Denials** | authorization failures, especially bursts |
| **The audit log itself** | who read it, attempts to disable it |

Reads of ordinary data are usually too voluminous to audit individually — but *bulk* reads and
*cross-user* reads are exactly the exfiltration signal you want ([I09](../track-i/I09-detecting-account-takeover.md)).

---

## Retention and access

- **Retain per your compliance regime** ([I11](../track-i/I11-compliance.md)) — often 1–7 years.
  This is longer than your debug logs, which is another reason to keep them separate.
- **Access to the audit log is itself audited.** Who read it, and when — because reading who
  did what is itself a sensitive action.
- **Customer-visible audit** is a feature: enterprise buyers want their *own* audit log
  ([I11](../track-i/I11-compliance.md)), scoped to their tenant ([H09](H09-multi-tenancy-isolation.md)).
  Build the tenant scoping in from the start.

---

## Terms defined in this chapter

`audit log`, `tamper-evident log`

---

## What to remember

1. **The audit log is the *proof* layer of authorization** — it answers "who did what," which
   arrives at the worst times.
2. **Audit log ≠ application log.** Different purpose, audience, mutability, retention. Don't
   conflate them.
3. Every entry: **who, what, when, which target, and the result (including *denials*)** — plus
   IP, session hash, and auth level.
4. **Log the real actor *and* the impersonated user** (`on_behalf_of`) — or impersonation
   audit is worthless.
5. **Write it at the enforcement point** (service layer), so every entry path is covered.
6. **Hash-chain entries for tamper-evidence**, and write to append-only, access-controlled
   storage an attacker can't reach.
7. **Never log secrets** — identifiers, not tokens; a session hash, not the session.
8. Audit the security-relevant and consequential — **including denials and bulk reads.** Retain
   per compliance; scope it per tenant for customers.

---

## Sources

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST SP 800-92 — Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
- [OWASP Top 10 — A09: Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

---

**Next:** [H14 — Broken access control: IDOR, privilege escalation, mass assignment](H14-attack-your-own-authorization.md)
