# J03 — Service accounts and their failure modes

**Part J · Machine, workload & agent identity** · *Builds on [J01](J01-machine-identity-is-not-user-identity.md)*
---

## What a service account is

> **A service account is a non-human identity created inside a system that was designed for human
> users** — so it has a username, often a password, and lives in the same account store as people.

They exist because sometimes you need a machine to act within a human-oriented system (a database,
a SaaS tool, a legacy app) that only understands "accounts." They're a pragmatic necessity, and
also a magnet for trouble, because the human-account model fits machines badly
([J01](J01-machine-identity-is-not-user-identity.md)).

---

## The failure modes, and their fixes

Service accounts fail in a handful of distinct, nameable ways, each with a specific defence:

### 1. Static, shared, un-rotated credentials

The password never changes and many people know it. When anyone who knew it leaves
([I03](../track-i/I03-deprovisioning.md)), the secret is compromised — but nobody rotates it,
because "who rotates the robot's password?" ([J01](J01-machine-identity-is-not-user-identity.md)).

**Fix:** prefer **credentials the platform issues and rotates automatically** — workload identity
([J05](J05-workload-identity-spiffe.md)), client credentials with short-lived tokens
([F10](../track-f/F10-client-credentials.md)), or at minimum a secret in a manager with automated
rotation ([I05](../track-i/I05-secrets-management.md), [I06](../track-i/I06-key-rotation.md)). The
goal is **no long-lived shared secret in a config file.**

### 2. Privilege accumulation

Over time the account gains permissions until it's over-powered — the mover problem
([I01](../track-i/I01-identity-lifecycle.md)) with no forcing function, because a machine never
changes roles to prompt a review.

**Fix:** **least privilege** ([H01](../track-h/H01-where-does-authz-live.md)), enforced by *one
account per service, per purpose* (below), and **periodic access review** of service accounts
([I03](../track-i/I03-deprovisioning.md)) — because nothing else will catch the creep.

### 3. No ownership

Nobody owns it, so nobody rotates it, reviews it, or removes it. Ownerless credentials are how
orphans form.

**Fix:** **every service account has a named human or team owner**, recorded, responsible for its
lifecycle. An account with no owner is flagged for removal.

### 4. It's an orphan

The service is gone; the account lives on ([I01](../track-i/I01-identity-lifecycle.md),
[I03](../track-i/I03-deprovisioning.md)) — a standing, unmonitored credential an attacker can find.

**Fix:** **last-used tracking** ([J02](J02-api-keys.md)) and automated flagging of accounts unused
for N days; tie the account's lifecycle to the service's ([I03](../track-i/I03-deprovisioning.md)).

### 5. It weakens the human account system

Because it can't do MFA ([D11](../track-d/D11-sms-second-factor.md)), it becomes a documented
*exception* in your security policy — and exceptions accumulate and erode the policy.

**Fix:** **don't put machines in the human account store at all** where you can avoid it. Use a
machine-identity mechanism ([F10](../track-f/F10-client-credentials.md), [J04](J04-mtls.md),
[J05](J05-workload-identity-spiffe.md)) so your human MFA policy has no exceptions.

---

## The golden rules

Distilling the fixes into policy:

```
   1. ONE per service, per purpose.   No shared accounts. A leak/departure
                                      affects one service, and you know which.  I03
   2. LEAST privilege.                Scoped to exactly what THAT service needs.  H01
   3. Every account has an OWNER.     A named human/team responsible for it.
   4. NO long-lived shared secrets.   Platform-issued, auto-rotated credentials.  J05/I06
   5. AUDITED and monitored.          Every action attributable; last-used tracked.  H13/J02
   6. LIFECYCLE-managed.              Provisioned, reviewed, and DEPROVISIONED with
                                      the service.  I01/I03
   7. Prefer NOT a human-store account at all.  Use machine-identity tools.  F10/J04/J05
```

Rule 1 does the most work. A **shared** service account (`db-user` used by five services) means: a
compromise affects all five, a departure of anyone who knew the password compromises all five, and
you can't tell *which* service did *what* in the audit log ([H13](../track-h/H13-audit-logging.md)).
One account per service per purpose makes every one of those tractable — the leak is contained, the
audit is attributable, and the least-privilege scope is meaningful.

---

## The better answer: don't use a service account

The recurring theme of this track ([J01](J01-machine-identity-is-not-user-identity.md),
[J05](J05-workload-identity-spiffe.md)): the safest service-account is the one that doesn't exist.
Where the platform supports it, replace the human-style account with **workload identity**:

```
   HUMAN-STYLE SERVICE ACCOUNT          WORKLOAD IDENTITY  J05
   ────────────────────────────          ─────────────────
   username + static password           the platform ATTESTS what the workload is
   in a config file                     → short-lived credential, auto-rotated
   never rotates                        → no static secret to leak, share, or forget
   an exception to MFA policy           → cryptographic proof, no MFA question
```

- **Cloud** (AWS IAM roles, GCP service accounts with workload identity federation, Azure managed
  identities): the workload assumes an identity based on *where it runs*, with no static key
  ([I05](../track-i/I05-secrets-management.md), [F10](../track-f/F10-client-credentials.md)).
- **Kubernetes / mesh**: SPIFFE/SPIRE gives each workload a short-lived certificate
  ([J05](J05-workload-identity-spiffe.md), [J04](J04-mtls.md)).

Note that cloud "service accounts" (GCP, AWS) done *this* way — assumed via workload identity
rather than a downloaded key — avoid the whole failure list. The anti-pattern is specifically the
*human-style account with a static shared password*; a platform-attested, auto-rotated machine
identity is the good version.

---

## When you're stuck with one

Legacy systems and some SaaS tools only understand username/password accounts. If you must:

- **One per purpose, named owner, least privilege** (the golden rules).
- **Secret in a manager, rotated** ([I05](../track-i/I05-secrets-management.md), [I06](../track-i/I06-key-rotation.md)) —
  never in a config file, never shared in chat.
- **IP-allowlist** the account where the system supports it, so a leaked credential is only usable
  from your infrastructure.
- **Monitor and alert** on its use ([I08](../track-i/I08-observability.md), [I09](../track-i/I09-detecting-account-takeover.md)) —
  a service account logging in from a new location is a near-certain compromise.
- **Track it in an inventory** so it's reviewed and deprovisioned, not forgotten.

---

## Terms defined in this chapter

`service account`

---

## What to remember

1. **A service account is a non-human identity in a human-oriented system** — a pragmatic necessity
   and a magnet for the [J01](J01-machine-identity-is-not-user-identity.md) failure.
2. **The failure modes:** static shared un-rotated secrets, privilege accumulation, no ownership,
   orphans, and weakening the MFA policy — all from treating a machine like a human.
3. **Golden rules:** one per service per purpose, least privilege, a named owner, no long-lived
   shared secrets, audited, lifecycle-managed.
4. **Rule 1 does the most work** — shared accounts break containment, attribution, and least
   privilege all at once.
5. **The better answer is workload identity** ([J05](J05-workload-identity-spiffe.md)) — the
   platform attests the workload, no static secret exists. Cloud service accounts done *this* way
   avoid the whole failure list.
6. **The anti-pattern is specifically the human-style static-password account** — not machine
   identity itself.
7. **If stuck with one:** named owner, least privilege, managed rotated secret, IP-allowlist,
   monitor, inventory.

---

## Sources

- [Google Cloud: Best practices for service accounts](https://cloud.google.com/iam/docs/best-practices-service-accounts)
- [AWS: IAM roles vs. long-term access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)
- [SPIFFE](https://spiffe.io/) ([J05](J05-workload-identity-spiffe.md))
- [CISA / NSA: Managing non-human identities guidance](https://www.cisa.gov/)

---

**Next:** [J04 — mTLS: mutual authentication at the transport layer](J04-mtls.md)
