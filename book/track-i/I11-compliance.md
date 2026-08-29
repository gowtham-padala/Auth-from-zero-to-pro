# I11 — Compliance without a lawyer: SOC 2, GDPR, data minimization in tokens

**Part I · Identity lifecycle & operations** · *Builds on [I03](I03-deprovisioning.md), [I08](I08-observability.md)*
> Not legal advice. This is the engineer's-eye view: what these regimes actually require of your
> auth system, and why most of it is things you should do anyway.

---

## The regimes, and what they want of auth

You'll meet a handful. The engineer's summary of each:

| Regime | What it is | What it wants from your auth |
|---|---|---|
| **SOC 2** | An audit of security *controls* (not a law) | Provisioning/deprovisioning, access control, audit logs, encryption, MFA — with **evidence** |
| **GDPR** | EU data protection *law* | Lawful basis, data minimisation, breach notification, right to erasure/access |
| **HIPAA** | US health data law | Access controls, audit trails, encryption for PHI |
| **PCI DSS** | Payment card standard | Strong auth, MFA, no storing raw card data, access logging |
| **ISO 27001** | Security management standard | Documented controls across the board |

The pattern across all of them: they don't ask for anything exotic. They ask for **least
privilege, deprovisioning, audit logging, encryption, MFA, and documentation** — every one of
which is a chapter in this book, and every one of which you should do regardless of any auditor.

---

## SOC 2: prove the operational hygiene

SOC 2's relevant criteria map almost one-to-one onto Track I:

```
   Logical access provisioning     → I02  (SCIM, JIT)
   Logical access deprovisioning   → I03  (the one auditors scrutinise most)
   Access authorization            → Track H
   Audit logging                   → H13  (and it must be tamper-evident)
   Encryption of sensitive data    → B05/I05
   Key management                  → I05/I06
   Incident response               → I10
   MFA                             → D11/D12/D14
```

The word that matters is **evidence**. SOC 2 doesn't ask "do you deprovision?" — it asks "*show
me* the deprovisioning records for the last twelve months." So the operational controls must
*produce artifacts*:

- **Deprovisioning** ([I03](I03-deprovisioning.md)) must log each removal — that log *is* the
  evidence.
- **Access reviews** ([I03](I03-deprovisioning.md)) — periodic attestation that access is still
  appropriate — must be recorded.
- **The audit log** ([H13](../track-h/H13-audit-logging.md)) must be tamper-evident, or it isn't
  trustworthy evidence.
- **Key rotation** ([I06](I06-key-rotation.md)) must be documented and dated.

This is why the earlier chapters keep insisting on *logging* the action, not just doing it: the
log is what turns a control into auditable evidence. Build for evidence from day one and SOC 2 is
largely a matter of collecting what you already produce.

---

## GDPR: minimisation, erasure, and the token angle

GDPR is where auth *architecture* meets law, in a few specific ways:

**Data minimisation.** Collect and carry only the data you actually need. This has a direct,
often-missed implication for **tokens**:

> **Every claim you put in a JWT is personal data broadcast to every service that receives the
> token** ([E05](../track-e/E05-jwt-part-1-three-parts.md), [G03](../track-g/G03-id-token-vs-access-token.md)).

Stuffing `email`, `name`, `phone`, `address` into an access token that flows to a dozen internal
services ([H12](../track-h/H12-authz-in-microservices.md)) spreads PII far wider than necessary —
and it's readable by anyone who gets the token ([E05](../track-e/E05-jwt-part-1-three-parts.md)).
Minimise: put an **identifier** in the token, and have services look up the PII they actually need
([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md), [H12](../track-h/H12-authz-in-microservices.md)).
This is the [E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)/[H12](../track-h/H12-authz-in-microservices.md)
"identity in the token, data looked up at use" principle, now with a legal reason behind it.

The same applies to **logs** ([I08](I08-observability.md)): auth logs are personal data
(IPs, locations), so minimise what you log, bound retention, and control access.

**Right to erasure ("right to be forgotten").** A user can demand deletion of their data — which
your identity architecture must support. This is much easier if you **own your user table**
([C05](../track-c/C05-build-vs-buy.md)) with a clear key, and harder if identity data is scattered
or locked in a provider. The account-linking design ([G12](../track-g/G12-account-linking.md)) —
a local user keyed on `(iss, sub)` — is what makes "delete this human's data everywhere" tractable.

**Right of access.** A user can demand a copy of their data — including, often, their login and
activity history ([E13](../track-e/E13-sessions-across-devices.md)) and audit trail
([H13](../track-h/H13-audit-logging.md)). Build these as user-facing features and you satisfy the
right *and* provide a security control ([I09](I09-detecting-account-takeover.md)).

**Breach notification.** 72 hours to notify the supervisory authority
([I10](I10-incident-response.md)) — a hard clock the incident runbook must account for.

---

## Data minimisation as a security principle, not just a legal one

The through-line: **minimisation is good security regardless of GDPR.** Every piece of data you
don't collect is data that can't leak; every claim not in the token is PII not broadcast; every
log field not captured is not sitting in your aggregator. GDPR gives a legal name and a penalty to
a principle the whole book already advocates — least privilege ([H01](../track-h/H01-where-does-authz-live.md)),
least data, least exposure ([I10](I10-incident-response.md)'s blast radius). The regulation and the
security engineering point the same way.

---

## The engineer's compliance posture

You don't need to be a lawyer, but you should:

1. **Build the controls Track I describes** — deprovisioning, audit logging, key management, MFA,
   incident response. Compliance is mostly these, done well.
2. **Make them produce evidence** — log the action, record the review, date the rotation. The
   artifact is what the auditor wants.
3. **Own your user data** ([C05](../track-c/C05-build-vs-buy.md)) with a clear key
   ([G12](../track-g/G12-account-linking.md)), so erasure and access requests are tractable.
4. **Minimise data everywhere** — tokens ([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)),
   logs ([I08](I08-observability.md)), storage. It's both compliant and secure.
5. **Know the hard clocks** — 72-hour breach notification ([I10](I10-incident-response.md)) — and
   name who owns them.
6. **Get a lawyer for the actual legal questions** — jurisdiction, data-processing agreements,
   consent specifics. This chapter is the engineering scaffolding, not the legal answer.

The reassuring conclusion: a team that has genuinely worked through Tracks D–I is most of the way
to SOC 2 and GDPR compliance already. The gap is usually not *doing* the controls — it's *proving*
them, which is why building for evidence from the start is the highest-leverage compliance
decision you'll make.

---

## Terms defined in this chapter

`SOC 2`, `GDPR`, `data minimisation`, `PII` (from I08)

---

## What to remember

1. **Compliance is mostly the operational hygiene of Track I — plus the ability to *prove* it.**
   The gap teams hit is evidence, not controls.
2. **SOC 2 wants evidence:** deprovisioning records, access reviews, tamper-evident audit logs,
   documented key rotation. Log the action, not just do it.
3. **GDPR data minimisation applies directly to tokens:** every claim in a JWT is PII broadcast to
   every service. Put an **identifier** in the token; look up PII at use.
4. **Right to erasure/access** is tractable only if you **own your user table** with a clear key
   ([C05](../track-c/C05-build-vs-buy.md), [G12](../track-g/G12-account-linking.md)).
5. **Minimisation is good security regardless of the law** — data you don't hold can't leak.
6. **Know the 72-hour breach clock** ([I10](I10-incident-response.md)).
7. **A team that worked through Tracks D–I is most of the way to compliance** — build for evidence
   from day one, and get a lawyer for the legal specifics.

---

## Sources

- [AICPA SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
- [GDPR full text](https://gdpr-info.eu/) — esp. Art. 5 (minimisation), 17 (erasure), 33–34 (breach)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — maps controls to verifiable requirements

---

**Next:** [I12 — Migrating auth: rehashing passwords, cutting over, not logging everyone out](I12-migrating-auth.md)
