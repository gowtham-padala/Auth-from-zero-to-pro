# I10 — Incident response: your tokens leaked, now what?

**Part I · Identity lifecycle & operations** · *Builds on [E11](../track-e/E11-revocation.md), [I06](I06-key-rotation.md)*
---

## The two questions, first

Before any action, answer two things — they shape everything else:

**1. What leaked?** Different credentials have different blast radius
([I06](I06-key-rotation.md)):

```
   A SIGNING KEY        → every token is forgeable → total auth compromise    E06
   A user's PASSWORD    → one account (+ anywhere they reused it)             D08
   A user's SESSION     → one account, until revoked/expired                  E11
   AN API KEY           → whatever it's scoped to                            J02
   THE WHOLE DATABASE   → password hashes (crack-resistant if Argon2id) +    B08
                          session tokens (hashed?) + everything else          E04
```

**2. What's the blast radius?** — *how much* an attacker can reach with what leaked. A leaked
low-scope API key is contained; a signing key is everything. This determines whether you rotate
one credential or trigger a full compromise response. The reason the book keeps favouring
**least privilege** ([H01](../track-h/H01-where-does-authz-live.md)), **short lifetimes**
([E10](../track-e/E10-token-lifetimes-and-rotation.md)), and **non-extractable keys**
([I05](I05-secrets-management.md)) is precisely to shrink this radius *in advance* — the incident
you prepared for is the survivable one.

---

## The response, by what leaked

### A signing key — the worst case

Every token is forgeable, so the whole point of the tokens (that they need no lookup —
[E09](../track-e/E09-should-you-use-jwts-for-sessions.md)) is now a liability. Response:

```
1. ROTATE the key immediately.  I06 — but this is the EMERGENCY variant:
   you CANNOT wait for the overlap window, because the old key is compromised.
   → Remove the old key from the JWKS NOW. This invalidates all tokens signed
     by it — yes, logging everyone out. That's the correct cost here.       I06
2. Force re-authentication for everyone.                                    E13
3. Invalidate all refresh tokens (they may be forged too).                  E10
4. Investigate: what was accessed with forged tokens? (audit log)          H13
5. If the key was in a KMS, this is far less likely — you'd rotate the KMS
   key and the material never left.  ← the I05 argument, in an incident.    I05
```

Note the contrast with routine rotation ([I06](I06-key-rotation.md)): routine rotation preserves
the overlap window to avoid downtime; *emergency* rotation collapses it, accepting the mass
logout, because continuing to trust the compromised key is worse than the outage. This is why
[I06](I06-key-rotation.md) says to practise routine rotation — so the emergency version is a
known procedure, not a first attempt.

### Leaked sessions / tokens

```
1. Revoke the affected sessions/tokens.  E11/E13.
   → With server-side sessions: DELETE. Instant.  E03/E09 (this is why they're recommended)
   → With stateless JWTs: denylist by jti, or bump token_version, or wait out
     short expiry.  E11 — and note how much harder this is.
2. If you can't identify WHICH leaked, revoke the class (all sessions).
3. Refresh-token reuse detection may have already caught it.  E10.
```

The incident makes [E09](../track-e/E09-should-you-use-jwts-for-sessions.md)'s argument concrete:
**revocability is an incident-response property.** The system where you can `DELETE` a session
handles this leak in seconds; the system built on unrevocable tokens handles it by waiting or by
scrambling to build a denylist under pressure.

### Leaked passwords / password database

```
1. If a hash database (Argon2id): passwords are crack-resistant, but assume
   the weakest will fall.  B08.
2. Force reset for affected users; invalidate their sessions.  D09/E13.
3. Check the leaked passwords against your OTHER users (reuse).  D08.
4. Add the leaked set to your breach blocklist.  D04.
```

### Leaked API keys / secrets

```
1. Revoke immediately.  J02.
2. Rotate related secrets (they may share exposure).  I05/I06.
3. Scan for where else the secret was copied — secret sprawl.  I05/A10.
```

---

## Have the runbook before 3am

The single most valuable thing this chapter can convey: **write the runbook now, while calm.**
An incident runbook is a pre-decided sequence, so at 3am you *execute* rather than *deliberate*:

```
   AUTH INCIDENT RUNBOOK
   1. DETECT   — how did we find out? (alert, report, disclosure)  I08/I09
   2. CONTAIN  — stop the bleeding: revoke, rotate, disable.       E11/I06
   3. ASSESS   — what leaked, blast radius, what was accessed.     H13
   4. ERADICATE— remove the attacker's access (all of it).         I03
   5. RECOVER  — restore service, re-issue credentials cleanly.
   6. NOTIFY   — users, and regulators if required.                below
   7. LEARN    — post-mortem; fix the root cause.
```

Pre-decide the hard calls: *Who* has authority to rotate the signing key (it logs everyone out —
someone must own that decision)? *What's* the threshold for user notification? *Who* talks to
regulators and customers? Deciding these mid-incident wastes the time you don't have.

The book's earlier controls make each step executable: **containment** needs working revocation
([E11](../track-e/E11-revocation.md)) and rotation ([I06](I06-key-rotation.md)); **assessment**
needs a real audit log ([H13](../track-h/H13-audit-logging.md)); **eradication** needs
deprovisioning that reaches every path ([I03](I03-deprovisioning.md)). An incident is where you
discover whether you built those — or whether you're building them at 3am.

---

## Protect the evidence

An attacker who's inside will try to cover their tracks — the first target is often the logs
([H13](../track-h/H13-audit-logging.md)). This is why the audit log must be **append-only,
tamper-evident, and in a location the compromised system can't reach**
([H13](../track-h/H13-audit-logging.md)): during an incident, that log is how you answer "what was
accessed?", and a log the attacker could edit answers nothing. If you didn't build it that way
before the incident, the assessment step becomes guesswork.

---

## Notification: users and regulators

Two obligations, both often legally mandated ([I11](I11-compliance.md)):

**Users.** Tell affected users clearly and promptly — what happened, what to do (reset, check
other accounts where they reused the password — [D08](../track-d/D08-rate-limiting-and-stuffing.md)),
and what you've done. A clear, honest notification limits harm and preserves trust; a vague or
delayed one destroys both.

**Regulators.** **GDPR requires breach notification to the supervisory authority within 72 hours**
of becoming aware ([I11](I11-compliance.md)); many US states and sectoral regimes have their own
timelines. This is a hard clock, and it is *not* the moment to be reading the regulation for the
first time — the runbook must name who owns disclosure and know the deadlines in advance.

Do not hide or minimise. The reputational and legal damage from a *concealed* breach vastly
exceeds that from a well-handled disclosed one, and the cover-up is often the part that ends
careers and companies.

---

## The post-mortem: turn the incident into prevention

After recovery, a **blameless post-mortem**: what was the root cause, why wasn't it caught
earlier, and what change prevents recurrence. The signing key in a public repo
([A10](../track-a/A10-where-secrets-live.md)) → secret scanning in CI + a KMS so the key can't be
committed at all ([I05](I05-secrets-management.md)). The point is not blame; it's that **each
incident should make the next one impossible or smaller.** An incident you don't learn from you'll
have again.

---

## Terms defined in this chapter

`blast radius`

---

## What to remember

1. **Handling an incident badly is what turns a problem into a catastrophe.** The skill must
   exist *before* the incident — you'll never have time to build it during.
2. **First: what leaked, and what's the blast radius?** A signing key is total; a scoped API key
   is contained. Least privilege and short lifetimes shrink this *in advance*.
3. **A leaked signing key needs *emergency* rotation** — collapse the overlap window, accept the
   mass logout ([I06](I06-key-rotation.md)). A KMS makes this far less likely ([I05](I05-secrets-management.md)).
4. **Revocability is an incident-response property** — the [E09](../track-e/E09-should-you-use-jwts-for-sessions.md)
   argument made real: server-side sessions handle a leak in seconds.
5. **Write the runbook while calm** — detect, contain, assess, eradicate, recover, notify, learn —
   and pre-decide the hard calls (who rotates the key, who notifies).
6. **Protect the evidence** — an append-only, tamper-evident, out-of-reach audit log
   ([H13](../track-h/H13-audit-logging.md)) is how you assess; the attacker targets the logs first.
7. **Notify users promptly; GDPR gives 72 hours to notify regulators** ([I11](I11-compliance.md)).
   Never conceal.
8. **Blameless post-mortem** — make the next incident impossible or smaller.

---

## Sources

- [NIST SP 800-61 Rev. 3 — Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [GDPR Articles 33–34 — breach notification](https://gdpr-info.eu/art-33-gdpr/)
- [OWASP Incident Response](https://owasp.org/www-community/Incident_Response)

---

**Next:** [I11 — Compliance without a lawyer: SOC 2, GDPR, data minimization in tokens](I11-compliance.md)
