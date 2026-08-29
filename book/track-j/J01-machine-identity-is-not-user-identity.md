# J01 — Machine identity is not user identity

**Part J · Machine, workload & agent identity** · *Builds on [F10](../track-f/F10-client-credentials.md)*
> Auth when there's no human at all. And a note that this is where the field is moving —
> machine and agent identities now vastly outnumber human ones.

---

## Why they're different

```
   USER IDENTITY                          MACHINE IDENTITY
   ─────────────                          ────────────────
   A human, who...                        Software, which...
   • can prove presence (MFA)             • cannot — no human to prompt   D11
   • forgets passwords → recovery         • has no memory to jog; no recovery flow
   • logs in interactively (browser)      • runs headless; no redirect flow  F10
   • is one person                        • may be thousands of instances, ephemeral
   • leaves the company (a clear event)   • is decommissioned (no clear event)  I01/I03
   • ~thousands per org                   • ~millions per org, and growing fast
```

The differences aren't cosmetic — they invalidate the tools:

- **No second factor is possible.** A machine can't receive an SMS or touch a security key
  ([D11](../track-d/D11-sms-second-factor.md), [D14](../track-d/D14-webauthn-and-passkeys-concepts.md)).
  So "MFA everywhere" ([D18](../track-d/D18-step-up-auth-and-aal.md)) doesn't apply — and shoving a
  machine into a system that expects MFA means turning MFA *off* for it, which is worse.
- **No interactive login.** The authorization code flow ([F03](../track-f/F03-authorization-code-flow.md))
  assumes a browser and a human to consent. Machines use **client credentials**
  ([F10](../track-f/F10-client-credentials.md)) — a flow *designed* for no human — precisely
  because there's no one to redirect.
- **No password recovery.** A human forgetting a password is normal ([D09](../track-d/D09-account-recovery.md));
  a machine "forgetting" is a bug. Machine credentials are provisioned and rotated
  ([I06](../track-i/I06-key-rotation.md)), never "recovered."
- **Scale and ephemerality.** One human is one identity for years; a machine may be ten thousand
  short-lived container instances that come and go in minutes. Static credentials don't fit —
  which is what drives workload identity ([J05](../track-j/J05-workload-identity-spiffe.md)).

---

## Machine identity is now the majority

The industry framing worth internalising: in a modern cloud environment, **machine identities
outnumber human ones by a large and growing factor.** Every microservice, container, function,
CI job, and now every AI agent ([J07](J07-auth-for-ai-agents.md)) is an identity that needs to
authenticate. Managing them with tools built for humans — user accounts, passwords, manual
provisioning — doesn't scale and produces this human-vs-machine mismatch, at scale.

This is why Track J exists as a distinct track: machine identity is not an edge case of user
identity. It's a larger problem with its own tools ([J02](J02-api-keys.md)–[J06](J06-signing-webhooks.md)),
its own lifecycle ([J03](J03-service-accounts.md), [I01](../track-i/I01-identity-lifecycle.md)),
and — with agents ([J07](J07-auth-for-ai-agents.md), [J08](J08-mcp-and-oauth-21.md)) — its own
frontier.

---

## What machines use instead

The right tools for machine identity, each a chapter:

| Need | Tool | Chapter |
|---|---|---|
| Simple caller identification | **API keys** (done properly) | [J02](J02-api-keys.md) |
| A non-human account in a human system | **Service accounts** (carefully) | [J03](J03-service-accounts.md) |
| Machine-to-machine OAuth | **Client credentials grant** | [F10](../track-f/F10-client-credentials.md) |
| Mutual authentication at the transport | **mTLS** | [J04](J04-mtls.md) |
| Identity for ephemeral workloads at scale | **SPIFFE/SPIRE, cloud workload identity** | [J05](J05-workload-identity-spiffe.md) |
| Verifying inbound calls (webhooks) | **Signature verification** | [J06](J06-signing-webhooks.md) |
| An AI agent acting for a user | **Delegation + agent auth** | [J07](J07-auth-for-ai-agents.md) |

The organising principle: **the best machine credential is one the platform issues and rotates
automatically, scoped tightly, with no long-lived secret to store.** That's the throughline from
[I05](../track-i/I05-secrets-management.md) (don't hold the secret) and [F10](../track-f/F10-client-credentials.md)
(prefer workload identity to a static secret), and it culminates in
[J05](J05-workload-identity-spiffe.md).

---

## The principles that carry over — and the ones that don't

**Carry over from human identity:**

- **Least privilege** ([H01](../track-h/H01-where-does-authz-live.md)) — even more important for
  machines, because an over-scoped service account is a bigger blast radius than most user
  accounts ([I10](../track-i/I10-incident-response.md)) and nobody's watching it.
- **Lifecycle management** ([I01](../track-i/I01-identity-lifecycle.md)) — machines join, change,
  and leave too, and their *leaver* problem is worse (no departure event —
  [I03](../track-i/I03-deprovisioning.md)).
- **Rotation** ([I06](../track-i/I06-key-rotation.md)) — machine credentials must rotate; the
  "never rotate the robot's password" instinct is exactly the failure.
- **Audit** ([H13](../track-h/H13-audit-logging.md)) — every machine action attributable to a
  machine identity.

**Do NOT carry over:**

- **MFA / interactive login** — impossible; use cryptographic proof instead
  ([J04](J04-mtls.md), [J05](J05-workload-identity-spiffe.md)).
- **Password recovery** — provision fresh, don't recover.
- **"One account per entity" as a human account** — a service is not a user; don't create it in
  the user table with a password ([J03](J03-service-accounts.md)).

The core mistake is applying the *human* tools (password, MFA-or-disable,
user account, no rotation) to a *machine*. Applying the machine tools (client credentials, mTLS,
workload identity, tight scope, auto-rotation) is the fix.

---

## Terms defined in this chapter

`machine identity`, `workload`

---

## What to remember

1. **Machine identity is not user identity** — different properties (no MFA, no interactive login,
   no recovery, massive scale, ephemeral), which invalidate the human tools.
2. **Treating a machine like a human** — a user account with a password that never rotates, MFA
   disabled, no owner — is the core failure and produces orphans, weak accounts, and sprawl.
3. **Machines now vastly outnumber humans** as identities; managing them with human tools doesn't
   scale.
4. **Use the machine tools:** API keys done right ([J02](J02-api-keys.md)), client credentials
   ([F10](../track-f/F10-client-credentials.md)), mTLS ([J04](J04-mtls.md)), workload identity
   ([J05](J05-workload-identity-spiffe.md)).
5. **The best machine credential is platform-issued, auto-rotated, and tightly scoped** — no
   long-lived secret to store ([I05](../track-i/I05-secrets-management.md)).
6. **Least privilege, lifecycle, rotation, and audit carry over** — and matter *more*, because
   nobody's watching a service account.
7. **MFA, interactive login, and password recovery do not carry over** — replace them with
   cryptographic proof.

---

## Sources

- [RFC 6749 §4.4 — Client Credentials Grant](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) ([F10](../track-f/F10-client-credentials.md))
- [SPIFFE — Secure Production Identity Framework](https://spiffe.io/docs/latest/spiffe-about/overview/) ([J05](J05-workload-identity-spiffe.md))
- [NIST SP 800-63-4 (Base) — non-person entities](https://csrc.nist.gov/pubs/sp/800/63/4/final)

---

**Next:** [J02 — API keys: why they persist, and how to do them properly](J02-api-keys.md)
