# C04 — Threat modeling for normal people: who's attacking, with what?

**Part C · The map** · *Builds on [A07](../track-a/A07-client-vs-server.md)*
---

## Three questions

You can do a genuinely useful threat model in twenty minutes with these:

1. **What are we protecting?**
2. **Who wants it, and what can they already do?**
3. **What happens if they get it?**

Everything else is structure for answering those.

---

## 1. What are we protecting?

Be specific. "User data" is not an answer.

For the document-sharing app that runs through this book:

| Asset | Why it matters |
|---|---|
| Document contents | The product. Confidential business material. |
| Share graph | Who works with whom. Sensitive even without content. |
| User credentials | Reused elsewhere; a breach harms users beyond us. |
| Session tokens | Live access. Bypass MFA entirely. |
| Admin capability | Access to everything at once. |
| Audit log integrity | If it can be edited, it proves nothing. |
| Availability | A ransom or outage is a business event. |

The share graph row is the one teams miss. Metadata is often as sensitive as content —
"which two companies have a shared folder" can leak a merger before it is announced.

---

## 2. Who wants it, and what can they already do?

The capability column matters more than the name. Sort by what they *hold*:

| Attacker | Already has | Wants | Realistic? |
|---|---|---|---|
| **Opportunistic scanner** | Nothing. Automated. | Any easy win | **Constant. Today.** |
| **Credential stuffer** | Billions of breached passwords | Accounts | **Constant** |
| **Curious user** | A valid account | Other people's data | **Very common** |
| **Malicious tenant** | A valid account in another org | Cross-tenant data | Common in B2B |
| **Departed employee** | Knowledge, maybe credentials | Data, revenge | Common |
| **Phisher** | An email list | Credentials, sessions | **Very common** |
| **XSS-capable attacker** | A script on your origin | Sessions, actions | Depends on your CSP |
| **Network attacker** | A position on the path | Traffic | Rare, TLS handles it |
| **Insider with DB access** | Your database | Everything | Rare, catastrophic |
| **Nation state** | Almost anything | Targeted individuals | Only if you have targets |

> **Read down the "Realistic?" column.** The top four rows are happening to you right now.
> The bottom two probably are not.
>
> **Effort should follow that ordering.** Certificate pinning is row nine. IDOR is row
> three. The classic mistake is working bottom-up — hardening row nine while row three sits open.

### The "curious user" is the one people forget

Most breach reports are not sophisticated. They are an authenticated user changing an ID in
a URL and getting a response they should not have. That attacker has:

- A valid account (they signed up; it is free)
- A valid session (they logged in)
- Full knowledge of your API (from your own frontend —
  [A07](../track-a/A07-client-vs-server.md))
- Unlimited time and no risk

They are inside every one of your perimeter controls by design. The only thing standing
between them and your data is per-object authorization
([H14](../track-h/H14-attack-your-own-authorization.md)). That is why Track H matters more
than its reputation suggests.

---

## 3. What happens if they get it?

Rate each asset on two axes and multiply. This is the step that converts a list into a
priority order.

| | Low impact | High impact |
|---|---|---|
| **Likely** | Fix it, cheaply | **Fix it first** |
| **Unlikely** | Accept and document | Fix it, or transfer the risk |

The "accept and document" quadrant is legitimate and underused. Writing down *"we accept
the risk of a nation-state adversary compromising a CA, because we have no targets of that
value"* is a real decision that frees you to work on the top-left and top-right.

---

## STRIDE, as a checklist

Once you have assets and attackers, **STRIDE** is a six-item prompt for finding threats you
would otherwise miss. Walk each component through all six.

| Letter | Threat | Auth question | Chapter |
|---|---|---|---|
| **S** | Spoofing | Can someone pretend to be another principal? | D, E |
| **T** | Tampering | Can they modify data or tokens in flight or at rest? | B13, E06 |
| **R** | Repudiation | Can they deny an action they took? | H13 |
| **I** | Information disclosure | Can they read what they should not? | H14 |
| **D** | Denial of service | Can they make it unavailable? | D08 |
| **E** | Elevation of privilege | Can they gain permissions they lack? | H14 |

Applied to the login endpoint:

| | Threat | Mitigation |
|---|---|---|
| S | Credential stuffing, phishing | Rate limiting ([D08](../track-d/D08-rate-limiting-and-stuffing.md)), breached-password blocklist ([D04](../track-d/D04-password-policies.md)), passkeys ([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)) |
| T | Modifying the session cookie | Server-side sessions, or a signed token ([E03](../track-e/E03-build-server-side-sessions.md)) |
| R | "I never logged in from there" | Session listing + audit log ([E13](../track-e/E13-sessions-across-devices.md), [H13](../track-h/H13-audit-logging.md)) |
| I | User enumeration | Uniform responses and uniform timing ([D07](../track-d/D07-user-enumeration.md)) |
| D | Password hashing as a CPU sink | Rate limit *before* hashing; bound concurrency ([B08](../track-b/B08-salts-peppers-slow-hashes.md)) |
| E | Password reset to any account | Bind the token to one account, single-use ([D09](../track-d/D09-account-recovery.md)) |

Six prompts, six real controls. That is a threat model, and it took one table.

---

## The assumption list

The most valuable artefact is not the threat list. It is the **assumption list**, because
assumptions are what silently become false.

Write down what you are relying on:

- *"We assume the database is not readable by an attacker."* → If false, passwords must
  still be safe ([B08](../track-b/B08-salts-peppers-slow-hashes.md)) and session tokens
  must be hashed ([E04](../track-e/E04-session-ids.md)).
- *"We assume no XSS."* → You will have XSS. `HttpOnly` cookies mean the session survives
  it ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)).
- *"We assume our IdP is honest."* → Validate `iss`, `aud`, `exp`, `nonce` anyway
  ([G04](../track-g/G04-validate-an-id-token-by-hand.md)).
- *"We assume employees do not read customer data."* → Log every impersonation
  ([I04](../track-i/I04-admin-impersonation.md)).
- *"We assume tokens are not logged."* → Check. They probably are
  ([I08](../track-i/I08-observability.md)).

Then, for each: **what breaks when this stops being true?** That is
**defence in depth** — not "more controls" but *"assume each control fails, and have
another behind it."*

The rule of thumb: **any assumption you cannot verify automatically should have a
compensating control.**

---

## Threat modelling as a habit, not a document

Full sessions have their place. The version that actually gets used is a question asked
during design:

> **"Who would want to abuse this, and what would they need?"**

Applied to a feature:

- *Share a document by link* → Anyone with the link. Is the link guessable? Does it expire?
  Can it be revoked? Does it leak via `Referer` ([A04](../track-a/A04-headers.md))?
- *Invite a user by email* → Can I invite myself into someone else's tenant? Can I enumerate
  members? Can an invite be replayed?
- *Export to CSV* → Does the export apply the same authorization as the UI, or does it query
  the table directly ([H02](../track-h/H02-the-enforcement-point.md))?
- *Impersonate a user (support)* → Who may? Is it logged? Can it be used to escalate?
  ([I04](../track-i/I04-admin-impersonation.md).)

Thirty seconds per feature. It catches more than a quarterly review, because it happens at
the moment the decision is being made.

---

## What this book assumes

Stated explicitly, because every recommendation downstream depends on it:

**Assumed present:**
- Automated scanners hitting every endpoint, continuously.
- Attackers holding valid accounts on your system.
- Breached credential lists containing your users' passwords.
- Phishing targeting your users.
- Your own frontend code, fully readable.

**Assumed possible:**
- XSS somewhere, eventually.
- A stolen session token.
- A leaked API key in a public repository.
- A dependency compromise.

**Assumed out of scope:**
- Nation-state adversaries targeting specific individuals.
- Physical access to your servers.
- A compromised certificate authority.
- Post-quantum decryption of recorded traffic.

If your threat model includes the third list, this book is a foundation and not a complete
answer.

---

## Terms defined in this chapter

`threat model`, `attack surface`, `STRIDE`, `threat actor`, `defence in depth`

---

## What to remember

1. **What are we protecting, who wants it and what do they have, what happens if they get
   it?** Three questions.
2. Sort attackers by **capability**, not by scariness. The top four rows are attacking you
   today.
3. **The most dangerous attacker is an authenticated user changing an ID.** They are inside
   every perimeter control by design.
4. STRIDE is a six-item prompt to find threats you would skip.
5. The **assumption list** is the most valuable output. Defence in depth means assuming each
   control fails.
6. Ask "who would abuse this?" at design time. Thirty seconds beats a quarterly review.

---

## Sources

- Adam Shostack, *Threat Modeling: Designing for Security* — the standard text
- [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html)
- [Threat Modeling Manifesto](https://www.threatmodelingmanifesto.org/)
- [Microsoft STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)

---

**Next:** [C05 — Build vs buy: when to use a provider, and when not to](C05-build-vs-buy.md)
