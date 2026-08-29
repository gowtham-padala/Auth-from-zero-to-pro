# C05 — Build vs buy: when to use a provider, and when not to

**Part C · The map** · *Builds on [C01](C01-auth-is-five-different-problems.md)*
---

## The decision is per layer

From [C01](C01-auth-is-five-different-problems.md): auth is five problems. Each has its own
answer.

| Layer | Buy? | Why |
|---|---|---|
| **1. Authentication** | ✅ Usually | Commodity. Passkeys, TOTP, breach detection, and the recovery flows are a lot of undifferentiated work. |
| **2. Session management** | ⚠️ Partly | You issue **your own** session even when the IdP authenticated. Never delegate this entirely. |
| **3. Delegated authz (as a client)** | ✅ Use a library | Do not hand-write OAuth clients in production. Track F is for understanding, then use a certified library. |
| **3. Delegated authz (as a server)** | ⚠️ Buy unless it *is* your product | Running an authorization server is a serious commitment ([F14](../track-f/F14-build-an-authorization-server.md)). |
| **4. Federated identity / SSO** | ✅ Strongly | Multi-tenant SAML + OIDC + home realm discovery is months of work and permanently on fire ([G09](../track-g/G09-multi-tenant-sso.md)). |
| **5. Authorization** | ❌ **Build the model** | Your authorization model *is* your domain model. Tools can help evaluate it; nobody can define it for you. |
| **Lifecycle / ops** | ⚠️ Mixed | SCIM: buy. Audit logging: build, it is domain-specific. |

> **The one-line version: you can outsource *who they are*. You cannot outsource *what they
> may do*.**

The mistake in both opening stories is treating this as one decision. Team A should have
bought layer 4. Team B should have expected to build layer 5 regardless.

---

## When buying is clearly right

**You have enterprise customers.** They will demand SAML, SCIM, IdP-per-tenant, session
policies, and audit exports. Building that is a product in itself, and it is not yours.
([G09](../track-g/G09-multi-tenant-sso.md), [I02](../track-i/I02-provisioning-and-scim.md).)

**You are pre-product-market-fit.** Every hour on login is an hour not spent finding out
whether anyone wants your product. Buy, ship, learn.

**You are in a regulated industry.** A provider with existing SOC 2, ISO 27001, and
FedRAMP evidence removes months of audit preparation ([I11](../track-i/I11-compliance.md)).

**Your team has no security depth.** The failure modes in Tracks D and E are not obvious.
An unsalted hash, a predictable session ID, a reset token that does not expire — each is a
one-line mistake with total consequences.

**You need passkeys, and you need them to work everywhere.** WebAuthn is genuinely
intricate across platforms, authenticators, and browser versions
([D15](../track-d/D15-build-passkeys.md)). Providers absorb that churn.

---

## When building is clearly right

**Auth is your product.** Obviously.

**You have unusual requirements.** Air-gapped deployment, on-premise installs, a
non-standard identifier, regulatory data residency the provider cannot meet.

**Your scale makes per-user pricing absurd.** At ten million monthly active users, provider
pricing usually exceeds the fully-loaded cost of a small dedicated team. Do that arithmetic
at your *projected* scale, not today's.

**You are first-party only, forever.** A single web app with its own users, no third-party
integrations, no enterprise SSO. Server-side sessions plus Argon2id plus TOTP is genuinely
a few hundred lines, it is well-trodden, and Tracks D and E teach it completely. Do not let
anyone tell you this is reckless — it is what most of the web ran on for twenty years, and
it is *simpler* than integrating a provider.

**You cannot accept the availability coupling.** If the provider is down, nobody logs in.
For some businesses that is unacceptable, and no SLA changes it.

---

## The costs nobody quotes

### Buying

**Pricing model risk.** MAU pricing punishes success. Model your bill at 10× current
users before signing. Ask specifically what happens at each tier boundary.

**The migration tax.** This is the big one. If user records and password hashes live in the
provider, leaving means either (a) they export hashes in a format you can verify — ask
before you sign, and get it in writing — or (b) **every user resets their password**, which
costs you a measurable percentage of your user base.

> **Ask this before signing: "Can I export password hashes in a documented format?"** The
> answer determines whether this is a partnership or a lock-in. Some providers export
> bcrypt hashes cleanly. Some do not export them at all.

**The customisation wall.** Custom fields, custom flows, custom emails, conditional logic —
each is easy until it is not, and then you are writing extension code in their runtime with
their debugging tools.

**Availability coupling.** Their incident is your outage.

**You will still build layer 5.** Guaranteed. Budget for it from day one rather than
discovering it in month eight.

### Building

**It is never finished.** Login is a week. Password reset, rate limiting, enumeration
defence, 2FA, recovery codes, device listing, session revocation, step-up, breach detection,
audit logging — that is Tracks D, E, and I, and it is a year of part-time work.

**The failure modes are silent.** A predictable session ID does not throw an exception. It
works perfectly until someone notices.

**Security review is a real cost.** Budget for external review of anything you build in
Tracks F, G, and H. Wrong auth code causes breaches in *other people's* products.

**You will be behind.** Passkeys, then whatever comes next. Providers absorb that; you
schedule it.

---

## The pattern that keeps your options open

Regardless of which way you go, do this. It costs almost nothing at the start and is
expensive to retrofit.

### 1. Own your user table

Keep a local `users` row for every user, with your own primary key. Store the external
identity as `(issuer, subject)` in a separate `identities` table
([G12](../track-g/G12-account-linking.md)).

```sql
CREATE TABLE users (
  id            uuid PRIMARY KEY,
  email         citext UNIQUE NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identities (
  user_id       uuid REFERENCES users(id),
  issuer        text NOT NULL,          -- 'https://accounts.google.com'
  subject       text NOT NULL,          -- the IdP's `sub`
  PRIMARY KEY (issuer, subject)
);
```

Now your application's foreign keys point at *your* user ID, not the provider's. Switching
providers becomes "add rows to `identities`," not "rewrite every table."

**This single decision is the difference between a two-week migration and a two-quarter
one.**

### 2. Issue your own session

Even when a provider authenticates the user, **your** application creates **your** session
([E03](../track-e/E03-build-server-side-sessions.md)).

You control expiry, revocation, "log out everywhere," and device listing. You are not
coupled to the provider on every request. And their outage does not log out users who are
already in.

### 3. Keep authorization entirely yours

Never store roles or permissions in the provider. Your authorization data lives in your
database, next to the resources it protects
([H01](../track-h/H01-where-does-authz-live.md)).

Provider-managed roles seem convenient and become the thing that makes migration
impossible — and they are always a worse fit than a model you designed for your own domain.

### 4. Put an interface in front of it

```python
class IdentityProvider(Protocol):
    def authenticate(self, credentials) -> ExternalIdentity | None: ...
    def start_sso(self, tenant_id: str) -> RedirectURL: ...
    def complete_sso(self, callback_params) -> ExternalIdentity: ...
```

One module talks to the provider. Everything else talks to your interface. Not because you
plan to switch — because it forces the boundary to stay clean, which is what makes
switching possible if you ever must.

---

## The categories of provider

| Category | Examples | Best for |
|---|---|---|
| **Full CIAM** | Auth0, Okta CIC, Microsoft Entra External ID, AWS Cognito | Broad needs, enterprise features |
| **Developer-first** | Clerk, Stytch, WorkOS, Supabase Auth, Better Auth | Fast integration, good defaults |
| **SSO-only** | WorkOS, BoxyHQ | You have your own login and just need enterprise SSO |
| **Self-hosted** | Keycloak, Ory, Zitadel, Authentik | Data residency, no per-user cost, you run it |
| **Framework libraries** | Auth.js, Devise, Spring Security, Laravel Fortify | Building, but not from zero |
| **Authorization** | OpenFGA, SpiceDB, Oso, Cedar, OPA | Layer 5 — a *different* purchase ([H11](../track-h/H11-opa-cedar-or-sql.md)) |

Two things to notice. **The SSO-only category is underrated** — "we have login, we just
need SAML for enterprise customers" is an extremely common position, and buying only that
piece is often the best-value decision available.

And **self-hosted is a real option** that people skip. Keycloak, Ory, and Zitadel remove
per-user pricing and data-residency concerns. The trade is that you now operate an identity
service, including its upgrades and its availability.

**Deliberately not covered in this book:** how to configure any specific vendor. Those
guides rot in months and the vendor already wrote them
([appendix/excluded.md](../../appendix/excluded.md)).

---

## Terms defined in this chapter

`identity provider`, `CIAM`, `workforce identity`

---

## What to remember

1. **Decide per layer, not once.** The five problems have five answers.
2. **You can buy "who they are." You cannot buy "what they may do."** You will build
   Track H regardless.
3. Buy layer 4 (SSO) almost always. Multi-tenant SAML is months of work and never finishes.
4. Building layers 1–2 for a first-party app is genuinely reasonable and well-trodden.
5. **Ask about hash export before you sign.** It decides whether you can ever leave.
6. **Own your user table, issue your own session, keep authorization local, hide the
   provider behind an interface.** Four decisions that cost nothing now and save a quarter
   later.

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 3
- [The Copenhagen Book](https://thecopenhagenbook.com/) — what building it yourself actually involves
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

---

**Track C complete.** You have the map, the vocabulary, a threat model, and a build/buy
position. Everything from here is one layer at a time.

**Next:** [D01 — Identifiers: what should a user actually log in with?](../track-d/D01-identifiers.md)
