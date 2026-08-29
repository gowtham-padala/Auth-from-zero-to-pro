# G10 — Home realm discovery: routing users by email domain

**Part G · Federated identity & SSO** · *Builds on [G09](G09-multi-tenant-sso.md)*
---

## Why it matters

A multi-tenant B2B app shows every customer's SSO option on one login page:

```
   Sign in with:
   [ Acme Okta ]  [ Globex Azure AD ]  [ Initech Ping ]  [ Umbrella AD FS ]  ...
```

Three problems, escalating:

1. **It leaks the customer list.** Anyone who visits your login page now knows Acme, Globex,
   Initech, and Umbrella are your customers — competitively sensitive, and a gift to a
   spear-phisher.
2. **It does not scale.** At 500 customers it is unusable.
3. **A user might pick the wrong one**, or an attacker might route a victim to a malicious
   IdP.

The fix is **home realm discovery**: figure out which IdP a user belongs to from their
*email domain*, without showing anyone else's.

---

## The mechanism

```
   User enters:  alice@acme.com
                        │
                        ▼  extract domain: "acme.com"
   Look up the tenant whose verified email_domains contains "acme.com"
                        │
        ┌───────────────┴────────────────┐
   Found a tenant with SSO           No match
        │                                │
        ▼                                ▼
   Route to THAT tenant's IdP        Password login (or "no account")
   (Acme's Okta)                     — same as any non-SSO user
```

The email domain is the routing key. It maps a user to their tenant's IdP
([G09](G09-multi-tenant-sso.md)) while revealing nothing about any other tenant.

---

## The two-step login

The standard pattern: ask for the email first, *then* decide how to authenticate.

```python
@app.post("/login/identify")
def identify():
    email = request.form.get("email", "").strip().lower()
    domain = email.rpartition("@")[2]

    # Look up SSO config by verified domain. G09.
    tenant = db.find_tenant_by_verified_domain(domain)

    if tenant and tenant.sso_type and tenant.enforce_sso:
        # This domain is SSO-only. Go straight to their IdP.
        return redirect(f"/sso/start?tenant={tenant.id}")

    if tenant and tenant.sso_type:
        # SSO available but not enforced — offer both.
        return render("login-choice.html", email=email, sso_tenant=tenant.id)

    # No SSO for this domain — password path.
    return render("login-password.html", email=email)
```

The two-step flow ("enter email" → "here's how you log in") is now standard across major
products precisely because it enables home realm discovery without a wall of IdP buttons. It
also improves the password path — you can show the right thing (password, passkey, or SSO
redirect) for each user.

---

## Domain verification: the security foundation

The entire scheme rests on one thing: **a tenant may only claim a domain it has proven it
controls.** Otherwise the attack is devastating:

```
   Attacker signs up for your product, creates a tenant, and claims "google.com".
   Now every google.com employee who logs in to your app is routed to the
   ATTACKER'S IdP — and authenticates against it.
```

That is a complete account-takeover of every user on a claimed domain. So domain claims must
be **verified**, exactly like email verification ([D02](../track-d/D02-email-as-identity.md))
but for a whole domain:

| Method | How | Strength |
|---|---|---|
| **DNS TXT record** | Customer adds `acme-verify=<token>` to their DNS | ✅ Strong — proves DNS control |
| **File upload** | Customer hosts a token at `https://acme.com/.well-known/...` | ✅ Strong — proves web control |
| **Email to a privileged address** | Confirm via `admin@` / `security@acme.com` | ⚠️ Weaker; some domains lack these |
| **Meta tag** | Customer adds a tag to their homepage | ⚠️ Weaker |

**Require DNS or file verification** for domain claims, and **re-verify periodically** — a
domain can change hands, or a DNS record can be removed. Never let a tenant route a domain it
has not proven it owns.

### Subdomains and public-suffix traps

Two edges to handle:

- **Public email providers.** Nobody should claim `gmail.com`, `outlook.com`, or `yahoo.com`
  — they are shared across millions of unrelated users. Block claims on domains in a
  public-provider list; those users go to the password/social path.
- **Subdomains and the Public Suffix List** ([A11](../track-a/A11-same-origin-and-cors.md)).
  Decide whether claiming `acme.com` also covers `eng.acme.com`. Usually yes for a company's
  own subdomains — but verify at the registrable-domain level and be careful with
  suffixes-as-a-service (`*.github.io`, `*.herokuapp.com`) where subdomains belong to
  different parties.

---

## Enumeration and privacy

Home realm discovery *is* an enumeration surface ([D07](../track-d/D07-user-enumeration.md)):
the response reveals whether a domain has SSO configured, which reveals that the domain is a
customer.

You mostly cannot avoid this — routing *requires* knowing the domain's IdP. But you can limit
the leak:

- **Reveal *domain* configuration, not *user* existence.** "This domain uses SSO" is far less
  sensitive than "alice@acme.com has an account." Route on the domain without confirming the
  specific user exists.
- **Keep the redirect uniform.** Whether or not a specific user exists, an SSO domain redirects
  to the IdP; the IdP decides whether the user is valid. Do not branch visibly on user
  existence before the redirect.
- **Rate-limit** the identify endpoint, so an attacker cannot cheaply map your entire customer
  base by probing domains ([D08](../track-d/D08-rate-limiting-and-stuffing.md)).

Accept that *domain-level* configuration is somewhat discoverable, and compensate rather than
pretend otherwise ([D07](../track-d/D07-user-enumeration.md)).

---

## Edge cases you will hit

**One user, multiple tenants.** A consultant with `alice@acme.com` who works for two of your
customers. If both tenants verified `acme.com`... they cannot both own it exclusively. Usually
a domain maps to exactly one tenant; handle the genuinely-shared case (a parent company with
subsidiaries) explicitly, or key users on `(tenant_id, email)` and let the user pick which
tenant they are signing into ([G09](G09-multi-tenant-sso.md)).

**Personal email at a company.** An employee who signed up with `alice@gmail.com` before the
company enforced SSO. When SSO enforcement turns on, they cannot be routed by domain. Provide
an account-linking path ([G12](G12-account-linking.md)) or an admin-driven migration.

**Domain not yet verified.** During onboarding, before the customer completes DNS
verification, do not route — fall back to password login, and make the pending state visible
to the customer admin.

---

## Terms defined in this chapter

`home realm discovery`, `domain verification`

---

## What to remember

1. **Route users to their tenant's IdP by email domain** — never show a wall of every
   customer's SSO button.
2. **A wall of IdP buttons leaks your customer list**, does not scale, and enables
   mis-routing.
3. The **two-step login** (email first, then auth method) is the standard pattern that
   enables this.
4. **Domain verification is the security foundation.** An unverified domain claim routes a
   whole company's logins to an attacker's IdP.
5. **Require DNS or file verification**, re-verify periodically, and **block public email
   providers**.
6. Home realm discovery is an **enumeration surface** — reveal domain configuration, not user
   existence, and rate-limit it.
7. Handle one-user-multiple-tenants and personal-email-at-a-company explicitly.

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 7
- [WorkOS: Identity Provider detection / HRD](https://workos.com/docs/sso)
- [The Public Suffix List](https://publicsuffix.org/)

---

**Next:** [G11 — Federated sessions and single logout](G11-federated-sessions-single-logout.md)
