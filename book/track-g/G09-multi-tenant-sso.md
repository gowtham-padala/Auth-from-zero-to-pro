# G09 — Multi-tenant SSO for B2B SaaS: the IdP-per-customer problem

**Part G · Federated identity & SSO** · *Builds on [G08](G08-saml-vs-oidc.md)*
---

## Consumer SSO vs enterprise SSO

```
   CONSUMER (Sign in with Google)         ENTERPRISE (multi-tenant)
   ───────────────────────────────        ─────────────────────────
   ONE IdP, YOU configure it              ONE IdP PER CUSTOMER, THEY configure it
   Any user can use it                    Only that customer's employees
   You register once with Google          A separate setup per customer
   Users pick "Google"                    Users are routed by their email domain  G10
   IdP is your choice                     IdP is the customer's choice (Okta/Entra/AD FS)
```

The shift is from *one* federation relationship to *N* — one per customer, each with its own
IdP, its own certificate, its own configuration, and strict isolation from the others. This
is why [G08](G08-saml-vs-oidc.md) called multi-tenant SSO "months of work" and the clearest
buy case in the book.

---

## The tenant is the organising unit

Everything hangs off the **tenant** — one customer's isolated slice of your system
([H09](../track-h/H09-multi-tenancy-isolation.md)):

```sql
CREATE TABLE tenants (
  id            uuid PRIMARY KEY,
  name          text NOT NULL,
  -- SSO configuration, per tenant:
  sso_type      text,                    -- 'saml' | 'oidc' | null (no SSO)
  sso_config    jsonb,                   -- IdP metadata, endpoints, certs
  email_domains text[],                  -- for home realm discovery — G10
  enforce_sso   boolean DEFAULT false,   -- can users still use passwords?
  scim_enabled  boolean DEFAULT false    -- provisioning — I02
);

CREATE TABLE users (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id),   -- every user belongs to a tenant
  email         citext NOT NULL,
  -- identity is (issuer, subject) WITHIN the tenant — G12
  external_id   text,
  UNIQUE (tenant_id, email)              -- unique WITHIN a tenant, not globally
);
```

Two decisions in that schema are load-bearing:

**`UNIQUE (tenant_id, email)`, not `UNIQUE (email)`.** The same person may exist in two
customer tenants — a consultant working for two of your customers, say — as two separate
users. Global email uniqueness breaks that, and it also creates a cross-tenant information
leak (registration tells you the email exists in *some* tenant).

**SSO config lives on the tenant.** Each customer's IdP metadata, endpoints, and certificate
are per-tenant data, not global configuration. Adding a customer is adding a row, not
deploying code.

---

## The routing problem

A user arrives at your login page. Which tenant's IdP do you send them to?

You cannot show a list of every customer's IdP — that leaks your customer list and is
unusable. Instead you route by **email domain** — **home realm discovery**, its own chapter
([G10](G10-home-realm-discovery.md)):

```
   User enters:  alice@acme.com
                        │
                        ▼
   Look up the tenant whose email_domains contains "acme.com"
                        │
                        ▼
   Redirect to THAT tenant's IdP (Acme's Okta)
```

The email domain is the key that maps a user to their tenant's IdP without exposing anything
about other tenants ([G10](G10-home-realm-discovery.md)).

---

## Per-tenant SSO initiation

```python
@app.post("/sso/start")
def start_sso():
    email = request.form["email"]
    domain = email.split("@")[1].lower()

    # Home realm discovery: find the tenant for this domain. G10.
    tenant = db.find_tenant_by_email_domain(domain)
    if tenant is None or tenant.sso_type is None:
        # No SSO for this domain — fall back to password login.
        return redirect(f"/login/password?email={quote(email)}")

    if tenant.sso_type == "oidc":
        # Each tenant has its OWN OIDC provider config. G05.
        provider = OIDCProvider(tenant.sso_config["issuer"])
        return redirect(provider.build_authorize_url(
            client_id=tenant.sso_config["client_id"],
            redirect_uri=f"{BASE}/sso/callback/{tenant.id}",   # tenant in the callback
            state=make_state(tenant_id=tenant.id),             # bind tenant to the flow
            nonce=make_nonce(),                                # G04
        ))

    if tenant.sso_type == "saml":
        # Each tenant has its OWN SAML IdP metadata + cert. G07.
        return build_saml_request(tenant.sso_config)

@app.route("/sso/callback/<tenant_id>", methods=["GET", "POST"])
def sso_callback(tenant_id):
    tenant = db.get_tenant(tenant_id)

    # Validate using THIS tenant's config — its issuer, its cert.
    identity = validate_sso_response(request, tenant)          # G04 / G07

    # ★ The critical isolation check: the identity must belong to THIS tenant.
    if not identity_belongs_to_tenant(identity, tenant):
        abort(403, "identity/tenant mismatch")

    user = find_or_create_user(tenant.id, identity)            # G12, scoped to tenant
    session_id = create_session(user.id, tenant_id=tenant.id)  # E03
    ...
```

**The isolation check (`identity_belongs_to_tenant`) is the security core.** Without it, a
user authenticated by tenant A's IdP could be admitted into tenant B — a cross-tenant
breach. The token/assertion must be validated against *the tenant it claims to be for*, and
the resulting identity must be confined to that tenant
([H09](../track-h/H09-multi-tenancy-isolation.md)).

Notice the tenant travels through the whole flow: in the callback URL, bound into `state`
([F05](../track-f/F05-the-state-parameter.md)), and validated on return. That threading is
what keeps N federation relationships from bleeding into each other.

---

## The operational reality

Why this is "months of work," concretely:

**Per-customer onboarding.** Each new customer is a metadata/certificate exchange
([G07](G07-saml-survival-guide.md)) — often a back-and-forth with *their* IT team, on *their*
schedule. A self-service SSO setup UI is itself a significant build.

**Certificate rotation, times N.** Every SAML customer's IdP certificate expires and rotates
on its own schedule ([B15](../track-b/B15-certificates-and-pki.md),
[I06](../track-i/I06-key-rotation.md)). A missed rotation breaks *that customer's* login, and
you will not know until they call. You need monitoring and expiry alerting per tenant.

**Two protocols, per tenant** ([G08](G08-saml-vs-oidc.md)) — some customers OIDC, some SAML,
each configured differently.

**Provisioning and deprovisioning.** "When someone leaves, they lose access automatically"
means **SCIM** ([I02](../track-i/I02-provisioning-and-scim.md),
[I03](../track-i/I03-deprovisioning.md)) — a whole additional protocol per tenant, and the
part auditors scrutinise most.

**SSO enforcement.** `enforce_sso` means a tenant's users *cannot* use passwords — but you
must handle the break-glass case (the IdP is down, or the admin who configured it locked
themselves out). A tenant that enforces SSO and then loses its IdP is fully locked out unless
you designed an escape hatch.

**Support burden.** SSO problems are the customer's IdP misconfigured as often as your bug,
and diagnosing across an org boundary is slow.

---

## Why this is the buy case

Given all of the above, [G08](G08-saml-vs-oidc.md)'s recommendation is at its strongest here:
**buy the multi-tenant SSO layer.** SSO-specialist providers (WorkOS, BoxyHQ, and similar)
and CIAM platforms exist precisely to absorb per-tenant onboarding, dual-protocol support,
certificate rotation, and SCIM, behind one API.

You still own:

- **The tenant model** — tenants, users, and their relationships are your domain
  ([H09](../track-h/H09-multi-tenancy-isolation.md)).
- **The isolation guarantees** — no provider enforces that tenant A cannot see tenant B's
  data; that is your authorization layer ([Track H](../track-h/H01-where-does-authz-live.md)).
- **Your own session** ([E03](../track-e/E03-build-server-side-sessions.md)) — the SSO
  provider authenticates; you issue the session.

The pattern from [C05](../track-c/C05-build-vs-buy.md) holds exactly: buy *who they are*
(multi-tenant SSO), build *what they may do* and *which tenant they belong to*.

---

## Terms defined in this chapter

`tenant`, `multi-tenant`, `IdP-per-tenant`

---

## What to remember

1. **Enterprise SSO is one IdP *per customer*, configured by the customer** — not one IdP you
   chose. That is the whole shift from consumer SSO.
2. **The tenant is the organising unit.** SSO config lives on the tenant; users are unique
   *within* a tenant (`UNIQUE(tenant_id, email)`), never globally.
3. **Route users to the right IdP by email domain** — home realm discovery
   ([G10](G10-home-realm-discovery.md)).
4. **The isolation check is the security core:** an identity from tenant A's IdP must never be
   admitted into tenant B.
5. Thread the tenant through the whole flow — callback URL, `state`, and validation.
6. The work is per-customer onboarding, **certificate rotation times N**, two protocols,
   SCIM, and SSO enforcement with a break-glass path.
7. **This is the strongest buy case in the book.** Buy the SSO layer; keep the tenant model,
   isolation, and your session.

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 7 (B2B)
- [WorkOS: Enterprise SSO](https://workos.com/docs/sso)
- [RFC 7644 — SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644)
- [The SSO Wall of Shame](https://sso.tax/) — on SSO pricing, and why it is expensive to build

---

**Next:** [G10 — Home realm discovery: routing users by email domain](G10-home-realm-discovery.md)
