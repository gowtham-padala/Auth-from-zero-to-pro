# I02 — Provisioning: manual, just-in-time, and SCIM

**Part I · Identity lifecycle & operations** · *Builds on [I01](I01-identity-lifecycle.md), [G09](../track-g/G09-multi-tenant-sso.md)*
---

## The three approaches

```
   MANUAL              JIT (just-in-time)        SCIM
   ──────              ──────────────────        ────
   Admin creates       Account created on        Source of truth PUSHES
   each account        first SSO login           create/update/delete
   by hand
   ❌ doesn't scale    ✅ zero setup             ✅ full lifecycle
   ❌ error-prone      ⚠️ no deprovisioning      ✅ deprovisioning!
                       ⚠️ no pre-provisioning     ⚠️ real work to build
```

### Manual

Admin creates accounts one at a time. Fine for a handful of users; impossible at enterprise
scale ([I01](I01-identity-lifecycle.md)). Its only virtue is that it needs no integration.

### Just-in-time (JIT) provisioning

**Create the account automatically on the user's first successful SSO login**
([G01](../track-g/G01-sign-in-with-google.md)):

```python
@app.route("/sso/callback")
def sso_callback():
    identity = validate_sso_response(request, tenant)     # G04
    user = db.find_user_by_external_id(identity.subject)
    if user is None:
        # First login → provision now, from the token's claims. G06.
        user = db.create_user(
            tenant_id=tenant.id,
            external_id=identity.subject,                 # (iss, sub) — G12
            email=identity.email,
            roles=map_idp_groups_to_roles(identity.groups),  # H05 — map, don't adopt
        )
    ...
```

**Strengths:** zero setup, no separate integration, accounts appear exactly when needed.

**The critical weakness: JIT provisions but does *not* deprovision.** When an employee leaves,
their IdP disables them so they can't *log in* — but their account in *your* system **still
exists**, still holds its roles, and (if you allow any non-SSO path) may still be reachable
([I01](I01-identity-lifecycle.md), [I03](I03-deprovisioning.md)). JIT solves the joiner and
partly the mover; it leaves the **leaver** — the audit-failing gap — unsolved.

JIT also can't **pre-provision** (create an account before the person first logs in — needed for
sharing a document *with* a new hire before their first day) and can't update an account when
attributes change without a re-login.

### SCIM — the full lifecycle

**SCIM** (System for Cross-domain Identity Management, [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643)/[7644](https://www.rfc-editor.org/rfc/rfc7644))
is a standard REST API for provisioning. The customer's IdP (Okta, Entra, etc.) becomes a SCIM
*client* that pushes changes to *your* SCIM endpoint:

```
   Customer's IdP  ──SCIM──▶  YOUR /scim/v2 endpoint
     Joiner  → POST   /Users        create
     Mover   → PATCH  /Users/{id}    update roles, attributes, group membership
     Leaver  → PATCH  /Users/{id}    set active:false   ← THE deprovisioning fix
             → or DELETE /Users/{id}
     Groups  → /Groups              team/role assignments
```

This is what closes the leaver gap ([I01](I01-identity-lifecycle.md),
[I03](I03-deprovisioning.md)): when HR marks someone departed, the IdP sends a SCIM
`active:false`, and your system deactivates them **automatically, promptly, and verifiably** —
which is exactly what auditors ask for.

---

## A SCIM endpoint

SCIM is a defined REST/JSON API — you implement the server side:

```python
# POST /scim/v2/Users  — provision (joiner)
@app.post("/scim/v2/Users")
@scim_authenticated                          # bearer token per tenant — below
def scim_create_user():
    body = request.get_json()
    user = db.create_user(
        tenant_id=g.scim_tenant,
        external_id=body["externalId"],
        email=body["userName"],              # SCIM uses userName for the login id
        active=body.get("active", True),
        given_name=body["name"]["givenName"],
    )
    return scim_user_response(user), 201

# PATCH /scim/v2/Users/{id}  — mover AND leaver
@app.patch("/scim/v2/Users/<id>")
@scim_authenticated
def scim_patch_user(id):
    user = db.get_user_scoped(id, g.scim_tenant)     # tenant-scoped — H09
    for op in request.get_json()["Operations"]:
        if op["path"] == "active" and op["value"] is False:
            # ★ Deprovisioning. Deactivate AND kill sessions. I03.
            db.deactivate_user(user.id)
            db.delete_all_sessions_for(user.id)      # E13 — revoke live access NOW
            revoke_all_tokens_for(user.id)           # E10
            audit_log("scim.deprovision", user_id=user.id)   # H13
        elif op["path"] == "roles":
            db.set_roles(user.id, map_scim_roles(op["value"]))   # H05
    return scim_user_response(user)
```

Three things that matter:

**The `active:false` handler is the payoff** (the ★). Deactivating the account is not enough —
you must also **kill live sessions and revoke tokens** ([E13](../track-e/E13-sessions-across-devices.md),
[E10](../track-e/E10-token-lifetimes-and-rotation.md)), or a departed employee with an open
session keeps working until it expires ([I03](I03-deprovisioning.md)). Deprovisioning that only
sets a flag is the [I01](I01-identity-lifecycle.md) failure in a new costume.

**Every SCIM operation is tenant-scoped** ([H09](../track-h/H09-multi-tenancy-isolation.md)) —
one customer's IdP must only touch *its* users. A SCIM endpoint that isn't tenant-isolated is a
cross-tenant provisioning breach.

**SCIM has its own auth** — typically a per-tenant bearer token the customer configures in their
IdP ([J02](../track-j/J02-api-keys.md)). Treat it as the high-value credential it is: it can
create and delete users.

---

## SCIM + SSO: the two halves

SSO and SCIM answer different questions, and enterprise identity needs both
([G09](../track-g/G09-multi-tenant-sso.md)):

```
   SSO   → "Can this person log in?"      (authentication — Track G)
   SCIM  → "Does this account EXIST,      (provisioning — this chapter)
            with the right access, and
            is it removed when they leave?"
```

- **SSO without SCIM** — people can log in (and JIT creates accounts), but you can't
  pre-provision, can't reliably deprovision, and can't manage roles centrally.
- **SCIM without SSO** — accounts are managed, but authentication is separate.
- **Both** — the complete enterprise story: the IdP manages *who exists and what they can do*
  (SCIM) *and* authenticates them (SSO), from one source of truth.

This is why the enterprise checklist ([G08](../track-g/G08-saml-vs-oidc.md)) is *SSO + SCIM*,
and why both are "buy" candidates ([C05](../track-c/C05-build-vs-buy.md),
[G09](../track-g/G09-multi-tenant-sso.md)) — SSO/SCIM providers implement both behind one
integration.

---

## Mapping groups to roles — don't adopt, map

SCIM (and SSO) tells you the user's **groups** in the customer's directory
([G06](../track-g/G06-claims-vs-scopes-userinfo.md), [G13](../track-g/G13-enterprise-directories.md)).
As [H05](../track-h/H05-roles-permissions-scopes-groups.md) insists: **the IdP's groups are not
your roles.** Map them explicitly, per tenant:

```python
# The customer configures this mapping; you don't hardcode their group names.
GROUP_TO_ROLE = tenant.scim_group_mapping    # {"Acme-Engineers": "editor", ...}
```

This keeps *your* authorization model ([Track H](../track-h/H01-where-does-authz-live.md)) yours,
and lets each customer's directory structure map onto it without you knowing their org chart.

---

## Terms defined in this chapter

`provisioning`, `JIT provisioning`, `SCIM`

---

## What to remember

1. **Enterprises need their source of truth to manage accounts in your product** — that's
   provisioning.
2. **Manual doesn't scale. JIT is easy but doesn't deprovision** — it leaves the audit-failing
   leaver gap ([I01](I01-identity-lifecycle.md)).
3. **SCIM is the full lifecycle** — create (joiner), update (mover), deactivate (leaver) — pushed
   from the IdP.
4. **The `active:false` handler must kill sessions and revoke tokens**, not just set a flag, or
   deprovisioning is cosmetic.
5. **Every SCIM operation is tenant-scoped**, with its own per-tenant credential.
6. **SSO + SCIM is the complete enterprise story:** SSO authenticates, SCIM manages who exists
   and their access.
7. **Map the IdP's groups to your roles** — don't adopt them ([H05](../track-h/H05-roles-permissions-scopes-groups.md)).

---

## Sources

- [RFC 7643 — SCIM: Core Schema](https://www.rfc-editor.org/rfc/rfc7643) and [RFC 7644 — SCIM: Protocol](https://www.rfc-editor.org/rfc/rfc7644)
- [Okta / Entra SCIM provisioning documentation](https://developer.okta.com/docs/concepts/scim/)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 10

---

**Next:** [I03 — Deprovisioning: the offboarding gap that fails audits](I03-deprovisioning.md)
