# K03 — Build the capstone, part 2: OAuth, SSO, authorization

**Part K · Capstone** · *Builds on Tracks F, G, H*
> Layers 3, 4, and 5 on top of part 1. Delegation, federation, and — the layer where the breaches
> are — authorization.

---

## What we're adding

[K02](K02-capstone-part-1.md) gave us authentication and sessions (layers 1–2). Now: third-party API
access (OAuth, layer 3), enterprise SSO (OIDC/SAML, layer 4), and the authorization that decides what
a known user may do (layer 5). Repo tag `ep-K03-capstone-2`.

The critical join: [K02](K02-capstone-part-1.md)'s middleware established *who* the user is
([C02](../track-c/C02-authn-vs-authz-vs-session.md)); this chapter adds *what they may do* — and the
two must stay distinct, because conflating them is IDOR
([H14](../track-h/H14-attack-your-own-authorization.md)).

---

## Layer 4: SSO (federation), feeding into part 1

Enterprise customers log in via *their* IdP ([G09](../track-g/G09-multi-tenant-sso.md)), and the flow
ends by calling [K02](K02-capstone-part-1.md)'s `complete_login`:

```python
@app.post("/sso/start")
def sso_start():
    tenant = find_tenant_by_email_domain(request.form["email"].split("@")[1])  # HRD  G10
    if not tenant or not tenant.sso_type:
        return redirect("/login/password")                 # no SSO for this domain
    return redirect(build_authorize_url(tenant, state=..., nonce=...))  # per-tenant  G09

@app.route("/sso/callback/<tenant_id>")
def sso_callback(tenant_id):
    tenant = db.get_tenant(tenant_id)
    identity = validate_sso(request, tenant)               # OIDC: 10 checks  G04 / SAML: G07
    if not identity_belongs_to_tenant(identity, tenant):   # ★ isolation  G09
        abort(403)
    user = resolve_or_link(identity, ...)                  # (iss,sub), verified email  G12
    return complete_login(user, amr=["sso"], acr=identity.acr)   # ← same session path as K02!
```

The design payoff: **federation feeds the same `complete_login`** ([K02](K02-capstone-part-1.md)) as
password login. Whether the user authenticated with a password, a passkey, or their company's Okta,
the *session* is issued and managed identically ([E03](../track-e/E03-build-server-side-sessions.md),
[C05](../track-c/C05-build-vs-buy.md)) — "own your session regardless of how they logged in." The
ID-token validation ([G04](../track-g/G04-validate-an-id-token-by-hand.md)) and tenant isolation
([G09](../track-g/G09-multi-tenant-sso.md)) are the security-critical steps; SCIM
([I02](../track-i/I02-provisioning-and-scim.md)) handles the lifecycle around it.

---

## Layer 3: OAuth — the app as a client

Our app lets users connect third-party services (import documents from their Drive). The app is an
OAuth *client* ([F04](../track-f/F04-build-oauth-client-raw-http.md)):

```python
@app.get("/connect/drive")
@login_required                                            # they're already OUR user  K02
def connect_drive():
    verifier, challenge = make_pkce()                      # F06
    g.session_store["drive_pkce"], g.session_store["state"] = verifier, make_state()
    return redirect(drive_authorize_url(challenge=challenge, state=..., resource=DRIVE_API))  # F08

@app.get("/connect/drive/callback")
@login_required
def drive_callback():
    check_state(...)                                       # F05
    tokens = exchange_code(request.args["code"], verifier=g.session_store["drive_pkce"])  # back channel  F03/F06
    store_third_party_tokens(g.user.id, "drive", encrypt(tokens))   # server-side, encrypted  E10/I05
    return redirect("/documents")
```

And our app is *also* an OAuth *server* for third parties who want to access our documents — the
minimal AS ([F14](../track-f/F14-build-an-authorization-server.md)), with exact `redirect_uri`
matching, mandatory PKCE, single-use codes, and `aud`-scoped tokens ([F08](../track-f/F08-audience-and-resource-indicators.md)).
The security is in the checks the AS makes ([F20](../track-f/F20-attack-your-own-oauth.md)).

---

## Layer 5: authorization — where the breaches are

The most important layer, and the one you can't buy ([C01](../track-c/C01-auth-is-five-different-problems.md),
[C05](../track-c/C05-build-vs-buy.md)). Two models, as [K01](K01-architecture-review.md) decided:
**ReBAC for sharing** ([H07](../track-h/H07-rebac-and-zanzibar.md), [H08](../track-h/H08-model-drive-in-openfga.md))
and **RBAC for admin** ([H04](../track-h/H04-rbac-and-when-it-breaks.md)), enforced at the service
layer with RLS underneath ([H02](../track-h/H02-the-enforcement-point.md), [H10](../track-h/H10-row-level-security.md)):

```python
class DocumentService:
    def get(self, actor, doc_id):
        # ① Tenant isolation: RLS already filtered to actor's tenant.  H09/H10
        doc = self.repo.get(doc_id)                        # returns None if wrong tenant
        if doc is None: raise NotFound()                   # 404 hides existence  A03/H14

        # ② Object-level authorization: ReBAC check.  H07/H08 — this is what stops IDOR
        if not fga.check(f"user:{actor.id}", "viewer", f"document:{doc_id}").allowed:
            raise Forbidden()                              # H14

        return doc

    def delete(self, actor, doc_id):
        doc = self.repo.get(doc_id)
        if doc is None: raise NotFound()
        if not fga.check(f"user:{actor.id}", "owner", f"document:{doc_id}").allowed:  # owner-only
            raise Forbidden()
        self.repo.delete(doc)
        self.audit.record(actor, "document.delete", doc_id)   # tamper-evident  H13

    def share(self, actor, doc_id, target, relation):
        if not fga.check(f"user:{actor.id}", "owner", f"document:{doc_id}").allowed:  # sharing is authorized too!  H03
            raise Forbidden()
        fga.write([(f"user:{target}", relation, f"document:{doc_id}")])  # a tuple IS the grant  H08
        self.audit.record(actor, "document.share", doc_id, target, relation)
```

Three enforcement layers stack ([K01](K01-architecture-review.md)):

```
   ① RLS (database)       → tenant isolation. Unbypassable. Every query.   H10
   ② ReBAC (service)      → object-level authz. Stops IDOR.                H07/H14
   ③ RBAC (middleware)    → admin routes (deny by default).                H04/H01
```

**Every entry point calls the service** ([H02](../track-h/H02-the-enforcement-point.md)) — the API,
the GraphQL resolver, the CSV export, the background job. That's what stops the "another path bypassed
the check" failure ([H14](../track-h/H14-attack-your-own-authorization.md)). Make the service the
only door to the data, and IDOR becomes structurally hard.

Admin authorization uses RBAC ([H04](../track-h/H04-rbac-and-when-it-breaks.md)), deny-by-default
([H01](../track-h/H01-where-does-authz-live.md)):

```python
@app.get("/admin/users")
@require_permission("users:list")                          # deny by default  H01
def admin_users(): ...
```

---

## Layer J: machine and agent access

The app also serves machines and agents ([J01](../track-j/J01-machine-identity-is-not-user-identity.md)):

- **API keys** for external integrations — hashed, prefixed (`sk_live_`), scoped
  ([J02](../track-j/J02-api-keys.md)).
- **mTLS** between internal services ([J04](../track-j/J04-mtls.md)), each authorizing the action, not
  just trusting the network ([H12](../track-h/H12-authz-in-microservices.md)).
- **MCP** for AI agents ([J08](../track-j/J08-mcp-and-oauth-21.md)) — the app is an MCP server
  (resource server), validating audience-bound tokens ([F08](../track-f/F08-audience-and-resource-indicators.md)),
  and agents get *task-scoped, delegated* access ([J07](../track-j/J07-auth-for-ai-agents.md)) — a
  subset of their user's permissions, with the agent on the audit record.

Notice all of these end at the *same* authorization service — `fga.check(...)`. Whether the actor is
a user, an API key, or an agent acting for a user, the object-level authorization
([H07](../track-h/H07-rebac-and-zanzibar.md)) is identical. **One authorization model, many
principals** — which is exactly [J07](../track-j/J07-auth-for-ai-agents.md)/[J08](../track-j/J08-mcp-and-oauth-21.md)'s
point that agents add a principal type, not a new auth model.

---

## The integration checklist

```
☐ SSO feeds the SAME complete_login as password/passkey                  K02/G01
☐ ID token: all 10 checks; tenant isolation on SSO callback              G04/G09
☐ OAuth client: PKCE, state, back-channel exchange, tokens encrypted     F05/F06/E10
☐ OAuth server: exact redirect_uri, single-use codes, aud-scoped         F14/F08
☐ Object-level authz on EVERY document access (no IDOR)                  H14
☐ Every entry point (API, GraphQL, export, job) calls the service        H02
☐ RLS backstops tenant isolation                                         H10
☐ Sharing is itself authorized (owner-only)                              H03
☐ Admin: RBAC, deny by default                                           H01/H04
☐ Agents get task-scoped delegated tokens; on the audit record           J07
☐ ALL principals (user/key/agent) hit the same authz service            J07/J08
☐ Audit log: tamper-evident, every security-relevant action              H13
```

---

## What to remember

1. **Federation feeds the same session path as password login** — own your session regardless of how
   they logged in ([K02](K02-capstone-part-1.md), [C05](../track-c/C05-build-vs-buy.md)).
2. **The app is an OAuth client** (connecting third-party services) **and an OAuth server** (letting
   third parties in) — both from Track F.
3. **Authorization is three stacked layers:** RLS (tenant, unbypassable), ReBAC (object-level, stops
   IDOR), RBAC (admin, deny by default).
4. **Every entry point calls the service** — the one door to the data — or a path bypasses the check
   ([H02](../track-h/H02-the-enforcement-point.md), [H14](../track-h/H14-attack-your-own-authorization.md)).
5. **Sharing is itself an authorized action** ([H03](../track-h/H03-acls-and-direct-permissions.md)).
6. **One authorization model, many principals** — user, API key, and agent all hit the same
   `fga.check` ([J07](../track-j/J07-auth-for-ai-agents.md)).
7. **Layer 5 is the one you can't buy and where the breaches are** — the architecture must make IDOR
   structurally hard ([C01](../track-c/C01-auth-is-five-different-problems.md)).

---

## Sources

- *API Security in Action* (Neil Madden), Ch. 7–9 (OAuth, authorization)
- [OpenFGA documentation](https://openfga.dev/docs) ([H08](../track-h/H08-model-drive-in-openfga.md))
- [OWASP ASVS V7 (Access Control)](https://owasp.org/www-project-application-security-verification-standard/)

---

**Next:** [K05 — What should you use? The decision tree](K05-the-decision-tree.md)
