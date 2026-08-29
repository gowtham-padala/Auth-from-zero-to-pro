# I07 — Testing auth: the tests everyone skips

**Part I · Identity lifecycle & operations** · *Builds on [E16](../track-e/E16-xss-is-an-auth-vulnerability.md)*
---

## Why it matters

A team has 90% test coverage. Every feature has tests. Login has a test:

```python
def test_login():
    r = client.post("/login", data={"email": "test@x.com", "password": "correct"})
    assert r.status_code == 200        # ✅ the happy path works
```

Then an IDOR ([H14](../track-h/H14-attack-your-own-authorization.md)) ships, because **nobody
tested that user B *cannot* access user A's document.** The test suite proves the system works
for authorized users doing permitted things. It says nothing about the far more important
question: does it *stop* unauthorized users doing forbidden things?

Auth testing is inverted from feature testing. A feature test asks "does the thing work?" An
auth test asks **"does the thing correctly *not* work?"** — and that negative space is exactly
what teams skip, because it doesn't map to a user story and doesn't feel like progress.

---

## Test the denials, not just the permissions

The core discipline: **for every authorization rule, test that it *denies*, not just that it
allows.**

```python
# ❌ What everyone writes — tests only the allow.
def test_owner_can_read_document():
    assert owner_client.get("/api/documents/42").status_code == 200

# ✅ What actually prevents breaches — test every denial.
def test_non_owner_cannot_read_document():
    assert other_user_client.get("/api/documents/42").status_code in (403, 404)   # H14

def test_other_tenant_cannot_read_document():          # cross-tenant — H09
    assert other_tenant_client.get("/api/documents/42").status_code in (403, 404)

def test_unauthenticated_cannot_read_document():       # H01 — deny by default
    assert anon_client.get("/api/documents/42").status_code == 401

def test_viewer_cannot_delete_document():              # privilege — H14
    assert viewer_client.delete("/api/documents/42").status_code == 403
```

Four denial tests for one endpoint, versus one allow test. That ratio is roughly right: **most
of your auth tests should be assertions that access is refused.** The allow path is one case;
the deny paths are many, and they are where the bugs live.

The framing that makes this systematic — a matrix:

```
                  own doc   others' doc   other tenant   no auth
   owner          allow     deny          deny           deny
   editor         allow*    deny          deny           deny
   viewer         read-only deny          deny           deny
   admin          allow     allow?        deny(!)        deny
   anonymous      deny      deny          deny           deny
```

Every cell is a test. The cells that are *deny* are the ones that matter, and the ones people
skip. (Note the `deny(!)` — even an admin is confined to their tenant
[H09](../track-h/H09-multi-tenancy-isolation.md); that cell has caught real cross-tenant bugs.)

---

## The auth test suite everyone should have

Convert the failure-mode chapters ([F20](../track-f/F20-attack-your-own-oauth.md),
[G14](../track-g/G14-attack-your-own-sso.md), [H14](../track-h/H14-attack-your-own-authorization.md), and the vulnerability
concepts throughout Tracks D–H)
into a **standing regression suite** — the attacks become tests that run on every commit:

```python
class TestAuthorization:
    def test_idor_across_users(self):                     # H14
        for endpoint in OBJECT_ENDPOINTS:
            assert user_b.get(endpoint.format(user_a_object)).status_code in (403, 404)

    def test_idor_across_tenants(self):                   # H09 — the worst case
        assert tenant_b.get(f"/api/documents/{tenant_a_doc}").status_code in (403, 404)

    def test_mass_assignment_blocked(self):               # H14 / D05
        r = user.patch("/api/users/me", json={"is_admin": True, "role": "admin"})
        assert not db.get_user(user.id).is_admin

    def test_privilege_escalation_blocked(self):          # H14
        assert user.post("/api/users/me/roles", json={"role": "admin"}).status_code == 403

class TestSessions:
    def test_session_id_rotates_on_login(self):           # E04 — fixation
        before = anon.get_session_cookie()
        anon.login(...)
        assert anon.get_session_cookie() != before

    def test_logout_invalidates_server_session(self):     # E14
        token = login_get_token()
        logout()
        assert client.get("/api/me", cookies={"session": token}).status_code == 401

    def test_password_change_kills_other_sessions(self):  # D09
        other = login_get_token()
        change_password()
        assert client.get("/api/me", cookies={"session": other}).status_code == 401

class TestTokens:
    def test_alg_none_rejected(self):                     # E06 — the two-line forge
        forged = make_unsigned_jwt({"sub": "1", "role": "admin"})
        assert api.get("/admin", token=forged).status_code == 401

    def test_expired_token_rejected(self):                # E06
        assert api.get("/data", token=expired_token()).status_code == 401

    def test_wrong_audience_rejected(self):               # F08
        assert api.get("/data", token=token_for_other_api()).status_code == 401
```

Once these exist, **a regression that reintroduces an old vulnerability fails CI** — which is the
whole point. The [H14](../track-h/H14-attack-your-own-authorization.md)
attacks are a one-time exercise; this suite makes them permanent.

---

## The tests that are specifically skipped

Beyond the deny-matrix, a checklist of the auth tests that are almost universally missing:

```
☐ Enumeration: same response/timing for existing vs non-existing user   D07
☐ Rate limiting: the limit actually triggers, on the right key          D08
☐ MFA rate limiting: 6-digit code brute force is bounded                D12
☐ Session rotation on EVERY privilege change (login, MFA, pw change)    E04
☐ Logout kills the SERVER session, not just the cookie                  E14
☐ Password change / reset invalidates other sessions                    D09
☐ alg:none and algorithm confusion rejected                             E06
☐ aud / iss / exp / nonce validated on tokens                           G04
☐ redirect_uri exact-matched; state checked                             F20
☐ Deny-by-default: an unprotected route is BROKEN, not open             H01
☐ Fail-closed: authz errors deny, not allow                             H02
☐ Tenant isolation under connection-pool reuse                          H10
☐ Deprovisioning kills live sessions + tokens                           I03
```

Note how many are *negative* or *lifecycle* assertions — precisely the tests that don't
correspond to a feature and so never get written.

---

## Test at the right level

Different auth properties need different test levels:

- **Unit** — the authorization *decision* function ([H01](../track-h/H01-where-does-authz-live.md)):
  `can(viewer, "delete", doc)` returns `False`. Fast, exhaustive over the deny-matrix.
- **Integration** — the *enforcement* ([H02](../track-h/H02-the-enforcement-point.md)): the
  endpoint actually returns 403, through the real middleware and DB. This is where "the decision
  was right but nobody called it" is caught.
- **End-to-end** — full flows: login → session → authorized request → logout, including OAuth/OIDC
  round-trips against a test IdP.

The integration level is the one that catches the [H02](../track-h/H02-the-enforcement-point.md)
failure — the decision function is correct, but an entry point (export, GraphQL, job) bypasses
it. Unit-testing the decision alone gives false confidence.

---

## Beyond your own tests

Your suite proves the properties you *thought of*. Two things catch what you didn't:

- **Static analysis / SAST** — flags missing authorization checks, unsanitized inputs, and
  common patterns automatically.
- **DAST / fuzzing** — tools that probe endpoints for IDOR, injection, and access-control gaps at
  runtime, finding the endpoints you forgot to protect.
- **Penetration testing** — the human adversary, budgeted for the higher-risk tracks
  ([README](../../README.md)'s note on paid review for F/G/H/J). A pentest finds the creative
  bypass your tests and scanners don't model.

And the standard to test *against*: **OWASP ASVS** ([K01](../track-k/K01-architecture-review.md))
gives a checklist of verifiable auth requirements — chapters 2 (authentication), 3 (session
management), and 7 (access control) map directly onto testable assertions
([I11](I11-compliance.md)).

---

## Terms defined in this chapter

(No new glossary terms; this chapter operationalises the failure-mode coverage.)

---

## What to remember

1. **Auth testing is inverted:** a feature test asks "does it work?", an auth test asks "does it
   correctly *not* work?" The negative space is what's skipped.
2. **Test the denials.** For every rule, assert that unauthorized access is *refused* — most of
   your auth tests should be denial assertions.
3. **Use a deny-matrix** (roles × resources) — every *deny* cell is a test, including
   admin-across-tenants.
4. **Turn the failure-mode coverage into a standing regression suite** so old vulnerabilities fail CI.
5. **Test at the enforcement level, not just the decision** — that's where the
   [H02](../track-h/H02-the-enforcement-point.md) bypass hides.
6. **Cover the specifically-skipped tests:** enumeration, rate limits, session rotation,
   alg:none, tenant isolation, deprovisioning.
7. **Add SAST/DAST and a pentest** for what your tests didn't think of, and **test against
   OWASP ASVS.**

---

## Sources

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — V2, V3, V7 (testable auth requirements)
- [OWASP WSTG — Authentication, Session, Authorization testing](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — labs that map to test cases

---

**Next:** [I08 — Observability for auth: what to log, and what never to log](I08-observability.md)
