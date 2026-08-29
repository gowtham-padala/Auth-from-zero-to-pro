# C01 — "Auth" is five different problems

**Part C · The map** · *Builds on [A06](../track-a/A06-cookies.md), [B14](../track-b/B14-digital-signatures.md)*
> **This is the flagship chapter.** If you read one thing in this book, read this. It is
> the map that makes every other chapter findable.

---

## The five problems

```
   ┌──────────────────────────────────────────────────────────────────────┐
   │  1. AUTHENTICATION       Who are you?                     Track D    │
   │     "Prove it."          password, TOTP, passkey                     │
   ├──────────────────────────────────────────────────────────────────────┤
   │  2. SESSION MANAGEMENT   Are you still you?               Track E    │
   │     "Stay proven."       cookie, session, JWT                        │
   ├──────────────────────────────────────────────────────────────────────┤
   │  3. DELEGATED AUTHZ      May this app act for you?        Track F    │
   │     "On your behalf."    OAuth 2                                     │
   ├──────────────────────────────────────────────────────────────────────┤
   │  4. FEDERATED IDENTITY   Do I trust who vouched for you?  Track G    │
   │     "Someone else        OIDC, SAML                                  │
   │      already checked."                                               │
   ├──────────────────────────────────────────────────────────────────────┤
   │  5. AUTHORIZATION        What may you do?                 Track H    │
   │     "Permission."        RBAC, ABAC, ReBAC                           │
   └──────────────────────────────────────────────────────────────────────┘
```

They stack, but they are **not** a pipeline. You can have any subset. A public API with API
keys has 1 and 5 and nothing else. A CLI tool has 1, 3, and 5. An internal admin panel
behind a VPN might have only 5.

Naming which ones you have is the single most clarifying thing you can do at the start of a
project.

---

## 1. Authentication — who are you?

**The question:** is the person in front of me the one who owns this account?

**The mechanism:** they present something only they should have — a password, a code from
their phone, a signature from a key on their device.

**Where it lives:** one moment in time. A single event, at the start.

**Failure mode:** an attacker convinces you they are someone else. Credential stuffing,
phishing, password reset abuse.

**Chapters:** Track D.

The thing to notice: authentication happens **once** and then it is over. Everything after
it is problem 2. Confusing the moment with the duration is the most common conceptual
error in the whole field.

---

## 2. Session management — are you still you?

**The question:** this is request #4,731 since the login. Is it still the same person?

**The mechanism:** a credential the browser presents automatically, tied to the
authentication event that produced it.

**Where it lives:** every single request, forever, until it expires or is revoked.

**Failure mode:** an attacker steals or forges the session credential. XSS theft, session
fixation, a predictable session ID, an `alg: none` JWT.

**Chapters:** Track E.

This is where HTTP's statelessness ([A05](../track-a/A05-stateless.md)) forces a decision.
And it is the layer people skip in their mental model — they think "logged in" is a state
the server maintains, when in fact it is a claim re-established on every
request from a bearer credential.

> **Why the split matters:** authentication can be perfect and session management can be
> broken, and the result is total compromise. A stolen session cookie makes the strongest
> passkey irrelevant. Conversely, flawless session management on top of a guessable
> password buys nothing.
>
> They are independently strong and independently fatal.

---

## 3. Delegated authorization — may this app act for you?

**The question:** a third-party application wants to read this user's documents. The user
says yes. How does the app prove that to the API, without becoming the user?

**The mechanism:** OAuth 2. The user authorizes at the service; the app receives a scoped,
expiring token.

**Where it lives:** between *two applications*, mediated by a user.

**Failure mode:** an attacker steals the authorization code or token, or tricks the user
into authorizing something they did not intend. `redirect_uri` smuggling, missing `state`,
consent phishing.

**Chapters:** Track F. The motivation is [A08](../track-a/A08-what-an-api-is.md).

**The thing people get wrong:** using OAuth for problems 1 and 2. OAuth is not a login
protocol. It is an *authorization delegation* protocol that happens to involve a login as a
side effect. Building "log in with OAuth" on plain OAuth 2 without OIDC produces a system
that appears to work and has no defined way to verify *who* logged in — which is exactly
why OIDC exists ([G02](../track-g/G02-oidc-on-top-of-oauth.md)).

If you are a first-party web app authenticating your own users to your own API, you may not
need any of Track F ([F17](../track-f/F17-oauth-for-spas-and-bff.md)).

---

## 4. Federated identity — do I trust who vouched for you?

**The question:** I do not want to store this user's password. Google already knows who
they are. Can I accept Google's word for it?

**The mechanism:** OIDC or SAML. Another system authenticates the user and sends you a
signed statement — an ID token or an assertion.

**Where it lives:** at authentication time, replacing problem 1 with a trust relationship.

**Failure mode:** you accept a statement you should not. Unverified signature, wrong
issuer, wrong audience, replayed assertion, an unverified email claim letting someone
take over an existing account.

**Chapters:** Track G.

Federation *replaces* authentication rather than adding to it. You are outsourcing problem
1 to an identity provider. What you gain: no passwords to store, the IdP's MFA, enterprise
customers who require it. What you take on: a critical dependency, and the job of validating
their statement correctly — a checklist longer than most people expect
([G04](../track-g/G04-validate-an-id-token-by-hand.md)).

You still need problem 2. After federated login you issue **your own** session. The IdP's
token is not your session.

---

## 5. Authorization — what may you do?

**The question:** I know exactly who this is. May they delete this document?

**The mechanism:** a policy evaluated against the principal, the action, and the resource.

**Where it lives:** every request that touches anything. **The most frequently executed
security check in your system.**

**Failure mode:** someone does something they should not. IDOR, privilege escalation,
cross-tenant data access, mass assignment.

**Chapters:** Track H.

This is the layer that:

- **Providers do not solve for you.** Your authorization model is your domain model. No
  vendor knows what "can reshare a folder" means in your product.
- **Gets the least attention** and produces the most breaches. Broken access control is
  #1 in the OWASP Top 10, and IDOR is the most common serious vulnerability found in real
  applications ([H14](../track-h/H14-attack-your-own-authorization.md)).
- **Is not a login problem at all.** A user can be authenticated
  perfectly and still see another customer's documents.

---

## How they fit together

One request through a real application:

```
  GET /api/documents/9182
  Cookie: __Host-session=8f14e45f...

     │
     │  ┌─────────────────────────────────────────────────────────┐
     ├─>│ 2. SESSION: look up 8f14e45f → user 4471, tenant 88     │
     │  │    (authentication happened days ago — problem 1)        │
     │  └─────────────────────────────────────────────────────────┘
     │
     │  ┌─────────────────────────────────────────────────────────┐
     ├─>│ 5. AUTHORIZATION: may user 4471 read document 9182?     │
     │  │    - is 9182 in tenant 88?                              │
     │  │    - does 4471 have a viewer relation on it?            │
     │  └─────────────────────────────────────────────────────────┘
     │
     ▼
   200 OK  /  403  /  404
```

Problems 1 and 4 happened days ago. Problem 3 is not involved at all — this is a
first-party request. Problems 2 and 5 run on **every** request, which is why they are
where the bugs are.

---

## The diagnostic

When something is wrong with "auth," name the layer first. It changes where you look.

| Symptom | Layer | Look at |
|---|---|---|
| "Wrong password accepted" | 1 | [D06](../track-d/D06-build-login-part-2-login.md) |
| "Attacker guessed the password" | 1 | [D08](../track-d/D08-rate-limiting-and-stuffing.md) |
| "Attacker reset the password" | 1 | [D09](../track-d/D09-account-recovery.md) |
| "Logged out randomly" | 2 | [E04](../track-e/E04-session-ids.md), [E10](../track-e/E10-token-lifetimes-and-rotation.md) |
| "Still logged in after logout" | 2 | [E14](../track-e/E14-why-logout-is-hard.md) |
| "Session stolen via a script" | 2 | [E16](../track-e/E16-xss-is-an-auth-vulnerability.md) |
| "Third-party app has too much access" | 3 | [F07](../track-f/F07-access-refresh-scopes.md) |
| "Token accepted by the wrong API" | 3 | [F08](../track-f/F08-audience-and-resource-indicators.md) |
| "Customer wants SSO" | 4 | [G08](../track-g/G08-saml-vs-oidc.md) |
| "Two accounts for one person" | 4 | [G12](../track-g/G12-account-linking.md) |
| **"User saw another user's data"** | **5** | [H14](../track-h/H14-attack-your-own-authorization.md) |
| "Admin can do things they shouldn't" | 5 | [H04](../track-h/H04-rbac-and-when-it-breaks.md) |
| "Departed employee still has access" | lifecycle | [I03](../track-i/I03-deprovisioning.md) |

---

## The sixth thing, which is not a layer

**Identity lifecycle** — Track I. Creating, changing, and removing accounts over time;
provisioning, deprovisioning, key rotation, audit logs, incident response.

It is not a sixth layer because it cuts across all five. It is listed separately because it
is the half of auth that only appears in production, it is where audits fail, and it is
almost never in the tutorial.

---

## What to buy, and what you cannot

| Layer | Buy it? |
|---|---|
| 1. Authentication | ✅ Often. Providers do this well. |
| 2. Session management | ⚠️ Partly. You still issue and control your own session. |
| 3. Delegated authz | ✅ If you are a *client*. ⚠️ Building an authorization server is real work ([F14](../track-f/F14-build-an-authorization-server.md)). |
| 4. Federated identity | ✅ Yes. Multi-tenant SSO is genuinely hard ([G09](../track-g/G09-multi-tenant-sso.md)). |
| 5. Authorization | ❌ **No.** The model is your domain. Tools help ([H11](../track-h/H11-opa-cedar-or-sql.md)); the model is yours. |

That table is the honest version of [C05](C05-build-vs-buy.md). The short form: you can
outsource *who they are*. You cannot outsource *what they may do*.

---

## Terms defined in this chapter

`authentication`, `session management`, `delegated authorization`, `federated identity`,
`authorization`

---

## What to remember

1. **"Auth" is five problems.** Authentication, session, delegation, federation,
   authorization.
2. They are **separable**. You can have any subset, and each fails independently.
3. **Authentication is a moment. Session management is a duration.** Conflating them is the
   most common conceptual error in the field.
4. **OAuth is not a login protocol.** It delegates authorization. OIDC is what adds
   identity.
5. **Layer 5 is where the breaches are**, gets the least attention, and cannot be bought.
6. Name the layer before you debug. It changes where you look.

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed. — the only book whose structure maps onto all five layers
- [OWASP Top 10 2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [RFC 6749 §1](https://www.rfc-editor.org/rfc/rfc6749#section-1) — OAuth's own statement that it is about delegation, not authentication

---

**Next:** [C02 — Authentication vs authorization vs session, once and for all](C02-authn-vs-authz-vs-session.md)
