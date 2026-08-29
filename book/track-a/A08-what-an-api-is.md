# A08 — What an API is, and what "acting on someone's behalf" means

**Part A · How the web actually works** · *Builds on [A03](A03-methods-status-codes-401-vs-403.md)*
---

## What an API is

An **API** — application programming interface — is an interface designed for programs to
call rather than for people to click.

The web version is unglamorous: it is the same HTTP from
[A01](A01-what-happens-when-you-type-a-url.md), returning structured data instead of HTML.

```http
GET /api/documents/42 HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Accept: application/json
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"id": 42, "title": "Q3 plan", "owner": "alice@example.com"}
```

That is all. Same protocol, same methods, same status codes. An **endpoint** is one
callable URL.

The single meaningful difference is who is on the other end:

| | Web page | API |
|---|---|---|
| Consumer | A human, via a browser | A program |
| Response | HTML for rendering | JSON/XML for parsing |
| Credential | Cookie, sent automatically | Token, attached deliberately |
| Redirects | Followed; the user sees a login page | Useless; a program cannot log in |
| Error | A friendly page | A status code and a machine-readable body |

The redirect row matters more than it looks. A browser hitting an unauthenticated page can
be sent to a login form, where a human types a password. A program hitting an
unauthenticated endpoint cannot — there is no human, no form, no typing. It needs a
credential *before* it calls. **Everything about token-based auth follows from that one
constraint.**

---

## Three ways a program can call an API

Distinguishing these three is the point of the chapter. They look similar and have
completely different security models.

### 1. The program acting as itself

Your billing service calls your invoicing service. No user is involved. The caller has an
identity of its own.

```
billing-service ──[its own credential]──> invoicing-service
```

This is machine-to-machine authentication. It gets Track J, and the OAuth flow for it is
the client credentials grant ([F10](../track-f/F10-client-credentials.md)).

### 2. The user calling through your own front end

The browser calls your API with the user's session. The API is *yours*; the client is
*yours*; the user is present.

```
user ──[session cookie]──> your API
```

This is not delegation. It is the same trust relationship as a web page, over a different
content type. First-party. Track E, and [F17](../track-f/F17-oauth-for-spas-and-bff.md)
argues you often do not need OAuth for it at all.

### 3. A third party acting **on behalf of** the user

Some other application wants to read the user's data from your service.

```
                    ┌─── the user's data lives here
                    ▼
third-party app ──> your API
      ▲
      └─ acting with the user's permissions, without being the user
```

This is **delegated authorization**, and it is the hard one.

---

## "On behalf of" — the phrase, unpacked

Three parties, and the relationship between them is the entire subject of Track F.

- **The user** — owns the data, and wants a specific thing done.
- **The service** — holds the data, and enforces the rules.
- **The application** — wants to do the thing, and is not the user.

The problem, in one line:

> **How does the application prove to the service that the user authorized it — without
> becoming the user?**

The 2008 answer was: it *does* become the user. The application gets the password and
is indistinguishable from the human. This has a name — the **password anti-pattern** — and
it fails on five counts, each of which maps to a specific mechanism you will meet later:

| Failure | What fixes it | Chapter |
|---|---|---|
| The app gets *all* permissions | **Scopes** | [F07](../track-f/F07-access-refresh-scopes.md) |
| No way to revoke one app | **Per-app tokens** | [E11](../track-e/E11-revocation.md) |
| The app stores your password | **The app never sees it** | [F03](../track-f/F03-authorization-code-flow.md) |
| Breaks the moment you enable 2FA | **The IdP handles login** | [F02](../track-f/F02-four-roles-two-channels.md) |
| The service cannot tell app from user | **Client identity + `act` claim** | [F19](../track-f/F19-token-exchange.md) |

Every one of OAuth's parts exists to fix one row of that table. If OAuth ever feels like
arbitrary ceremony, come back to this table — it is the requirements document.

---

## What a good delegation looks like

The same 2008 scenario, done correctly:

```
1. App:     "I'd like to read this user's contacts."
2. Service: redirects the user to its OWN login page
3. User:    logs in — with 2FA, on the service's real domain, in their own browser
4. Service: "This app is asking to READ YOUR CONTACTS. Allow?"     ← consent
5. User:    Allow.
6. Service: issues the app a token that can ONLY read contacts,
            ONLY for this user, and expires in an hour.
7. App:     uses the token. Cannot send mail. Cannot change the password.
8. User:    revokes it later from a settings page, without changing anything else.
```

Every property that was missing in 2008 is present here:

- **The app never sees the password.** Step 3 happens on the service's own domain, in the
  address bar the user can verify ([A09](A09-redirects.md)).
- **The permission is narrow.** Step 6 issues a scoped credential, not a universal one.
- **The user knew.** Step 4 is informed consent, not a checkbox in a EULA.
- **It expires.** Step 6 has a lifetime.
- **It can be revoked independently.** Step 8.

That is OAuth 2.0. Not the details — the *shape*. Track F is thirteen thousand words
explaining how to make each of those eight steps unforgeable, and every one of those words
is defending one of the properties in that list.

---

## Why this is genuinely hard

The naive design fails immediately. Say the service just gives the app a token when it
asks.

- **What stops the app asking for a token for someone else's account?** Nothing. The user
  has to be involved, in their own browser session, or the app can name any victim.
- **What stops a malicious app impersonating a legitimate one?** Client identity and
  registered redirect URIs ([F09](../track-f/F09-public-vs-confidential-clients.md)).
- **The token has to get from the service to the app, and the only shared channel is the
  user's browser** — which is a hostile environment, logs URLs, and can be manipulated by
  any page. That single constraint is why the authorization *code* exists, why the code is
  single-use and short-lived, and why PKCE was needed on top
  ([F03](../track-f/F03-authorization-code-flow.md),
  [F06](../track-f/F06-pkce.md)).

The whole of OAuth is a careful answer to: *how do two servers who have never met agree on
something, using only a browser as a messenger, when the browser is untrustworthy?*
Hold that question. It makes Track F read like a solution instead of a ritual.

---

## API shapes you will meet

The auth story barely changes across these, but the vocabulary does:

- **REST** — resources as URLs, HTTP methods as verbs. Authorization per endpoint and
  per object.
- **GraphQL** — one endpoint, a query language. Endpoint-level authorization is nearly
  useless; you need field- and object-level checks, which is why GraphQL has a bad IDOR
  record ([H14](../track-h/H14-attack-your-own-authorization.md)).
- **gRPC** — binary RPC over HTTP/2. Credentials in metadata rather than headers; same
  model. Common in service meshes, so see [H12](../track-h/H12-authz-in-microservices.md).
- **Webhooks** — the API *calls you*. The direction reverses, and so does the
  authentication problem: now you must verify *their* identity
  ([J06](../track-j/J06-signing-webhooks.md)).
- **MCP** — an AI application calling tools and data sources. Structurally a client
  calling a resource server, with OAuth underneath
  ([J08](../track-j/J08-mcp-and-oauth-21.md)).

---

## Terms defined in this chapter

`API`, `endpoint`, `on behalf of`

---

## What to remember

1. An API is the same HTTP, aimed at a program instead of a person.
2. A program cannot be redirected to a login form. It needs a credential in advance. All
   of token-based auth follows from that.
3. Three call patterns: **as itself** (Track J), **as your own user** (Track E),
   **on behalf of a user** (Track F). Do not mix them up.
4. The **password anti-pattern** — giving app A your password for service B — fails on
   five counts. Each count maps to one OAuth feature.
5. Delegation is hard because the only channel between two servers is the user's browser,
   and the browser cannot be trusted.

---

## Sources

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) §1 (motivation)
- Aaron Parecki, [oauth.com — "Why OAuth?"](https://www.oauth.com/oauth2-servers/background/)
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)

---

**Next:** [A09 — Redirects, and why the address bar is a security boundary](A09-redirects.md)
