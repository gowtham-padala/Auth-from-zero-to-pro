# J08 — MCP and OAuth 2.1: dynamic client registration, resource-scoped tokens

**Part J · Machine, workload & agent identity** · *Builds on [J07](J07-auth-for-ai-agents.md), [F14](../track-f/F14-build-an-authorization-server.md)*
> The other half of your differentiator, and the concrete protocol behind agent auth. This is the
> capstone of the whole book: every OAuth chapter, assembled into the standard the AI ecosystem is
> building on right now.

---

## The MCP authorization model

MCP maps directly onto the OAuth roles you know ([F02](../track-f/F02-four-roles-two-channels.md)):

```
   MCP CLIENT           MCP SERVER               AUTHORIZATION SERVER
   (the AI app)         (the tool/resource)      (issues tokens)
   = OAuth client       = OAuth RESOURCE server   = OAuth AS
   F02                    F02/F08                   F02/F14
```

- The **MCP server is an OAuth 2.1 resource server** ([F02](../track-f/F02-four-roles-two-channels.md)) —
  it accepts access tokens and serves protected tools/data.
- The **MCP client is an OAuth 2.1 client** ([F02](../track-f/F02-four-roles-two-channels.md)) —
  making requests on behalf of a user ([J07](J07-auth-for-ai-agents.md)).
- The **authorization server** authenticates the user and issues tokens; it may be hosted with the
  resource server or separate.

Everything from Track F applies. What MCP *adds* is the machinery for these parties to find and
authenticate each other **with no prior manual setup** — because at agent scale, manual setup is
impossible.

---

## The three problems MCP had to solve

### 1. Discovery: how does a client find the AS?

An MCP client hits a tool server it's never seen. How does it learn where to authenticate? Via the
**`WWW-Authenticate` header on a 401** ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)) —
the discovery mechanism that chapter said matters here:

```
   1. MCP client → MCP server: a request with no token.
   2. MCP server → 401 with:
      WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
   3. Client fetches that Protected Resource Metadata (RFC 9728) → learns which AS to use.
   4. Client fetches the AS's metadata (RFC 8414 / OIDC discovery — G05) → learns its endpoints.
```

This chains together specs from across the book:
**Protected Resource Metadata** ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)) — MCP servers
**MUST** implement it — tells the client which AS protects the resource; **Authorization Server
Metadata** ([RFC 8414](https://www.rfc-editor.org/rfc/rfc8414)) / OIDC discovery
([G05](../track-g/G05-discovery-and-well-known.md)) tells it the endpoints. The client
self-configures from a single 401, with zero hand-configured URLs — the [A03](../track-a/A03-methods-status-codes-401-vs-403.md)/[G05](../track-g/G05-discovery-and-well-known.md)
discovery machinery doing exactly what it was built for.

### 2. Registration: how does a client get a client_id, at scale?

Manual registration ([F09](../track-f/F09-public-vs-confidential-clients.md)) doesn't scale to
thousands of clients. MCP supports two automatic mechanisms:

- **OAuth Client ID Metadata Documents** (a newer draft) — the client uses an **HTTPS URL as its
  `client_id`**, and the AS fetches the client's metadata from that URL. The client is identified by
  a document it hosts — no registration call at all. MCP clients and servers **SHOULD** support this.
- **Dynamic Client Registration** ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) — the client
  **POSTs to a `/register` endpoint** at runtime and gets a `client_id` back. MCP treats this as
  supported but *deprecated in favour of* Client ID Metadata Documents.

Either way, a brand-new client-server pair can establish an OAuth relationship **automatically**,
which is what makes the many-to-many agent ecosystem possible.

### 3. Audience: how do you stop token passthrough?

The confused-deputy risk ([F08](../track-f/F08-audience-and-resource-indicators.md),
[J07](J07-auth-for-ai-agents.md)) is *acute* for agents, which handle many tokens for many
resources. So MCP makes the [F08](../track-f/F08-audience-and-resource-indicators.md) rules **hard
`MUST`s** — this is the chapter's most important security content:

```
   ✅ The client MUST implement Resource Indicators (RFC 8707):
      send the `resource` parameter in BOTH the authorization and token requests,
      naming the EXACT MCP server.  F08
   ✅ The MCP server MUST validate that the token was issued for IT as the audience.  F08
   ❌ The client MUST NOT send a token to any server other than the one it was issued for.
      → NO token passthrough.  F08
   ❌ The MCP server MUST NOT accept or forward tokens not issued for it.
```

Every token is bound to one specific MCP server ([F08](../track-f/F08-audience-and-resource-indicators.md)),
so a compromised or manipulated agent ([J07](J07-auth-for-ai-agents.md)) **cannot** replay a token
meant for one tool against another. This is [F08](../track-f/F08-audience-and-resource-indicators.md)'s
"the most-skipped check in OAuth," elevated to a mandatory requirement precisely because the agent
world can't afford to skip it.

---

## The full flow

Assembling it — every arrow is a Track F/G chapter:

```
 MCP CLIENT (agent)                MCP SERVER (RS)              AUTH SERVER
   │                                    │                          │
   │── request (no token) ─────────────>│                          │
   │<── 401 WWW-Authenticate ───────────│  ← discovery. A03/RFC9728 │
   │      resource_metadata=...          │                          │
   │── fetch protected-resource-metadata >│  → learns the AS         │
   │── fetch AS metadata ───────────────────────────────────────── >│  G05
   │── register (Client ID Metadata Doc or DCR) ───────────────────>│  RFC 7591
   │                                    │                          │
   │  ── authorization code + PKCE + resource=<this server> ──────> │  F03/F06/F08
   │      (user authenticates & consents on the AS)                 │  J07 — delegation
   │  <── code ──                                                   │
   │  ── token request + PKCE verifier + resource=<this server> ──> │  F06/F08
   │  <── access token (aud = THIS MCP server) ────────────────────│
   │                                    │                          │
   │── request + Bearer token ─────────>│  validates aud == itself  │  F08
   │<── tool result ────────────────────│  (rejects if not)         │
```

Notice the requirements MCP inherits and mandates:
**OAuth 2.1** (code flow + **PKCE mandatory**, no implicit — [F06](../track-f/F06-pkce.md),
[F15](../track-f/F15-implicit-and-password-grants.md)), **`iss` validation** to defeat mix-up
([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207), [F20](../track-f/F20-attack-your-own-oauth.md)),
and the audience rules above. MCP is essentially "OAuth 2.1 with the security BCP
([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)) turned into hard requirements, plus automatic
discovery and registration." Note that OAuth 2.1 itself is still a **draft**
([F01](../track-f/F01-the-problem-oauth-solves.md)) — MCP references a specific draft revision, and
the spec is versioned and evolving.

---

## Step-up and scopes, the MCP way

MCP also standardises **incremental authorization** ([F07](../track-f/F07-access-refresh-scopes.md),
[D18](../track-d/D18-step-up-auth-and-aal.md)) — an agent requests minimal scopes, and asks for more
when a tool needs them, via the `WWW-Authenticate` challenge ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)):

```
   HTTP 403 Forbidden
   WWW-Authenticate: Bearer error="insufficient_scope",
                     scope="files:write",
                     resource_metadata="..."
```

The server tells the client *exactly* which scope it needs ([F07](../track-f/F07-access-refresh-scopes.md));
the client runs a **step-up authorization flow** to acquire it, accumulating scopes across
operations. This is the RFC 9470 step-up pattern ([D18](../track-d/D18-step-up-auth-and-aal.md))
applied to tools — least privilege ([H01](../track-h/H01-where-does-authz-live.md)) for agents,
enforced by the protocol: the agent starts with the minimum and earns more only as tasks require,
which bounds a manipulated agent ([J07](J07-auth-for-ai-agents.md)).

---

## Why this is the capstone

Look at what one MCP flow uses — it is the entire book:

| MCP requirement | Chapter |
|---|---|
| OAuth roles, two channels | [F02](../track-f/F02-four-roles-two-channels.md) |
| Authorization code flow | [F03](../track-f/F03-authorization-code-flow.md) |
| PKCE (mandatory) | [F06](../track-f/F06-pkce.md) |
| `resource` parameter + `aud` validation (MUST) | [F08](../track-f/F08-audience-and-resource-indicators.md) |
| `iss` validation (mix-up defence) | [F20](../track-f/F20-attack-your-own-oauth.md) |
| Discovery via `WWW-Authenticate` + `.well-known` | [A03](../track-a/A03-methods-status-codes-401-vs-403.md), [G05](../track-g/G05-discovery-and-well-known.md) |
| JWT/token validation | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md), [G04](../track-g/G04-validate-an-id-token-by-hand.md) |
| Delegation (user → agent) | [F19](../track-f/F19-token-exchange.md), [J07](J07-auth-for-ai-agents.md) |
| Step-up / incremental scopes | [D18](../track-d/D18-step-up-auth-and-aal.md), [F07](../track-f/F07-access-refresh-scopes.md) |
| The security BCP | [F14](../track-f/F14-build-an-authorization-server.md), [F20](../track-f/F20-attack-your-own-oauth.md) |

MCP is not a new auth system. It's **the assembly of everything this book taught, into the standard
the AI ecosystem is standardising on right now.** Which is the reassuring conclusion of the whole
book: the newest, fastest-moving frontier in identity is built entirely from the fundamentals — and
you now know all of them.

---

## Terms defined in this chapter

`MCP`, `protected resource metadata`, `dynamic client registration`, `client ID metadata document`,
`WWW-Authenticate`

---

## What to remember

1. **MCP is OAuth 2.1 for agent-to-tool connections** — the MCP server is a resource server, the MCP
   client an OAuth client, with automatic discovery and registration for a many-to-many world.
2. **Discovery via `WWW-Authenticate` + Protected Resource Metadata (RFC 9728, MUST) + AS metadata**
   — a client self-configures from a single 401 ([A03](../track-a/A03-methods-status-codes-401-vs-403.md),
   [G05](../track-g/G05-discovery-and-well-known.md)).
3. **Registration scales via Client ID Metadata Documents** (preferred) or **Dynamic Client
   Registration** (RFC 7591, deprecated) — no manual per-pair setup.
4. **Audience is mandatory:** clients **MUST** send the `resource` parameter (RFC 8707); servers
   **MUST** validate the token was issued for them; **no token passthrough**
   ([F08](../track-f/F08-audience-and-resource-indicators.md)). The confused-deputy defence, elevated
   to a hard requirement.
5. **PKCE is mandatory, `iss` is validated** — OAuth 2.1 + the security BCP as hard requirements
   ([F06](../track-f/F06-pkce.md), [F20](../track-f/F20-attack-your-own-oauth.md)).
6. **Step-up / incremental scopes** via `WWW-Authenticate` challenges enforce least privilege for
   agents ([D18](../track-d/D18-step-up-auth-and-aal.md), [F07](../track-f/F07-access-refresh-scopes.md)).
7. **MCP is the capstone** — it assembles the entire book. The newest frontier is built from the
   fundamentals you now know. (OAuth 2.1 is still a draft; the spec is versioned and evolving.)

---

## Sources

- [Model Context Protocol — Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization) — the normative source for every claim here
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728)
- [RFC 8707 — Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707), [RFC 7591 — Dynamic Client Registration](https://www.rfc-editor.org/rfc/rfc7591), [RFC 9207 — Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [The OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) and [RFC 9700 — OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700)

---

**Track J complete.** You can authenticate machines, workloads, and AI agents — from API keys to
SPIFFE to MCP. Track K assembles the entire book into one application, then breaks it.

**Next:** [K01 — One app, all five layers: architecture review](../track-k/K01-architecture-review.md)
