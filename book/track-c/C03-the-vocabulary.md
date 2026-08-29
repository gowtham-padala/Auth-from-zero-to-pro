# C03 — The vocabulary: principal, subject, claim, scope, credential, token

**Part C · The map** · *Builds on [C01](C01-auth-is-five-different-problems.md)*
---

## The core six

### Principal

> **The entity a system is making a decision about.**

A user, a service, a device, an AI agent. The generic word for "the thing that acts."

Use it when you want to say "user" but the actor might not be a person — which, by Track J,
it frequently is not. `principal` is the word that survives that transition.

### Subject

> **The principal a token or statement is *about*.** The `sub` claim.

```json
{ "sub": "4471", "iss": "https://auth.example.com" }
```

Subject is *relative to a statement*. "The subject" alone is incomplete: subject of which
token?

Two properties of `sub` that specifications insist on and implementations forget:

- **It is only unique within an issuer.** `sub: "4471"` from Google and `sub: "4471"` from
  Okta are different people. Your local key must be `(iss, sub)`, never `sub` alone. This
  is one of the top causes of cross-IdP account confusion
  ([G12](../track-g/G12-account-linking.md)).
- **It is stable; the email is not.** People change email addresses, and providers reassign
  them. Key on `sub`, display the email. Keying on email is how one employee inherits
  another's account.

Note that in **delegation** ([F19](../track-f/F19-token-exchange.md)), subject and actor
separate: `sub` is who the action is *for*, `act` is who is *doing* it.

### Identity

> **The set of attributes a system associates with a principal.**

Name, email, roles, tenant. One human can have several identities — a Google identity, a
GitHub identity, a local account — and reconciling them is
[G12](../track-g/G12-account-linking.md).

### Identifier

> **The value used to look a principal up.**

Email, username, `sub`, a UUID. [D01](../track-d/D01-identifiers.md) is entirely about
choosing one, and it matters more than it sounds.

### Credential

> **Something a principal presents to prove identity.**

| Factor | Examples |
|---|---|
| Something you **know** | password, PIN, recovery code |
| Something you **have** | phone with TOTP, security key, client certificate |
| Something you **are** | fingerprint, face |

A **factor** is a *category*, not an instance. Two passwords are not two factors. A password
plus a security question is one factor twice — both are things you know, and both are
guessable from the same public information.

### Token

> **A string that stands in for a credential or a decision.**

The key distinction, which decides your entire revocation story
([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)):

| | **Opaque / reference** | **Self-contained** |
|---|---|---|
| Content | Meaningless — a pointer | Readable claims + signature |
| Validation | Look it up | Verify the signature |
| Revocation | **Delete the row. Instant.** | **Hard.** Wait for expiry. |
| Example | `8f14e45fceea167a...` | A JWT |

### Bearer token

> **A token where possession alone is sufficient.**

Whoever holds it can use it. No proof of anything else — like cash.

This is the security model of almost every token in this book, and its weakness:
steal it, use it. The alternative is a **sender-constrained** token, which additionally
requires proving possession of a key — mTLS or DPoP
([F16](../track-f/F16-sender-constrained-tokens.md)).

---

## The four that get confused

This is the section people return to.

### Claim

> **A single assertion about a subject, as a name/value pair.**

```json
{
  "sub": "4471",
  "email": "alice@example.com",
  "email_verified": true,
  "tenant": "acme"
}
```

Each line is a claim. The issuer asserts them; the signature makes them tamper-evident; and
**a claim is only as trustworthy as its issuer.** `email_verified: false` means the IdP is
explicitly telling you not to trust the email — and accepting it anyway is a well-documented
account-takeover path ([G12](../track-g/G12-account-linking.md)).

Registered claims worth memorising:

| Claim | Meaning |
|---|---|
| `iss` | Issuer — who minted this |
| `sub` | Subject — who it is about |
| `aud` | **Audience — who may accept it** |
| `exp` | Expiry |
| `nbf` | Not before |
| `iat` | Issued at |
| `jti` | Unique token ID — for denylists ([E11](../track-e/E11-revocation.md)) |

### Scope

> **A coarse label bounding what a token may be used for. Requested by the client,
> consented by the user.**

```
scope=openid profile documents:read
```

Two properties define scope and separate it from everything else:

- **It is about the *client's* permissions, not the user's.** A scope can only ever
  *narrow*. `documents:write` on a token held by an app the user has read-only access to
  grants nothing — the token says "this app may attempt writes on the user's behalf," and
  the user's own permissions still apply on top.
- **It is coarse.** `documents:read` says nothing about *which* documents.

> **Scope is a filter on delegation. It is not an authorization model.**
>
> Every scope-based system eventually needs a real authorization layer underneath, because
> "may read documents" and "may read *this* document" are different questions. Track H is
> the second one. ([H05](../track-h/H05-roles-permissions-scopes-groups.md) does the full
> triage.)

### Role

> **A named bundle of permissions, assigned to principals.**

`admin`, `editor`, `viewer`. Roles live in **your** system, describe what a *user* may do,
and are Track H ([H04](../track-h/H04-rbac-and-when-it-breaks.md)).

**Roles and scopes are orthogonal.** A token can have `documents:write` scope while its
user has only the `viewer` role — and the write must be denied. The permission check is
`scope AND role`, never `scope OR role`, and never scope alone.

### Audience

> **Who a token is *for*.** The `aud` claim.

```json
{ "aud": "https://api.example.com" }
```

**Every resource server must reject tokens whose `aud` is not itself.** Skipping this check
is how the confused deputy attack works: a malicious service collects tokens users sent it,
then replays them against a different API that failed to check
([F08](../track-f/F08-audience-and-resource-indicators.md)).

Audience checking is the single most commonly omitted validation step in OAuth deployments,
and the MCP authorization specification makes it a hard `MUST` for exactly this reason
([J08](../track-j/J08-mcp-and-oauth-21.md)).

---

## The one-glance table

| Word | Answers | Set by | Lives in | Track |
|---|---|---|---|---|
| **principal** | Who is acting? | — | Everywhere | C |
| **subject** | Who is this *about*? | Issuer | `sub` claim | C |
| **credential** | What proves it? | The principal | Login | D |
| **token** | What carries it? | Issuer | Cookie/header | E |
| **claim** | What is asserted? | Issuer | Token payload | E |
| **scope** | What may this *app* attempt? | Client + user consent | Token | F |
| **audience** | Who may *accept* this? | Issuer | `aud` claim | F |
| **role** | What may this *user* do? | You | Your database | H |
| **permission** | What single action? | You | Your database | H |

Reading down the "Set by" column is the most useful part. **Scope and claims are set by
someone else. Roles and permissions are set by you.** Trusting the first category to
decide the second is the structural error behind a large class of authorization bugs.

---

## Two more you will meet

**Assertion** — SAML's word for a signed statement about a subject. Structurally the same
idea as an ID token, in XML ([G07](../track-g/G07-saml-survival-guide.md)).

**Authenticator** — the *thing* that holds a credential and performs the proof: a phone, a
security key, a password manager. WebAuthn's central noun
([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)).

---

## Terms defined in this chapter

`principal`, `subject`, `identity`, `identifier`, `credential`, `token`, `bearer token`,
`claim`, `scope`, `audience`, `issuer`, `factor`

---

## What to remember

1. **Principal** is the generic actor. Use it when the actor might not be human.
2. **`sub` is unique only within an issuer.** Key on `(iss, sub)`. Never on email.
3. **Factors are categories.** Two passwords are one factor.
4. **Claim** = an assertion. Trustworthy only insofar as its issuer is.
5. **Scope bounds the app. Roles bound the user.** Check both. Never scope alone.
6. **Always check `aud`.** It is the most-skipped validation in OAuth.
7. Scope and claims come from someone else. Roles and permissions are yours.

---

## Sources

- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) §4 (registered claim names)
- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) §3.3 (access token scope)
- [NIST SP 800-63-4 (Base)](https://csrc.nist.gov/pubs/sp/800/63/4/final) — Appendix A, definitions
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §2, §5.1 (standard claims)

---

**Next:** [C04 — Threat modeling for normal people: who's attacking, with what?](C04-threat-modeling.md)
