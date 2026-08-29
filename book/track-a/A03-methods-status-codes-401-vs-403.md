# A03 — HTTP methods, status codes, and why 401 is not 403

**Part A · How the web actually works** · *Builds on [A02](A02-reading-http-in-dev-tools.md)*
---

## Methods: the verb

The method is the first word of the request. It says what kind of operation this is.

| Method | Means | Safe? | Idempotent? | Body? |
|---|---|---|---|---|
| `GET` | Give me this | Yes | Yes | No |
| `HEAD` | Give me just the headers | Yes | Yes | No |
| `POST` | Here is something; do a thing with it | **No** | **No** | Yes |
| `PUT` | Make this resource be exactly this | No | Yes | Yes |
| `PATCH` | Change part of this resource | No | No | Yes |
| `DELETE` | Remove this | No | Yes | No |
| `OPTIONS` | What may I do here? | Yes | Yes | No |

Two words in that table carry weight.

**Safe** means the method is not supposed to change anything. `GET` is safe. This is a
contract, not an enforcement — a server *can* delete a record on `GET`, and some do, and
those servers get their data deleted by search engine crawlers and by browser prefetch.

**Idempotent** means doing it five times has the same effect as doing it once. `DELETE` is
idempotent (it is gone; deleting it again keeps it gone). `POST` is not (five POSTs to
`/orders` create five orders). Idempotency is why clients may safely retry `PUT` and
`DELETE` on a network timeout but must not blindly retry `POST`.

### Why this matters for auth

Three concrete consequences, all of which come back later:

**1. CSRF defences hinge on safety.** A cross-site request forgery attack works by making
a victim's browser issue a state-changing request. If your `GET` endpoints genuinely
change nothing, an attacker cannot do damage with an `<img src>` tag. If your `GET
/account/delete` endpoint works, they can.
([E15](../track-e/E15-csrf.md).)

**2. `SameSite=Lax` cookies are sent on top-level `GET` navigations but not on
cross-site `POST`s.** The browser's default protection is *built on the safe/unsafe
distinction*. Violate it and you have opted out of a protection you did not know you
had. ([E02](../track-e/E02-cookie-attributes.md).)

**3. Method-based authorization is a classic bypass.** A rule that checks `POST /admin/*`
but not `PUT /admin/*` is bypassed by changing one word. Authorize the *operation*, not
the verb. ([H02](../track-h/H02-the-enforcement-point.md).)

---

## Status codes: the answer

Five families. The first digit is the whole story.

| Family | Meaning | Whose problem |
|---|---|---|
| `1xx` | Hold on, still going | — |
| `2xx` | It worked | — |
| `3xx` | Go somewhere else | — |
| `4xx` | **You** did something wrong | The client's |
| `5xx` | **I** did something wrong | The server's |

That `4xx`/`5xx` split is a genuine debugging shortcut. `4xx` — fix your request. `5xx` —
read their logs, or your own.

### The ones that appear constantly in auth

| Code | Name | Say it in English |
|---|---|---|
| `200` | OK | Here it is. |
| `201` | Created | I made it; the `Location` header says where. |
| `204` | No Content | Done. Nothing to send back. |
| `302` / `303` | Found / See Other | Go to the `Location` header. |
| `304` | Not Modified | You already have it. |
| `400` | Bad Request | I could not parse that. |
| **`401`** | **Unauthorized** | **I do not know who you are.** |
| **`403`** | **Forbidden** | **I know who you are. No.** |
| `404` | Not Found | No such thing — *or* I am not telling you it exists. |
| `405` | Method Not Allowed | That resource exists; that verb does not apply. |
| `409` | Conflict | State collision. Duplicate email at registration. |
| `422` | Unprocessable Content | I parsed it; the values are invalid. |
| `429` | Too Many Requests | Slow down. See `Retry-After`. |
| `500` | Internal Server Error | I crashed. |
| `503` | Service Unavailable | I am down or overloaded. |

---

## 401 vs 403, properly

This is the section people come here for.

> **`401 Unauthorized` means unauthenticated.** The name is a forty-year-old mistake in
> the specification that is now impossible to fix. Read it as "401 Unauthenticated."
>
> **`403 Forbidden` means unauthorized.** Authentication succeeded. Authorization failed.

The decision procedure:

```
        Did a valid credential arrive?
                 │
        ┌────────┴────────┐
        NO               YES
        │                 │
      401              Is this principal
   Unauthorized        allowed to do this?
                             │
                     ┌───────┴───────┐
                     NO             YES
                     │               │
                   403             2xx
                Forbidden
```

The practical distinction is **retryability**:

- **`401` is retryable with a better credential.** Log in, refresh the token, present the
  certificate. The client's correct reaction is to *acquire a credential and try again*.
  This is why an expired token must be `401` — it triggers the refresh path
  ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).
- **`403` is not retryable.** No credential will help. This user, authenticated as
  themselves, may not do this thing. The client's correct reaction is to *stop and tell
  the human*.

### The rule that follows

**Never return `403` for an authentication problem, and never return `401` for an
authorization problem.** Concretely:

| Situation | Correct code |
|---|---|
| No `Authorization` header | `401` |
| Malformed token | `401` |
| Expired token | `401` |
| Invalid signature | `401` |
| Valid token, insufficient scope | `403` |
| Valid session, not this user's document | `403` **or** `404` — see below |
| Valid session, account suspended | `403` |

### `401` requires a `WWW-Authenticate` header

This is in the specification and almost universally ignored. A `401` must tell the client
*how* to authenticate:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="api", error="invalid_token",
                  error_description="The access token expired"
```

This is not pedantry. This header is the discovery mechanism that the MCP authorization
specification builds its entire bootstrap on — a client with no configuration makes an
unauthenticated call, reads `WWW-Authenticate`, and learns where to go
([J08](../track-j/J08-mcp-and-oauth-21.md)). A `401` with no `WWW-Authenticate` is a dead
end for any client that was not hardcoded in advance.

For insufficient scope, the parallel is `403` plus:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="documents:write"
```

Now the client knows exactly what to ask for next.

---

## When `404` is the right answer to an authorization failure

Sometimes `403` leaks information. Consider:

```
GET /documents/9182   →  403 Forbidden
GET /documents/9183   →  404 Not Found
```

You have just told an attacker that document 9182 exists and 9183 does not. Enumerate the
ID space and you have a complete inventory of your customers' documents, including
approximate volume, growth rate, and which IDs are worth attacking. You have leaked no
content — and quite a lot of intelligence.

The mitigation is to return `404` for "exists but you may not see it," making existence
itself unobservable:

| Case | Behaviour |
|---|---|
| The resource is not secret; the operation is | `403`. "You may not delete this shared document." |
| The resource's *existence* is sensitive | `404` for both missing and forbidden. |

The same reasoning drives login error messages, where it has a name — user enumeration —
and its own chapter, [D07](../track-d/D07-user-enumeration.md).

A caution: `404`-for-forbidden makes your own support harder. Log the real distinction
server-side, always. Return the ambiguous answer, record the precise one.

---

## Status codes that quietly matter

**`429 Too Many Requests`** — the rate limiting response. Include `Retry-After`. Do not
use `403`; clients cannot tell "slow down" from "never." ([D08](../track-d/D08-rate-limiting-and-stuffing.md).)

**`405 Method Not Allowed`** — tells an attacker the path exists. Consider whether you
want that.

**`302` vs `303` vs `307`** — after a `POST`, `302` historically caused browsers to
convert the follow-up to `GET`; `303` says so explicitly, and `307` preserves the method
and body. For POST/Redirect/GET, `303` is the correct one. `307` after a login POST would
re-POST your credentials to the destination — including, potentially, to a different
host.

---

## Terms defined in this chapter

`method`, `safe method`, `idempotent`, `status code`, `401 Unauthorized`,
`403 Forbidden`

---

## What to remember

1. **`401` = "who are you?" `403` = "not you."** The name of `401` is wrong; the meaning
   is not.
2. `401` is retryable with a credential; `403` is not. That is why the distinction is
   worth caring about.
3. Every `401` should carry `WWW-Authenticate`. It is the discovery mechanism modern
   clients bootstrap from.
4. Return `404` instead of `403` when the *existence* of the resource is itself sensitive.
   Log the real answer regardless.
5. `GET` must not change state. Real browser protections are built on that promise.

---

## Sources

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) §9 (methods), §15 (status codes)
- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750) §3 (`WWW-Authenticate` for bearer tokens)
- [MDN: HTTP response status codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)

---

**Next:** [A04 — Headers: the metadata every request carries](A04-headers.md)
