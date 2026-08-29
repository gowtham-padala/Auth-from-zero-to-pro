# F08 — Audience and resource indicators: the part everyone gets wrong

**Part F · Delegated authorization — OAuth 2** · *Builds on [F07](F07-access-refresh-scopes.md)*
---

## The attack

You run a small, low-trust API — a webhook receiver, say. A user connects it via OAuth, and
it faithfully receives their access tokens.

You are malicious. You take one of those tokens and present it to a *different*, high-value
API from the same provider — the payments API, the admin API. It **works**, because that API
verified the token's signature ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)),
saw it was validly issued, and accepted it — without checking that the token was meant *for
it*.

You are now acting against an API you were never authorized to touch, using tokens users
handed to your innocuous-looking service.

This is the **confused deputy**: a low-privilege component's credentials misused against a
high-privilege one. The `aud` claim is the fix, and **the missing `aud` check is the single
most common serious flaw in real OAuth deployments.**

---

## The `aud` claim

> **`aud` (audience) names who a token is *for*. Every resource server MUST reject any
> token whose `aud` is not itself.**

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-4471",
  "aud": "https://api.example.com",       ← this token is ONLY for this API
  "scope": "photos:read",
  "exp": 1756348800
}
```

The check the payments API in the attack failed to make:

```python
def validate(token):
    claims = verify_signature(token)                    # ① authentic
    if claims["iss"] != EXPECTED_ISSUER:                # ② from our AS
        raise Invalid()
    if MY_IDENTIFIER not in as_list(claims["aud"]):     # ③ FOR ME  ← the missing line
        raise Invalid("token not intended for this resource server")
    if claims["exp"] < now():                           # ④ not expired
        raise Invalid()
    require_scope(claims, needed_scope)                 # ⑤ scope. F07
    authorize_object(claims, resource)                  # ⑥ per-object. H14
    return claims
```

Line ③ is the one everyone skips. A verified signature proves the token is *authentic*
([B14](../track-b/B14-digital-signatures.md)); it says nothing about *who it is for*.
"Valid" and "valid for me" are different claims, and the gap between them is this attack.

`aud` may be a string or an array. Handle both.

---

## Why this is so commonly wrong

Three reasons, all structural:

**1. It works without the check.** In development, everything is your own API, so the token
is always for you, so omitting the `aud` check breaks nothing. The bug only manifests when a
*second* resource server exists — which is exactly when the stakes rise.

**2. Signature verification *feels* complete.** The hard-looking part — fetching the JWKS,
checking the signature ([E07](../track-e/E07-jose-family.md)) — succeeds, and it is
tempting to stop there. But signature verification answers "is this real?", not "is this
mine?"

**3. Single-audience mental model.** Teams that start with one API internalise "a valid
token is a usable token." Then they add a second API, copy the validation code, and inherit
the missing check into a context where it now matters.

---

## Resource indicators (RFC 8707)

The `aud` claim is checked by the *resource server*. But how does the client tell the *AS*
which resource server it wants a token *for*, so the AS can set `aud` correctly?

That is [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) — the `resource` parameter:

```http
GET /authorize?
    response_type=code
    &client_id=printco
    &scope=photos:read
    &resource=https://api.example.com       ← "I want a token FOR this API"
    &...
```

The client says which API it intends to call, and the AS mints a token whose `aud` is that
API — and *only* that API.

Why this matters:

**It bounds the blast radius per token.** Without resource indicators, an AS often issues one
token valid for *all* the resource servers the client is registered for. That single token,
if leaked, works everywhere. With resource indicators, the client gets a **narrow token per
API**, so a leak is contained to one.

**It is how you get different tokens for different services.** A client calling both the
photos API and the calendar API should request two tokens, each scoped to its own audience,
so neither can be replayed against the other.

**It makes `aud` meaningful in the first place.** Without a way to *request* an audience,
`aud` is whatever the AS decides, often a catch-all. Resource indicators let the client and
AS agree on a specific, narrow audience.

---

## Where this becomes mandatory: MCP

The MCP authorization specification ([J08](../track-j/J08-mcp-and-oauth-21.md)) makes both
sides of this a hard requirement, precisely because AI agents pass tokens between many
resources and the confused-deputy risk is acute:

- The MCP client **MUST** implement RFC 8707 and send the `resource` parameter in **both**
  the authorization and token requests, identifying the exact MCP server.
- The MCP server (as resource server) **MUST** validate that the token was issued for it as
  the intended audience, per RFC 8707.
- The client **MUST NOT** send a token to any server other than the one it was issued for —
  no **token passthrough**.

That last rule names the general anti-pattern: **token passthrough** — forwarding a token
you received to a *different* downstream API. It is almost always a vulnerability, because
the downstream API's `aud` check either fails (good) or was omitted (the confused deputy).
If service A needs to call service B on the user's behalf, it should perform **token
exchange** ([F19](F19-token-exchange.md)) to obtain a token whose `aud` is B — not forward
A's token.

---

## The checklist for a resource server

Every resource server, on every request:

```
☐  ① Signature verified against the AS's JWKS          E06 / E07
☐  ② iss matches the expected authorization server
☐  ③ aud contains MY identifier   ← the one everyone forgets
☐  ④ exp / nbf enforced (with small leeway for skew)
☐  ⑤ Required scope present                            F07
☐  ⑥ Per-object authorization performed                H14
☐     Never forward this token to another API          F19
```

Steps ①–④ are token validity. Step ⑤ is delegated authorization. Step ⑥ is object
authorization. **All three layers, every request.** A system that does ① and ⑤ and skips ③
and ⑥ is the norm, and it is why BOLA/IDOR and confused-deputy attacks are so common.

---

## Terms defined in this chapter

`aud`, `resource indicator`, `confused deputy`, `token passthrough`

---

## What to remember

1. **A verified signature says "authentic," not "for me."** `aud` is the difference.
2. **Every resource server MUST reject tokens whose `aud` is not itself.** This is the
   single most-skipped check in OAuth.
3. It is skipped because it **works without it** until a second API exists — which is when
   it starts mattering.
4. **Resource indicators (RFC 8707)** let the client request a token *for a specific API*,
   so `aud` is narrow and a leak is contained.
5. **Never forward a token to a different API** (token passthrough). Use token exchange
   ([F19](F19-token-exchange.md)).
6. **MCP makes both the `resource` parameter and the `aud` check hard `MUST`s**
   ([J08](../track-j/J08-mcp-and-oauth-21.md)).
7. Validity (①–④) + scope (⑤) + object authorization (⑥). All three, every request.

---

## Sources

- [RFC 8707 — Resource Indicators for OAuth 2.0](https://www.rfc-editor.org/rfc/rfc8707)
- [RFC 9068 — JWT Profile for Access Tokens](https://www.rfc-editor.org/rfc/rfc9068) §4 (audience validation)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.9 (audience restriction)
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization) — audience validation as a MUST

---

**Next:** [F09 — Public vs confidential clients, and why it changes everything](F09-public-vs-confidential-clients.md)
