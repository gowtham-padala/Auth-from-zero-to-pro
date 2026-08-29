# F19 — Token exchange, impersonation, and delegation

**Part F · Delegated authorization — OAuth 2** · *Builds on [F07](F07-access-refresh-scopes.md)*
---

## Token exchange (RFC 8693)

> **Trade one token for another** — with a different audience, narrower scope, or a different
> subject.

```http
POST /token HTTP/1.1
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<the user's token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=https://service-b.example.com          ← the token I actually need
&scope=orders:read                                ← narrowed for this call
```

The AS validates the incoming `subject_token`, applies policy, and issues a **new** token
whose `aud` is `service-b` and whose scope is exactly `orders:read`. The gateway calls
service-b with *that* token — correct audience, least privilege, small blast radius.

This is how a request fans out across services correctly
([H12](../track-h/H12-authz-in-microservices.md)): each hop exchanges for a token scoped to
the next hop, rather than forwarding a token meant for the first.

---

## Impersonation vs delegation — the distinction that matters

Token exchange can produce two very different results, and confusing them is an audit and
accountability failure.

### Impersonation — acting *as* the user

The new token looks exactly like the user's. The downstream service sees the user, and
**there is no record that anyone else was involved.**

```json
{ "sub": "user-4471", "aud": "service-b", "scope": "orders:read" }
```

Service-b believes user-4471 made the request. It cannot tell that the gateway — or an admin,
or a support agent — was the actual actor. From the logs, the user did it.

**Use impersonation only when the actor should genuinely be invisible** — e.g. a trusted
internal gateway that is architecturally transparent. For anything involving a human acting
on another human's behalf, impersonation destroys accountability and should be avoided.

### Delegation — acting *for* the user, on the record

The new token names **both** the subject (who it's for) and the **actor** (who's really
doing it), via the `act` claim:

```json
{
  "sub": "user-4471",                    // the action is for this user
  "act": { "sub": "support-agent-99" },  // but THIS actor is performing it
  "aud": "service-b",
  "scope": "orders:read"
}
```

Now service-b knows: *the support agent is acting on behalf of user-4471.* Both identities
are in the audit log ([H13](../track-h/H13-audit-logging.md)). Accountability is preserved.

`act` can even nest, for chains: agent → gateway → user.

> **Impersonation hides the actor. Delegation records the actor.** When a human acts for
> another human — support, admin, an agent — **use delegation.** When you truly need the
> action attributed solely to the subject, and the actor is a transparent piece of
> infrastructure, impersonation is acceptable.

The vocabulary comes straight from [C03](../track-c/C03-the-vocabulary.md): **subject** =
who it's about, **actor** = who's doing it. Token exchange is where they diverge.

---

## Where this is used

**Microservice fan-out.** Done right, each service
exchanges for a token scoped to the next call ([H12](../track-h/H12-authz-in-microservices.md)).

**Admin impersonation ("log in as user").** Support needs to reproduce a user's problem
([I04](../track-i/I04-admin-impersonation.md)). Token exchange with **delegation** — `act`
names the admin — so every action the admin takes "as" the user is attributable to the
admin. This is the safe way to build "log in as customer," and building it with
impersonation (no `act`) is how support access becomes an unauditable backdoor.

**Downscoping.** A service holds a broad token but needs to pass a *narrow* one to a
less-trusted component. Exchange for a reduced-scope token, so the component gets only what
it needs ([F07](F07-access-refresh-scopes.md)).

**Crossing trust domains.** A token from IdP-A is exchanged for one trusted in domain B — the
token equivalent of federation ([Track G](../track-g/G02-oidc-on-top-of-oauth.md)).

**AI agents.** An agent acting for a user should carry a **delegated** token — `act` names the
agent, `sub` names the user — so the resource server and the audit log both know a non-human
actor is involved ([J07](../track-j/J07-auth-for-ai-agents.md)). This is one of the most
important emerging uses, and getting the impersonation/delegation distinction right is what
keeps agent actions accountable.

---

## The policy question

Token exchange is powerful, so the AS must gate it carefully. Uncontrolled exchange is a
privilege-escalation engine.

The AS must decide, per request:

- **May this client exchange this token at all?** Not every client should be permitted.
- **May it request *this* audience?** Restrict which downstream audiences a given actor can
  target.
- **Impersonation or delegation?** Some actors may impersonate; most should only delegate.
- **Can it *widen* scope?** Almost never — exchange should downscope, not upscope
  ([F07](F07-access-refresh-scopes.md)).
- **How does the actor authenticate?** An `actor_token` may be required to prove who is
  requesting the exchange.

Get this wrong and token exchange becomes the thing that lets a low-trust service mint a
high-trust token — the confused deputy ([F08](F08-audience-and-resource-indicators.md)),
industrialised.

---

## Terms defined in this chapter

`token exchange`, `impersonation`, `delegation`, `act claim`

---

## What to remember

1. **Don't forward a token to a different audience** (token passthrough). **Exchange it** for
   a token scoped and audienced for the actual call.
2. Token exchange (RFC 8693) trades one token for another: different audience, narrower scope,
   different subject.
3. **Impersonation hides the actor** (`sub` only). **Delegation records the actor** (`sub` +
   `act`).
4. **When a human acts for a human — support, admin, agents — use delegation.** Impersonation
   destroys accountability.
5. Uses: microservice fan-out, admin "log in as user," downscoping, cross-domain,
   **AI agents**.
6. The AS must **gate exchange by policy** — who, which audience, impersonate vs delegate,
   and never widen scope.

---

## Sources

- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693) (the `act` claim is §4.1)
- [RFC 8693 §1.1](https://www.rfc-editor.org/rfc/rfc8693#section-1.1) — impersonation vs delegation
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.11 (audience of exchanged tokens)

---

**Next:** [F20 — OAuth's failure modes: redirect_uri smuggling, mix-up, token leakage](F20-attack-your-own-oauth.md)
