# F05 — The state parameter: CSRF for OAuth

**Part F · Delegated authorization — OAuth 2** · *Builds on [F04](F04-build-oauth-client-raw-http.md), [E15](../track-e/E15-csrf.md)*
---

## The attack

The `state` parameter looks like a throwaway. Skipping it enables **login CSRF**, and the
attack is worth seeing in full because it is not obvious.

```
1. The attacker starts an OAuth flow with THEIR OWN account at the AS.
2. They stop at the callback and capture the code meant for their account:
        https://victim-app.example/callback?code=ATTACKER_CODE
3. They trick YOU into visiting that exact callback URL
   (a link, an image, a hidden iframe — E15).
4. Your browser hits victim-app's callback with the ATTACKER's code.
5. victim-app exchanges it, gets tokens for the ATTACKER's account,
   and logs YOU into the attacker's account.
```

Now you are using an account the attacker controls. Anything you save — a document, a
payment method, private notes — goes into *their* account, which they can read. Or the
inverse: they connect their Google Drive to *your* app account, and now your app reads their
(planted) files as if they were yours.

`state` is what stops this. It is CSRF protection ([E15](../track-e/E15-csrf.md)) for the
OAuth callback, and it is not optional.

---

## What `state` does

> **`state` binds the authorization *response* to the authorization *request* that a
> specific browser started.**

The client generates an unguessable value, sends it in the authorization request, and the
AS returns it unchanged in the callback. If the returned value does not match what *this
browser* sent, the response did not originate from a flow this browser began — so it is
rejected.

```
   Client                          Browser                    AS
     │                               │                        │
     │ generate state = xyz789       │                        │
     │ store it in THIS session      │                        │
     │──── /authorize?...&state=xyz789 ─────────────────────>│
     │                               │                        │
     │<──── /callback?code=X&state=xyz789 ───────────────────│
     │                               │                        │
     │ stored state == returned state?                        │
     │   yes → continue                                       │
     │   no  → reject (403)  ← the attack above lands here    │
```

The attacker in step 3 cannot know the `xyz789` that *your* browser generated, because it is
in *your* session, which they cannot read. Their forged callback carries *their* state (or
none), and the mismatch is caught.

---

## Doing it correctly

```python
import secrets
from flask import session, request, abort

# ── Generate and store, at the START of the flow ──
def start_flow():
    state = secrets.token_urlsafe(32)          # B03 — 256 bits, unguessable
    session["oauth_state"] = state             # server-side, bound to THIS browser
    return build_authorize_url(state=state)

# ── Verify, at the callback, BEFORE anything else ──
def handle_callback():
    returned = request.args.get("state")
    expected = session.pop("oauth_state", None)      # pop: single-use

    if not expected:
        abort(400, "no flow in progress")
    if not returned or not secrets.compare_digest(returned, expected):   # B16
        abort(403, "state mismatch")

    # only now touch the code
    ...
```

Five properties, each a real bug when missing:

| Property | Missing it means |
|---|---|
| **Unguessable** (256-bit CSPRNG) | An attacker predicts it and forges a valid callback |
| **Stored server-side, session-bound** | If it is not tied to *this browser*, it protects nothing |
| **Verified before using the code** | You act on an attacker's code before checking |
| **Single-use** (`pop`) | A captured callback URL replays |
| **Constant-time compared** | A timing oracle recovers it ([B16](../track-b/B16-timing-attacks.md)) |

The second is the one SDKs get wrong. `state` stored in a place not bound to the specific
browser session — a shared cache keyed only by the state value itself, say — provides zero
protection, because the attacker's browser and the victim's browser both satisfy it.

---

## `state` for round-tripping application data

`state` has a legitimate second use: carrying where the user was going, so you can return
them there after login.

**Do not put the data directly in `state`** — it travels the front channel, so it is visible
and tamperable ([F02](F02-four-roles-two-channels.md)):

```python
# ❌ front-channel data, tamperable
state = base64.b64encode(json.dumps({"return_to": "/documents/42"}).encode())
```

**Instead: `state` is a random key; the data lives server-side under that key.**

```python
# ✅
def start_flow(return_to: str):
    state = secrets.token_urlsafe(32)
    session[f"oauth_flow:{state}"] = {
        "return_to": validate_relative_path(return_to),   # A09 — never an open redirect
        "started_at": time.time(),
    }
    session["oauth_state"] = state
    return build_authorize_url(state=state)

def handle_callback():
    state = request.args.get("state")
    if not secrets.compare_digest(state or "", session.pop("oauth_state", "")):
        abort(403)
    flow = session.pop(f"oauth_flow:{state}", None)
    if not flow:
        abort(400)
    # ... exchange code ...
    return redirect(flow["return_to"])       # already validated as a relative path
```

**Validate `return_to` as a relative path**, or you have built an open redirect
([A09](../track-a/A09-redirects.md)) — attacker sets `return_to=https://evil.example`, and
your app sends the just-authenticated user there.

---

## `state` vs `nonce` vs PKCE — three parameters, three jobs

These get conflated constantly. They are different, and you often need all three.

| | `state` | `nonce` | PKCE `code_verifier` |
|---|---|---|---|
| Defends | The **client's callback** (CSRF) | The **ID token** (replay) | The **code exchange** (interception) |
| Lives in | The client's session | The **ID token** | The client's session |
| Checked by | The **client** | The **client** | The **AS** |
| Belongs to | OAuth | **OIDC** ([G03](../track-g/G03-id-token-vs-access-token.md)) | OAuth |
| Chapter | here | [G04](../track-g/G04-validate-an-id-token-by-hand.md) | [F06](F06-pkce.md) |

The clean way to hold them:

- **`state`** — "is this callback a response to a flow *my browser* started?" Client checks
  it against its session.
- **`nonce`** — "was this ID token minted for *this specific* authentication request?" Client
  checks it against a value it embedded and the AS echoed *inside the token*.
- **PKCE** — "is the party redeeming this code the same one that requested it?" The **AS**
  checks the verifier against the challenge.

They are not redundant. PKCE protects the code; `state` protects the callback; `nonce`
protects the ID token. An OIDC flow uses **all three**.

---

## Does PKCE make `state` redundant?

A common and reasonable question, because both defend the front channel. The answer is
**no**, and it is worth being precise:

- **PKCE** ensures a stolen *code* cannot be exchanged by anyone else. It says nothing about
  *which flow* a callback belongs to.
- **`state`** ensures the *callback* corresponds to a request *this browser* made. It is the
  CSRF defence specifically.

RFC 9700 recommends **both**. In some OIDC deployments, `nonce` can substitute for `state`'s
CSRF role — but only if you are getting an ID token and checking `nonce`. The safe, universal
answer: **always send and verify `state`.** It costs one random string.

---

## Terms defined in this chapter

`state`

---

## What to remember

1. **`state` is CSRF protection for the OAuth callback.** Omitting it enables login CSRF —
   logging a victim into the attacker's account, or vice versa.
2. It must be **unguessable, session-bound, verified before the code, single-use, and
   constant-time compared.**
3. **Session-bound is the property SDKs get wrong.** `state` not tied to *this browser*
   protects nothing.
4. Round-trip application data by making `state` a **random key** to server-side data —
   never by putting the data in `state` itself.
5. **Validate any `return_to`** as a relative path, or you have an open redirect.
6. **`state`, `nonce`, and PKCE are three different defences.** An OIDC flow uses all three.
7. PKCE does not make `state` redundant. Send both.

---

## Sources

- [RFC 6749 §10.12](https://www.rfc-editor.org/rfc/rfc6749#section-10.12) — CSRF and the `state` parameter
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.7 (CSRF)
- Aaron Parecki, [oauth.com — Redirect URLs and state](https://www.oauth.com/oauth2-servers/server-side-apps/authorization-code/)

---

**Next:** [F06 — PKCE: what it fixes, and why it's mandatory now](F06-pkce.md)
