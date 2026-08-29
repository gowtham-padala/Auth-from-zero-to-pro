# G11 — Federated sessions and single logout

**Part G · Federated identity & SSO** · *Builds on [G05](G05-discovery-and-well-known.md), [E14](../track-e/E14-why-logout-is-hard.md)*
---

## Why there are (at least) two sessions

Federated login deliberately creates independence
([G01](G01-sign-in-with-google.md), [C05](../track-c/C05-build-vs-buy.md)):

```
   ┌──────────────────────────────────────────────────────────────┐
   │  IdP SESSION (Okta)          ← "you are logged in to Okta"    │
   │     one, shared across every app that federates with Okta      │
   ├──────────────────────────────────────────────────────────────┤
   │  APP SESSION (your app)      ← "you are logged in to us"      │
   │     yours; you issued it; you control its lifetime  E03        │
   ├──────────────────────────────────────────────────────────────┤
   │  APP SESSION (another app)   ← a third app's own session      │
   │     also independent                                          │
   └──────────────────────────────────────────────────────────────┘
```

This independence is a *feature* for login — one authentication reused across many apps (the
"single" in single sign-on). It is a *problem* for logout — one logout should ideally reach
many apps, and there is no automatic mechanism that makes it.

Two logout directions, and they are not symmetric:

- **Log out of your app** → easy; kill your session ([E14](../track-e/E14-why-logout-is-hard.md)).
  But the IdP session survives, so "Sign in with SSO" logs the user *right back in* with no
  prompt — the shared-computer trap from [E14](../track-e/E14-why-logout-is-hard.md).
- **Log out everywhere (single logout)** → hard; must reach the IdP *and* every app that
  federated from it.

---

## Single logout: three approaches, all imperfect

### 1. Local logout only (the honest default)

Kill your session. Optionally redirect the user to the IdP's `end_session_endpoint`
([G05](G05-discovery-and-well-known.md)) so they can choose to log out of the IdP too.

**Be honest in the UI** ([E14](../track-e/E14-why-logout-is-hard.md)):

```
   ✅ "You've been signed out of [YourApp]."
   ⚠️ "You may still be signed in to your organisation's account."
```

Simple, reliable, and it does not over-promise. For most products this is the right default —
just do not claim more than it delivers.

### 2. Front-channel logout (fragile)

The IdP's logout page loads hidden iframes, one per app, hitting each app's logout URL:

```
   IdP logout page
      ├─ <iframe src="https://app-a.com/logout">
      ├─ <iframe src="https://app-b.com/logout">
      └─ <iframe src="https://app-c.com/logout">
```

Each iframe's request carries that app's cookie, so the app can kill its session.

**Why it is fragile — and increasingly broken:**

- It depends on **third-party cookies** in cross-site iframes, which browsers are actively
  removing ([E02](../track-e/E02-cookie-attributes.md), [A11](../track-a/A11-same-origin-and-cors.md)).
  As third-party cookies disappear, the iframe request arrives *without* the app's cookie, so
  the app cannot identify which session to kill.
- No confirmation an app actually logged out; failures are silent.
- A slow or broken app blocks the whole page.

Front-channel logout is on its way out for the same reason cross-site tracking is. Do not
build new systems on it.

### 3. Back-channel logout (the correct one)

The IdP calls each app's logout endpoint **directly, server-to-server**, with a signed
**logout token** — no browser, no iframes, no third-party cookies:

```
   IdP ──POST /backchannel-logout (logout_token JWT)──> app-a's server
   IdP ──POST /backchannel-logout (logout_token JWT)──> app-b's server
```

```python
@app.post("/backchannel-logout")
def backchannel_logout():
    logout_token = request.form["logout_token"]

    # Validate it like an ID token — signature, iss, aud, and it MUST have
    # events + a sid or sub. It MUST NOT have a nonce.  G04.
    claims = validate_logout_token(logout_token)      # OIDC Back-Channel Logout spec

    # Kill the session(s) for this subject or session id. E13.
    if "sid" in claims:
        db.delete_sessions_by_idp_session(claims["sid"])
    else:
        db.delete_all_sessions_for_external_id(claims["sub"])

    return "", 200          # 200 tells the IdP it worked
```

**This is the reliable mechanism**, and it is what solves the fired-employee failure: when IT
disables the account, the IdP sends back-channel logout to every federated app, and each
kills its sessions server-side ([E11](../track-e/E11-revocation.md),
[E13](../track-e/E13-sessions-across-devices.md)) — within seconds, not "whenever the session
expires."

Validation notes ([OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)):

- Validate signature, `iss`, `aud` exactly like an ID token ([G04](G04-validate-an-id-token-by-hand.md)).
- The token **must** contain an `events` claim marking it a logout token, and a `sid` and/or
  `sub`.
- It **must not** contain a `nonce` — a nonce would mean someone is replaying an ID token as a
  logout token.
- Track the IdP **`sid`** (session ID) at *login*, so you can match a back-channel logout to
  the exact session(s) it should end.

---

## The deprovisioning connection

The fired-employee case is really a **deprovisioning** problem
([I03](../track-i/I03-deprovisioning.md)), and single logout is only half the answer:

```
   Log out            → ends CURRENT sessions
   Deprovision (SCIM) → prevents FUTURE logins        I02 / I03
```

You need both. Back-channel logout kills the live sessions *now*; SCIM deprovisioning
([I02](../track-i/I02-provisioning-and-scim.md)) ensures the disabled user cannot start a
*new* session tomorrow. An app that supports single logout but not SCIM lets a fired employee
back in the moment they re-authenticate — which they cannot, if the IdP disabled them, *unless
your app also allows non-SSO login*. This is why `enforce_sso`
([G09](G09-multi-tenant-sso.md)) matters: it closes the password back door that would
otherwise survive IdP deprovisioning.

The auditor's question is almost always: *"When someone leaves, how fast do they lose access
across all systems?"* The complete answer is **back-channel logout + SCIM deprovisioning +
SSO enforcement.**

---

## What to actually build

For most products:

```
1. Local logout, done properly (kill YOUR session server-side). E14
2. Honest UI: "signed out of us; may still be signed in to your org."
3. Support OIDC BACK-CHANNEL logout if you serve enterprise customers
   who require fast cross-system logout. ← the one that matters
4. SCIM deprovisioning for the "future logins" half. I02 / I03
5. Avoid front-channel logout — it is dying with third-party cookies.
```

Enterprise customers with compliance requirements will specifically ask for #3 and #4. They
are what turns "we support SSO" into "we support enterprise SSO."

---

## Terms defined in this chapter

`SP-initiated logout`, `front-channel logout`, `back-channel logout`

---

## What to remember

1. **The IdP session and your app session are separate.** Killing one does not kill the other
   — the fired-employee-still-logged-in problem.
2. **Local logout is the honest default**, but the IdP session survives, so SSO logs the user
   straight back in. Say so in the UI.
3. **Front-channel logout (iframes) is fragile and dying** with third-party cookies. Don't
   build on it.
4. **Back-channel logout is the correct mechanism:** the IdP calls each app's endpoint
   directly with a signed logout token. Validate it like an ID token; track the IdP `sid` at
   login.
5. The fired-employee case needs **both** single logout (ends current sessions) **and SCIM
   deprovisioning** (prevents future logins).
6. **SSO enforcement** closes the password back door that would survive IdP deprovisioning.
7. Enterprise buyers ask specifically for back-channel logout + SCIM.

---

## Sources

- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html)
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [RFC 7644 — SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644) (the deprovisioning half)

---

**Next:** [G12 — Account linking: same human, three identity providers](G12-account-linking.md)
