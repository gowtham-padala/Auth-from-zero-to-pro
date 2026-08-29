# G14 — SSO's failure modes: signature wrapping, replay, and identity confusion

**Part G · Federated identity & SSO** · *Builds on [G04](G04-validate-an-id-token-by-hand.md), [F20](../track-f/F20-attack-your-own-oauth.md)*

> Federation adds two attack surfaces on top of OAuth's ([F20](../track-f/F20-attack-your-own-oauth.md)):
> the **assertion/token validation** (many ways to get it wrong — [G04](G04-validate-an-id-token-by-hand.md))
> and the **trust relationship itself** (which provider, which tenant — [G09](G09-multi-tenant-sso.md)).
> This chapter is those failure modes.

---

## Why it matters

An application validates SAML assertions ([G07](G07-saml-survival-guide.md)) but decodes ID tokens
without checking the signature "just to read the claims":

```
claims = decode(id_token, verify_signature=False)   # ← catastrophe
login(find_user(email=claims["email"]))
```

An attacker crafts an unsigned token with any email they like, and logs in as anyone. An unvalidated
assertion is a statement from a stranger, not a login ([G04](G04-validate-an-id-token-by-hand.md)).
The signature-and-claims checks are the entire security of federated login.

---

## Signature not verified — or verified wrong

The headline SSO failure. It takes several forms:

- **No signature check at all** — the `verify_signature=False` disaster above.
- **`alg: none`** — a forged JWT declares itself unsigned, and a verifier that trusts the token's
  algorithm accepts it ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).
- **Algorithm confusion** — the attacker signs a token with the provider's *published public key* used
  as an HMAC secret ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).
- **SAML: only the response envelope signed, not the assertion** — or the assertion signed by the
  wrong certificate ([G07](G07-saml-survival-guide.md)).

**The prevention:** pin the algorithm in configuration, never read it from the token; verify against
the provider's key from discovery/metadata ([G05](G05-discovery-and-well-known.md),
[E07](../track-e/E07-jose-family.md)); and confirm the **assertion itself** is what is signed.

---

## Signature wrapping (XSW) — SAML's defining attack

XML Signature Wrapping is unique to SAML's XML, and has broken implementations at major companies
repeatedly. It exploits a gap between *what is signed* and *what is read*:

```
1. Capture any validly-signed assertion (e.g. the attacker's own legitimate login).
2. Move the signed assertion elsewhere in the XML tree, and inject a NEW, unsigned
   assertion where the application will READ it.
3. The signature still verifies — it covers the (relocated) original element.
4. The application reads the injected assertion — the attacker's forged one.
```

The root cause: XML is a tree, signatures reference elements by ID, and the *verifier* and the
*consumer* can end up looking at different nodes ([G07](G07-saml-survival-guide.md)).

**The prevention — the strongest advice in this part:** **do not parse SAML XML yourself.** Use a
maintained library, verify the signature covers the *exact* element you read, reject documents with
multiple or misplaced assertions, and schema-validate. And prefer OIDC for new integrations — a JWS
signs a flat string, so there is no tree to wrap ([G07](G07-saml-survival-guide.md)).

---

## Audience and issuer confusion

A federated token is only meaningful *for a specific application, from a specific provider*
([G04](G04-validate-an-id-token-by-hand.md), [F08](../track-f/F08-audience-and-resource-indicators.md)):

- **Wrong `aud`** — a token minted for a *different* application is accepted. This is the exploitable
  "log in with OAuth" mistake ([G01](G01-sign-in-with-google.md)): reading an email from a token that
  was never issued for your app.
- **Wrong `iss`** — a validly-signed token from a *different* (attacker-controlled) provider is
  accepted.
- **Cross-tenant** — in multi-tenant SSO, a token from tenant A's provider is admitted into tenant B.
  This is a *cross-customer* breach, the worst kind ([G09](G09-multi-tenant-sso.md)).

**The prevention:** validate `aud == your client/entity ID` and `iss == the expected provider`
([G04](G04-validate-an-id-token-by-hand.md)); in multi-tenant, confirm the identity belongs to the
tenant it claims ([G09](G09-multi-tenant-sso.md)).

---

## Replay — reusing a captured token or assertion

A signature stays valid forever ([B14](../track-b/B14-digital-signatures.md)). Without freshness
checks, a captured token or assertion can be reused:

- **OIDC:** the `nonce` binds an ID token to *this* authentication request — but this check is
  *manual*; libraries don't know your nonce, so it is commonly missing
  ([G04](G04-validate-an-id-token-by-hand.md), [G02](G02-oidc-on-top-of-oauth.md)).
- **SAML:** an assertion-ID replay cache, plus `InResponseTo` correlation and `NotOnOrAfter`
  enforcement ([G07](G07-saml-survival-guide.md)).

**The prevention:** generate a per-request `nonce`, verify it, and consume it single-use; track seen
SAML assertion IDs; enforce timing windows.

---

## Open redirects and IdP-initiated abuse

Federation adds redirect-specific risks ([A09](../track-a/A09-redirects.md),
[F20](../track-f/F20-attack-your-own-oauth.md)):

- **Open redirect after login** via `RelayState` (SAML) or a `return_to` value — deadly right after a
  successful login, when the user trusts the page.
- **IdP-initiated SSO** — an *unsolicited* signed assertion POSTed to your endpoint, with no request
  to correlate against ([G07](G07-saml-survival-guide.md)).

**The prevention:** validate any post-login redirect as a relative path
([A09](../track-a/A09-redirects.md)); disable or tightly restrict IdP-initiated SSO.

---

## Account linking confusion

Federated login must resolve to the right local account ([G12](../track-g/G12-account-linking.md)):

- **Pre-account-takeover** — an attacker pre-registers with a victim's email (unverified); the victim
  later federates in and is linked to the attacker's account
  ([D02](../track-d/D02-email-as-identity.md)).
- **Keying on email instead of `(iss, sub)`** — emails change and get reassigned
  ([C03](../track-c/C03-the-vocabulary.md)).

**The prevention:** key identity on `(iss, sub)`; link only on an email verified by *both* the
provider and your own record; prefer explicit, logged-in linking; notify the user
([G12](../track-g/G12-account-linking.md)).

---

## Terms defined in this chapter

`signature wrapping`

---

## What to remember

1. **The unverified-signature class is the headline SSO failure** — pin the algorithm, verify against
   the provider's key, confirm the *assertion* is signed.
2. **Signature wrapping (XSW)** keeps a valid signature while swapping the content read. **Never parse
   SAML XML yourself** — use a maintained library.
3. **`aud` and `iss` validation** stop tokens from other apps and providers; in multi-tenant, **tenant
   isolation** prevents cross-customer breaches ([G09](G09-multi-tenant-sso.md)).
4. **The OIDC `nonce` check is manual** and commonly missing — generate, verify, single-use.
5. **Open redirects after login** and **IdP-initiated SSO** are federation-specific redirect risks.
6. **Account linking must key on `(iss, sub)` and doubly-verified email** — or it's
   pre-account-takeover ([G12](../track-g/G12-account-linking.md)).

---

## Sources

- Somorovsky et al., [*On Breaking SAML: Be Whoever You Want to Be*](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky) (USENIX 2012) — the XSW paper
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OpenID Connect Core §3.1.3.7 — ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)

---

**Next:** [H01 — Where does authorization actually live in your app?](../track-h/H01-where-does-authz-live.md)
