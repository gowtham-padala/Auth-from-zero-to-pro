# F18 — OAuth for mobile: deep links and app-claimed URLs

**Part F · Delegated authorization — OAuth 2** · *Builds on [F06](F06-pkce.md), [A09](../track-a/A09-redirects.md)*
---

## Why it matters

A mobile app does OAuth with a custom URL scheme for the redirect:

```
myapp://oauth/callback?code=SplxlOBeZQQYbYS6WxSbIA
```

**Any app on the device can register `myapp://`.** A malicious app registers the same
scheme. When the OS routes the callback, it may deliver the code to the attacker's app — or
prompt the user to choose, and users pick the wrong thing. The malicious app races to the
token endpoint and, for a public client with no secret ([F09](F09-public-vs-confidential-clients.md)),
exchanges the stolen code.

This is the exact attack that made **PKCE** mandatory ([F06](F06-pkce.md)) — and it is only
half the mobile story. The other half is *where the user logs in*: in the system browser
(safe) or in an in-app webview (a credential-harvesting trap).

Mobile OAuth has two hard problems that web OAuth does not: **the redirect has no guaranteed
owner**, and **the login surface can be counterfeited.** This chapter is both.

---

## Problem 1 — the redirect needs an owner

Web OAuth redirects to an `https://` URL your server owns
([F03](F03-authorization-code-flow.md)). On mobile, the redirect must reach the *app*, and
there are three ways to do that, of increasing safety.

### Custom URI scheme — weak

```
myapp://callback
```

Any app can claim `myapp://`. The OS does not verify ownership. Vulnerable to the
interception above. **PKCE makes it survivable** — a stolen code is useless without the
verifier — but the scheme itself provides no guarantee about *who* receives the redirect.

Acceptable only as a fallback, and only with PKCE.

### Loopback interface — for desktop/CLI

```
http://127.0.0.1:{random-port}/callback
```

The app opens a temporary local server on a random port and the browser redirects to it.
Only a process on the same machine can receive it. Good for **native desktop and CLI** apps;
irrelevant on mobile. (Note: `127.0.0.1`, not `localhost` — the latter can resolve
unexpectedly.)

### App-claimed HTTPS URLs — strong ✅

```
https://app.example.com/oauth/callback
```

The OS routes this `https://` URL directly to your app — **but only after verifying you own
the domain.** This is the answer for mobile.

| Platform | Feature | Verified by |
|---|---|---|
| iOS | **Universal Links** | `apple-app-site-association` file on your domain |
| Android | **App Links** | `assetlinks.json` on your domain (Digital Asset Links) |

You host a signed association file at a well-known path on `app.example.com`; the OS fetches
it and confirms your app is authorized for that domain. Now **no other app can claim your
redirect URL**, because no other app controls your domain. The interception attack is closed
at the OS level, not just mitigated by PKCE.

```
   https://app.example.com/.well-known/assetlinks.json        (Android)
   https://app.example.com/.well-known/apple-app-site-association   (iOS)
```

**Use app-claimed HTTPS URLs.** Fall back to a custom scheme only for older OS versions, and
always with PKCE.

---

## Problem 2 — where the user logs in

This one causes more real damage, because it is a *phishing* problem
([A09](../track-a/A09-redirects.md)).

### ❌ Embedded webview — never

```swift
// ❌ WKWebView / Android WebView showing the login page IN your app
let webView = WKWebView()
webView.load(URLRequest(url: authorizeURL))
```

An embedded webview is **controlled by your app**. Which means:

- **Your app can read everything the user types** — including their password on the IdP's
  page. The entire point of OAuth was that the client never sees the password
  ([F01](F01-the-problem-oauth-solves.md)). A webview throws that away.
- **The user cannot verify the address bar** ([A09](../track-a/A09-redirects.md)) — there
  isn't one, or the app draws a fake one. Every anti-phishing signal a user relies on is
  gone.
- **No shared session** with the real browser, so no single sign-on, and the user
  re-authenticates every time.
- **Providers block it.** Google, Microsoft, Apple, and others *refuse* OAuth in embedded
  webviews specifically to stop credential harvesting. Your integration will simply fail.

A malicious app using a webview is doing the 2006 password anti-pattern with better styling.
A *legitimate* app using one is training users that typing their password into an app is
normal — which is what makes the malicious version work.

### ✅ System browser / auth session — always

Use the OS-provided secure authentication session, which shows a **real browser with a real
address bar** and shares the system browser's cookies:

| Platform | API |
|---|---|
| iOS | **`ASWebAuthenticationSession`** |
| Android | **Custom Tabs** (Chrome Custom Tabs / equivalent) |
| Cross-platform | **AppAuth** libraries (iOS/Android), which use the above |

```swift
// ✅ iOS — the address bar is real; your app cannot read the page.
let session = ASWebAuthenticationSession(
    url: authorizeURL,
    callbackURLScheme: "https"   // or the app-claimed URL
) { callbackURL, error in
    // Receive the code, then exchange it with PKCE. F06.
}
session.presentationContextProvider = self
session.start()
```

What this buys, and why it is non-negotiable:

- **Your app never sees the credential.** The login happens in a browser process your app
  cannot inspect. OAuth's core promise is restored.
- **The address bar is real** ([A09](../track-a/A09-redirects.md)), so the user can verify
  they are on the genuine IdP — and passkeys work, with their origin binding
  ([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)).
- **Single sign-on works** — the shared cookie jar means an already-logged-in user isn't
  prompted.
- **Providers allow it**, because it is the phishing-resistant path.

> **The rule: OAuth login on mobile happens in the system browser, never in an embedded
> webview. This is not a preference — it is the difference between the app seeing the
> password or not.**

---

## Putting it together

The complete, correct mobile OAuth flow:

```
1. App generates PKCE verifier + challenge, and state.        F06 / F05
2. App opens ASWebAuthenticationSession / Custom Tab
   pointing at the AS /authorize URL.                         ← system browser
3. User authenticates on the AS (real address bar, MFA,
   passkeys) — the app sees NONE of it.
4. AS redirects to the APP-CLAIMED HTTPS URL with the code.   ← OS-verified ownership
5. The OS routes it to YOUR app (and only yours).
6. App exchanges the code + PKCE verifier at the token
   endpoint.                                                  F03
7. Tokens land in the app; refresh token → Keychain/Keystore. D16 / E10
```

Every mobile-specific defence is present: PKCE for code interception, app-claimed URLs for
redirect ownership, system browser for credential safety, secure storage for the tokens.

---

## Where the tokens go

Mobile has genuinely good secure storage, unlike browsers
([E12](../track-e/E12-where-to-store-a-token.md)):

| Store | Verdict |
|---|---|
| **iOS Keychain** | ✅ Hardware-backed on modern devices; use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| **Android Keystore / EncryptedSharedPreferences** | ✅ Hardware-backed on modern devices |
| `UserDefaults` / plain `SharedPreferences` | ❌ Readable on a rooted/jailbroken device |
| A file in app storage | ❌ Same |

The refresh token is a long-lived credential ([E10](../track-e/E10-token-lifetimes-and-rotation.md))
— Keychain/Keystore, and bind it to device unlock. Consider requiring biometric/PIN
re-auth ([D16](../track-d/D16-biometrics.md)) to *use* it for sensitive operations, so a
stolen unlocked phone is less catastrophic.

**App attestation** (Play Integrity, App Attest) can raise the cost of a modified app, but it
is a risk *signal*, not an authorization control ([A07](../track-a/A07-client-vs-server.md))
— the device belongs to the user, and a determined attacker controls it.

---

## Terms defined in this chapter

`app-claimed URL`, `custom URI scheme`

---

## What to remember

1. Mobile has two extra problems: **the redirect has no guaranteed owner**, and **the login
   surface can be counterfeited.**
2. **Use app-claimed HTTPS URLs** (Universal Links / App Links) — the OS verifies you own the
   domain, so no other app can claim your redirect. Custom schemes only as a PKCE-protected
   fallback.
3. **PKCE is mandatory** — it is what makes even an intercepted code useless
   ([F06](F06-pkce.md)).
4. **Log in through the system browser** (`ASWebAuthenticationSession` / Custom Tabs), **never
   an embedded webview.** A webview lets the app read the password and kills phishing
   resistance.
5. Providers **block embedded webviews** for exactly this reason.
6. Store tokens in the **Keychain/Keystore**, hardware-backed, device-bound.
7. Use **AppAuth** libraries — they get all of this right.

---

## Sources

- [RFC 8252 — OAuth 2.0 for Native Apps (BCP 212)](https://www.rfc-editor.org/rfc/rfc8252) — the normative source: system browser, PKCE, redirect URIs
- [Apple: Supporting Universal Links](https://developer.apple.com/documentation/xcode/supporting-universal-links-in-your-app)
- [Android: Verify Android App Links](https://developer.android.com/training/app-links/verify-android-applinks)
- [AppAuth](https://appauth.io/) — the reference native OAuth libraries

---

**Next:** [F19 — Token exchange, impersonation, and delegation](F19-token-exchange.md)
