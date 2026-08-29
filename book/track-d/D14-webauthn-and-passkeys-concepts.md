# D14 — WebAuthn and passkeys: the concepts

**Part D · Authentication** · *Builds on [B14](../track-b/B14-digital-signatures.md)*
---

## The idea

A passkey is a **key pair** ([B11](../track-b/B11-asymmetric-encryption.md)).

```
   REGISTRATION
   ┌──────────────────────────────────────────────────────────────────┐
   │  Your device generates a key pair, bound to example.com.         │
   │                                                                  │
   │  private key  ──> stays on the device (or in an encrypted sync   │
   │                   keychain). NEVER transmitted.                  │
   │  public key   ──> sent to the server and stored.                 │
   └──────────────────────────────────────────────────────────────────┘

   LOGIN
   ┌──────────────────────────────────────────────────────────────────┐
   │  Server sends a random challenge.                                │
   │  Device signs (challenge + origin + other data) with the         │
   │    private key, after the user proves presence (touch/biometric).│
   │  Server verifies with the stored public key.                     │
   └──────────────────────────────────────────────────────────────────┘
```

Three properties follow directly, and each removes a whole category of attack:

**1. Your database breach yields nothing.** You store only public keys. There are no
password hashes to crack, no shared secrets to steal, no TOTP seeds to decrypt. An attacker
who dumps your `credentials` table gets a list of public keys — which were public.

**2. Phishing fails.** The signature covers the **origin** the browser is actually on. There
is no relay, because a signature for `exarnple.com` will not verify as one for
`example.com`.

**3. Nothing is reusable across sites.** Each site gets its own key pair. A breach of one
service tells an attacker nothing about your account anywhere else — which is the single
biggest problem with passwords ([D08](D08-rate-limiting-and-stuffing.md)).

---

## The vocabulary

| Term | Meaning |
|---|---|
| **WebAuthn** | The W3C browser API. `navigator.credentials.create()` and `.get()`. **Level 3** reached Candidate Recommendation in January 2026. |
| **CTAP** | Client to Authenticator Protocol — how a browser talks to an external security key. |
| **FIDO2** | The umbrella: WebAuthn + CTAP. |
| **Authenticator** | The thing holding the private key. A phone, a laptop's secure enclave, a YubiKey. |
| **Relying party (RP)** | Your service. |
| **RP ID** | The domain the credential is bound to. **The anti-phishing binding.** |
| **Passkey** | A *discoverable* credential, usually synced across a user's devices. |
| **Challenge** | Fresh server randomness, so the signature cannot be replayed. |
| **User presence (UP)** | A human touched the authenticator. |
| **User verification (UV)** | The *right* human — PIN, fingerprint, face. |
| **Attestation** | Optional evidence about what kind of authenticator this is. |

### Platform vs roaming

| | **Platform authenticator** | **Roaming authenticator** |
|---|---|---|
| Where | Built into the device — Touch ID, Windows Hello, Android | External — YubiKey, Titan |
| Transport | Internal | USB, NFC, Bluetooth |
| Portable | ❌ tied to the device | ✅ works anywhere |
| Typical use | Everyday consumer login | High-security, shared workstations |

### Synced vs device-bound

This is the distinction that defines what "passkey" means in 2026.

| | **Synced passkey** | **Device-bound** |
|---|---|---|
| Stored in | iCloud Keychain, Google Password Manager, 1Password, Dashlane | One device or one security key |
| Lost device | ✅ Restored from the cloud | ❌ Gone |
| Copies exist | Yes, across the user's devices | No |
| Assurance | Depends on the provider's account security | Higher |
| NIST AAL | Generally **AAL2** | Can reach **AAL3** ([D18](D18-step-up-auth-and-aal.md)) |

**Synced passkeys made passkeys usable.** Device-bound credentials had a fatal problem:
lose the device, lose the account. Sync moved recovery to the platform, which already
solves it well for billions of users.

The trade is that the passkey's security now depends on the user's Apple or Google account
— which is generally strong, and is a real consideration for regulated environments. If you
need AAL3, require device-bound credentials with attestation.

---

## Why it is phishing-resistant, precisely

The mechanism is worth understanding exactly, because it is the whole point.

When a page calls WebAuthn, the **browser** — not the page — assembles the client data:

```json
{
  "type": "webauthn.get",
  "challenge": "<base64url of the server's challenge>",
  "origin": "https://example.com",        ← the browser supplies this
  "crossOrigin": false
}
```

The authenticator signs `authenticatorData ‖ SHA256(clientDataJSON)`. The origin is inside
the hash. It **cannot be forged by the page**, because the page never gets to write it.

Two independent checks, both mechanical:

1. **The browser** refuses to use a credential whose RP ID does not match the current
   origin. On `exarnple.com`, a credential for `example.com` is simply not offered.
2. **The server** verifies that the `origin` in the signed client data is one it expects.

A human deciding whether a URL looks right is a check that fails under time pressure,
homoglyphs ([D02](D02-email-as-identity.md)), and fatigue. A string comparison performed by
the browser does not.

> **This is the same insight as [A09](../track-a/A09-redirects.md): the address bar is the
> only unforgeable part of the browser. WebAuthn is what happens when you let software read
> it instead of a person.**

---

## Discoverable credentials, and usernameless login

A **discoverable credential** (formerly "resident key") stores the user handle on the
authenticator itself.

- **Non-discoverable:** the server must first say *who* is logging in, then the
  authenticator finds the matching key. Two steps: username, then passkey.
- **Discoverable:** the user clicks "Sign in," the authenticator offers accounts it holds
  for this site, and the user picks one. **No username at all.**

Discoverable is what makes passkeys feel like magic, and it is what "passkey" implies in
common usage. It costs storage on the authenticator — security keys hold a limited number,
typically 25–100 — which is why hardware keys sometimes refuse to create more.

**Conditional UI** (autofill) is the best version: the browser offers passkeys in the
username field's autofill dropdown, so a user who has one sees it and a user who does not
sees a normal login form. No branching UI, no "do you have a passkey?" question.

---

## What is new in WebAuthn Level 3

Level 3 reached W3C Candidate Recommendation on 13 January 2026. The parts that change what
you can build:

| Feature | What it does | Why you care |
|---|---|---|
| **Related Origin Requests** | One passkey works across several domains, via a `/.well-known/webauthn` allowlist on the RP ID domain | Country domains: `example.co.uk`, `example.de`. Limited to **5** registrable domains. |
| **Signal API** | The site tells the password manager a credential was revoked, or that account details changed | Kills stale entries in the user's manager. Chromium-first. |
| **`getClientCapabilities()`** | Ask the browser what it supports before showing UI | No more feature-detection guesswork |
| **PRF extension** | Derive an encryption key from the passkey | End-to-end encryption keyed to a passkey |
| **Conditional create** | Register a passkey silently after a password login | The best upgrade path from passwords |
| **JSON serialisation helpers** | `parseCreationOptionsFromJSON()` etc. | Removes a mountain of manual base64url handling ([B02](../track-b/B02-encoding-is-not-encryption.md)) |

**Related Origin Requests** solves a real and previously painful problem. Before it, a
passkey was bound to exactly one registrable domain, so international sites needed a
separate passkey per country domain. Chrome/Edge 128+ and Safari 18 shipped it in 2024;
Firefox 152 added it on desktop and Android in May 2026.

**Conditional create** is the deployment strategy that actually works: when a user logs in
with a password, silently offer to create a passkey. No modal, no interruption, no
education campaign.

---

## Attestation: usually skip it

Attestation lets the authenticator prove *what it is* — "I am a genuine YubiKey 5."

Ask for it when:
- You are in a regulated environment requiring certified authenticators.
- You need AAL3 and must exclude software authenticators.
- Enterprise policy mandates specific hardware.

**Otherwise use `attestation: "none"`**, which is the default for good reasons:

- It creates a privacy concern — attestation certificates can be correlating identifiers.
- It requires maintaining a trust store of authenticator vendor roots (the FIDO Metadata
  Service), which is real operational work.
- **Synced passkeys generally do not provide meaningful attestation anyway**, so requiring
  it excludes the most usable option and most of your users.

Most consumer services do not need it. Requiring it is a common early mistake that produces
a passkey implementation nobody can enrol in.

---

## What passkeys do not solve

Being honest about this makes the rest credible.

**Account recovery.** A user who loses every device with no synced passkey and no recovery
codes is locked out. This becomes *the* design problem
([D13](D13-recovery-codes.md), [D09](D09-account-recovery.md)). Enrol two authenticators at
registration.

**Session theft.** Once logged in, the session cookie is the credential. A passkey does not
protect a stolen session ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)) — which is
why layer 2 is a separate problem ([C01](../track-c/C01-auth-is-five-different-problems.md)).

**Device compromise.** Malware with control of the device can request a signature while the
user is present. The private key is safe; the *session it produces* is not.

**Shared accounts.** Passkeys bind to individuals, which is correct and occasionally
inconvenient. Solve it with proper multi-user access, not shared credentials.

**Legacy and edge cases.** Old browsers, locked-down corporate machines, unusual assistive
technology. Always keep a fallback.

---

## Terms defined in this chapter

`WebAuthn`, `FIDO2`, `CTAP`, `passkey`, `relying party`, `RP ID`, `challenge`,
`attestation`, `phishing-resistant`

---

## What to remember

1. **A passkey is a key pair.** The server stores only the public key, so your breach yields
   nothing.
2. **The origin is inside the signature, supplied by the browser.** That is what makes
   phishing fail.
3. **Synced passkeys made this usable** by moving recovery to the platform. Device-bound is
   stronger and reaches AAL3.
4. **Discoverable credentials + conditional UI** are what make it feel like no login at all.
5. **Level 3 (Jan 2026):** Related Origin Requests (5-domain limit), Signal API,
   `getClientCapabilities()`, PRF, conditional create, JSON helpers.
6. **Use `attestation: "none"`** unless a regulator says otherwise.
7. Passkeys do not solve **recovery**, **session theft**, or **device compromise**. Plan for
   all three.

---

## Sources

- [W3C Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/) (Candidate Recommendation, 13 January 2026)
- [passkeys.dev](https://passkeys.dev/) — the practical implementation guide
- [FIDO Alliance specifications](https://fidoalliance.org/specifications/)
- [W3C: WebAuthn Signal API explainer](https://github.com/w3c/webauthn/wiki/Explainer:-WebAuthn-Signal-API-explainer)
- [Related Origin Requests explainer](https://github.com/w3c/webauthn/wiki/Explainer:-Related-origin-requests)

---

**Next:** [D15 — Build passkey registration and login](D15-build-passkeys.md)
