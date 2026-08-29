# F13 — Consent screens, and the UX that prevents phishing

**Part F · Delegated authorization — OAuth 2** · *Builds on [F03](F03-authorization-code-flow.md)*
---

## Why consent exists — and its blind spot

Consent is the "you knew" property from [F01](F01-the-problem-oauth-solves.md): the user
explicitly approves what an application may do. It is what separates OAuth from the password
anti-pattern.

But consent has a structural weakness: **it moves the security decision from the platform to
the user**, and users are not equipped to make it well. They cannot tell a legitimate app
from a malicious one with a similar name; they do not read scope lists; and they are trained
by every other dialog to click the primary button.

So the consent screen has two jobs, and most designs only do the first:

1. **Ask** — get the user's approval. Easy.
2. **Inform** — make the approval *meaningful*, so the user can actually reason about it.
   Hard, and usually neglected.

A consent screen that asks without informing is not consent. It is a click.

---

## What a good consent screen does

```
   ┌────────────────────────────────────────────────────────────┐
   │  PrintCo  wants to access your Acme account                │
   │  ─────────────────────────────────────────────────────     │
   │                                                            │
   │  This will allow PrintCo to:                               │
   │                                                            │
   │    ✓  View your photos                                     │
   │       PrintCo can see all photos in your library.          │
   │                                                            │
   │    ✓  Create print orders                                  │
   │                                                            │
   │  This will NOT allow PrintCo to:                           │
   │    ✗  Delete your photos                                   │
   │    ✗  Access your contacts or messages                     │
   │                                                            │
   │  PrintCo is developed by PrintCo Inc. · printco.example    │
   │  Not verified by Acme.                    ⚠️                │
   │                                                            │
   │            [ Cancel ]        [ Allow ]                     │
   └────────────────────────────────────────────────────────────┘
```

Six properties that turn a click into a decision:

**1. Plain-language scopes.** `photos:read` renders as *"View your photos,"* with a sentence
of consequence. A user cannot consent to a permission they cannot read
([F07](F07-access-refresh-scopes.md)). This is the payoff of designing readable scopes.

**2. Say what it can *not* do.** The absence of "delete" is reassuring and informative. It
frames the request as bounded rather than open-ended.

**3. Identify the app honestly** — name, developer, domain — and **flag verification
status.** "Not verified by Acme" is the single most useful anti-phishing signal, because the
"0ffice365 Backup" attack relies on the user *not* seeing that the app is unverified.

**4. No dark patterns.** "Cancel" and "Allow" are equal in weight. The dangerous action is
not the pre-selected, brightly-coloured default. Getting this wrong is how you train users
to click through.

**5. Show it every time for sensitive scopes.** For low-risk, first-party apps, remembered
consent is fine. For broad or dangerous scopes, re-prompt — the friction is the feature.

**6. Distinguish first-party from third-party.** Your own apps may skip consent (the user is
already trusting you). A *third* party must always be shown, unmistakably, as a third party.

---

## The attacks consent screens must resist

### Consent phishing

The user is on the real AS, genuinely authenticated, and approves a **malicious app**. No
technical exploit — the user was fooled into consenting.

Platform-level defences:

- **App verification / publisher verification.** Google's "verified app" badge, Microsoft's
  publisher verification. Unverified apps requesting sensitive scopes get a prominent warning
  or are blocked outright.
- **Admin consent for high-risk scopes** in enterprise contexts — an individual user
  *cannot* grant mail-read to a new app; an administrator must. This removes the decision
  from the phishing target entirely, and it is the most effective control available for
  organisations.
- **Scope-based risk gating** — treat `mail.readwrite` differently from `profile`. Warn,
  delay, or require admin approval proportional to risk.
- **Anomaly detection** — a brand-new app suddenly consented to by hundreds of users in an
  org is a campaign in progress ([I09](../track-i/I09-detecting-account-takeover.md)).

### Redirect and clickjacking attacks

- **`redirect_uri` must be exactly matched** so consent for one app cannot deliver the code
  to another ([F03](F03-authorization-code-flow.md), [F20](F20-attack-your-own-oauth.md)).
- **`X-Frame-Options: DENY` / `frame-ancestors 'none'`** on the consent page
  ([A04](../track-a/A04-headers.md)), so an attacker cannot frame it and trick the user into
  clicking "Allow" through an overlay (**clickjacking**).

### Scope creep

An app that requested `photos:read` last month cannot silently expand to `photos:delete`. A
**new scope requires a new consent** — which is also why incremental authorization
([F07](F07-access-refresh-scopes.md)) is honest: each expansion is shown.

---

## The other side: managing granted consent

Consent is not one-time. Users and admins must be able to review and revoke it — this is the
"revocable" property from [F01](F01-the-problem-oauth-solves.md).

**A "Connected apps" page** ([E13](../track-e/E13-sessions-across-devices.md)):

```
   Apps with access to your account

   📷  PrintCo          View photos, Create orders    Last used: today    [ Remove ]
   📅  CalendarSync     Read/write calendar           Last used: 3d ago   [ Remove ]
   ❓  0ffice365 Backup  Read/write mail  ⚠️ unverified  Last used: 1h ago   [ Remove ]
                                                        ← the phishing app, findable here
```

Requirements:

- **Show every third-party grant**, with its scopes and last-used time.
- **One-click revoke**, which deletes the grant *and* its tokens
  ([E11](../track-e/E11-revocation.md)).
- **Notify on new grants**, especially for sensitive scopes — an email saying "you granted
  mail access to 0ffice365 Backup" is often how the victim discovers the attack.
- **Admin visibility** in enterprise contexts — a security team must be able to see and
  revoke every app across the org, and to hunt for a phishing campaign after the fact
  ([I10](../track-i/I10-incident-response.md)).

The connected-apps page is where a consent-phishing victim recovers. If it does not exist, or
is buried, the malicious grant persists indefinitely.

---

## Terms defined in this chapter

`consent`, `consent phishing`

---

## What to remember

1. Consent moves the security decision **to the user** — who is poorly equipped to make it.
   The screen must *inform*, not just *ask*.
2. **Consent phishing** — a real consent screen for a malicious app with a trustworthy name —
   is one of the most effective attacks against MFA-protected organisations.
3. A good screen: **plain-language scopes, what it can't do, honest app identity, verification
   status, no dark patterns, re-prompt for sensitive scopes.**
4. **"Not verified" is the highest-value signal.** The attack depends on the user not seeing
   it.
5. **Admin consent for high-risk scopes** removes the decision from the phishing target — the
   best enterprise control.
6. Frame-bust the consent page; exactly-match `redirect_uri`; require new consent for new
   scopes.
7. A **connected-apps page with one-click revoke and new-grant notifications** is how victims
   recover.

---

## Sources

- [RFC 6749 §10.2](https://www.rfc-editor.org/rfc/rfc6749#section-10.2) — client impersonation and consent
- [Microsoft: Consent phishing / illicit consent grant attacks](https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants)
- [Google: OAuth app verification](https://support.google.com/cloud/answer/9110914)
- [OWASP: Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)

---

**Next:** [F14 — Build a minimal authorization server](F14-build-an-authorization-server.md)
