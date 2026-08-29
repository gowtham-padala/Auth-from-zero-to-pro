# A07 — Client vs server: which of your code can an attacker read?

**Part A · How the web actually works** · *Builds on [A01](A01-what-happens-when-you-type-a-url.md)*
> **This is the highest-leverage chapter in Track A.** Nearly every beginner auth mistake
> — and a good share of expert ones — is a misunderstanding of what the attacker can read
> and what the attacker can change.

---

## Why it matters

A React app hides the admin panel:

```jsx
{user.isAdmin && <AdminPanel />}
```

and calls the API:

```js
const res = await fetch("/api/users", {
  headers: { "X-Admin": user.isAdmin ? "true" : "false" }
});
```

An attacker opens dev tools, types four words into the console:

```js
localStorage.setItem("user", JSON.stringify({ ...JSON.parse(localStorage.user), isAdmin: true }));
```

reloads, and the admin panel renders. Then they click a button and the API — which trusted
`X-Admin` — hands over every user record.

Two separate mistakes, and only one of them is obvious.

The obvious one: the API trusted a header ([A04](A04-headers.md)).

The subtle one, the one worth this whole chapter: **the developer thought hiding the
button was a security control.** It is not. It never was. It is a *user interface*
decision that happens to look like a security decision, and the resemblance is what makes
it dangerous.

---

## The line

There is exactly one line that matters in web security, and it is this:

```
┌────────────────────────────────┐   ┌────────────────────────────────┐
│         THE CLIENT             │   │          THE SERVER            │
│                                │   │                                │
│  Runs on THEIR machine         │   │  Runs on YOUR machine          │
│                                │   │                                │
│  They can:                     │   │  They can:                     │
│    • read every line           │   │    • send you bytes            │
│    • edit every value          │   │                                │
│    • delete your checks        │   │  That's the entire list.       │
│    • run your code backwards   │   │                                │
│    • replay any request        │   │  You control:                  │
│    • not run your code at all  │   │    • the code that runs        │
│                                │   │    • the data it reads         │
│  Everything here is            │   │    • the decisions it makes    │
│  a SUGGESTION.                 │   │                                │
│                                │   │  This is where security is.    │
└────────────────────────────────┘   └────────────────────────────────┘
                    ▲                        ▲
                    └──── the trust boundary ┘
              everything crossing it is untrusted input
```

The client is not "less trusted." It is **not trusted at all**. There is no partial
credit. Code you shipped to someone else's machine is code they own.

---

## What "they can read every line" actually means

People accept this in the abstract and then design as if it were not true. Here is what it
means concretely.

**Minification is not obfuscation.** `Ctrl+Shift+P` → "Pretty print" in dev tools, and
your bundle is readable again. Variable names are gone; logic is not.

**Source maps are usually deployed.** Most build pipelines ship `.map` files by default.
Your original TypeScript, with comments, one HTTP request away.

**Obfuscation is a speed bump.** Commercial deobfuscators exist. An LLM will explain an
obfuscated bundle to an attacker in seconds. If your security depends on someone not
understanding your code, you have no security — you have a puzzle, and puzzles get solved.

**Native apps are not different.** iOS and Android binaries are decompiled routinely.
Frida hooks running functions. A rooted device reads any file the app can. "It is
compiled" is not a security property.

**The network is inspectable regardless.** Even if the code were unreadable, every request
it makes is visible. Proxy tools like Burp Suite or mitmproxy install a CA certificate on
the device and read TLS traffic in the clear ([B15](../track-b/B15-certificates-and-pki.md)
explains why that works — the user controls their own root store).

---

## The four things client code cannot do

Stated positively, because the negative framing makes people despair.

The client **can**:
1. Provide a good experience.
2. Give fast feedback (validate a form before the round trip).
3. Hide things that are merely *irrelevant* to this user.
4. Hold a credential *for the duration of a session*, if you accept the risks.

The client **cannot**:
1. **Keep a secret.** Anything in the bundle is public. ([A10](A10-where-secrets-live.md).)
2. **Enforce a rule.** Any check can be removed.
3. **Attest to anything.** "This request came from my app" is unprovable.
4. **Be trusted about who the user is.** `user.isAdmin` in client state is a *cached copy
   of a server's answer*, not a fact.

---

## The reframe that fixes it

Stop thinking of the client as the front of your application. Think of it as **a
convenient default UI for a public API**.

Your API is public. Not "public" as in documented — public as in *anyone on the internet
can send it any request they like, in any order, with any values*. That is true today,
whether or not you intended it, because the client is just one program that talks to it.

So the question is never "can the user reach this UI?" It is always:

> **If someone wrote their own client and sent this request, what stops
> them?**

If the answer is "our UI wouldn't let them," you have a vulnerability. If the answer is
"the server checks the session's permissions before doing the work," you have a security
control.

This reframe resolves an enormous amount:

| Client-side thing | What it actually is | What must exist server-side |
|---|---|---|
| Hidden admin button | UI decluttering | Permission check on every admin endpoint |
| Disabled submit button | UX | Validation on the endpoint |
| `maxlength="20"` | UX | Length validation, and a DB constraint |
| Price shown as £10 | Display | **Server looks up the price.** Never trust a price in a request body |
| `role` in a JWT you issued | A verified claim ✅ | Verify the signature, then trust it ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) |
| `role` in `localStorage` | A note the user can rewrite | Ignore it entirely |
| Client-side route guard | Prevents a confusing 403 page | Authorization at the API |

The JWT row is the interesting one. A signed token *is* trustworthy client-side data —
because the trust comes from the signature you can verify, not from where it was stored.
That is the whole point of Track B. The distinction is not "client data bad, server data
good." It is **verifiable vs unverifiable.**

---

## Three variations that catch experienced people

### 1. "It's an internal API"

Internal means "not linked from the marketing site." It does not mean unreachable. A
misconfigured ingress, a VPN, a compromised laptop, an SSRF bug, a contractor — and your
internal API is external. This is the whole argument for zero trust, and it is why
[H12](../track-h/H12-authz-in-microservices.md) says every service authenticates its
callers, even inside the mesh.

### 2. "It's a mobile app, we control the client"

You control the code you *published*. You do not control the running process on a device
someone else owns. App attestation (Play Integrity, App Attest) raises the cost
meaningfully and is worth deploying — but it is a signal for risk scoring, not an
authorization control. Design as if the attacker has a working, modified copy of your app,
because they will.

### 3. "The secret is in an environment variable"

In a *server* environment variable, good ([A10](A10-where-secrets-live.md)). In a
`NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` variable, it is **compiled into the bundle**. The
build tool inlines it as a string literal. It is in the JavaScript your users download.
The word "environment variable" made it feel server-side; the prefix made it client-side;
nothing warned you.

This ships to production constantly. Grep your bundle for your API keys, right now,
before you finish this chapter.

---

## Where the boundary lives in each architecture

```
SERVER-RENDERED                 SPA + API                    MOBILE + API
┌──────────┐                 ┌──────────┐                  ┌──────────┐
│ Browser  │                 │ Browser  │                  │   App    │
│ (HTML)   │                 │ (JS app) │                  │ (binary) │
└────┬─────┘                 └────┬─────┘                  └────┬─────┘
     │                            │                             │
═════╪═══ boundary ═══        ════╪═══ boundary ═══        ═════╪═══ boundary ═══
     │                            │                             │
┌────┴─────┐                 ┌────┴─────┐                  ┌────┴─────┐
│  Server  │                 │   API    │                  │   API    │
│ decides  │                 │ decides  │                  │ decides  │
│ + renders│                 └──────────┘                  └──────────┘
└──────────┘
Boundary is obvious.          Boundary moved, and the       Same as SPA, plus
Hard to get wrong.            "frontend" now feels like     the false comfort
                              part of your app. It isn't.   of compilation.
```

The reason this book builds server-rendered pages until Track E is precisely this: when
the boundary is obvious, you learn where it is. Then when it moves, you still know.

---

## The test

Before shipping anything, ask:

> **"If I delete all my client code and send the raw request with `curl`, what stops the
> attack?"**

If you can name a server-side check — a session lookup, a permission query, a signature
verification — you are fine.

If your answer starts with "the UI," "the app," or "you'd have to know the URL," you have
found a vulnerability. Write it down and fix it.

---

## Terms defined in this chapter

`client-side`, `server-side`, `trust boundary`, `attacker`

---

## What to remember

1. Client code is **not trusted**. Not less-trusted. Not trusted at all.
2. Minification, obfuscation, and compilation are speed bumps, not controls.
3. Your API is public whether you meant it to be or not. Design for a hand-written client.
4. Hiding a button is UX. Checking a permission is security. They look alike and are not
   alike.
5. The distinction is **verifiable vs unverifiable**, not client vs server. A signed token
   held by the client is trustworthy; a flag in `localStorage` is not.
6. `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` secrets are in your bundle right now. Go
   look.

---

## Sources

- [OWASP Top 10 — A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Mobile Top 10 — M8: Security Misconfiguration / M9: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) V1.2 — "Verify that all access control decisions can be logged and enforced server-side"

---

**Next:** [A08 — What an API is, and what "acting on someone's behalf" means](A08-what-an-api-is.md)
