# G13 — Enterprise directories you'll meet: LDAP, Kerberos, Active Directory

**Part G · Federated identity & SSO** · *Builds on [G07](G07-saml-survival-guide.md)*
---

## Why this chapter exists

You will meet these acronyms in enterprise integration conversations, and they predate
everything else in this book. **Active Directory** is the identity backbone of most large
organisations; **LDAP** and **Kerberos** are the protocols underneath it. You rarely
integrate with them *directly* any more — you go through SAML or OIDC
([G08](G08-saml-vs-oidc.md)) — but you need to recognise what a customer means when they say
"we use AD," and know why the modern advice is *not* to speak these protocols yourself.

This is orientation, not implementation.

---

## LDAP — the directory query protocol

**LDAP** (Lightweight Directory Access Protocol) is how you query a hierarchical directory of
people, groups, and computers.

```
   dc=example,dc=com                          ← the organisation
     └─ ou=People                             ← organisational unit
          ├─ cn=Alice Smith                   ← an entry
          │    mail: alice@example.com
          │    memberOf: cn=Engineers
          └─ cn=Bob Jones
     └─ ou=Groups
          └─ cn=Engineers
```

Entries are identified by a **Distinguished Name** (DN) like
`cn=Alice Smith,ou=People,dc=example,dc=com` — a path through the tree.

Two operations matter for auth:

- **Bind** — authenticate: "connect as this DN with this password." A successful bind *is* a
  password check.
- **Search** — query: "find the entry for `alice@example.com`," "list members of `Engineers`."

The classic LDAP login flow: search for the user's DN by email, then attempt a bind with that
DN and the supplied password. A successful bind means the password is correct.

### The security warnings

If you ever touch LDAP directly (you should avoid it — see below):

- **LDAP injection.** Building a search filter by string concatenation is the LDAP version of
  SQL injection. `(&(mail=INPUT))` with a crafted `INPUT` becomes a filter that matches
  everyone. **Escape every user input** in a filter, or better, use parameterised APIs.
- **`ldap://` is plaintext.** Passwords cross the wire in the clear. Use **`ldaps://`** (LDAP
  over TLS) or StartTLS ([B17](../track-b/B17-what-https-protects.md)), always.
- **Anonymous bind.** Many directories allow querying without authentication. That can leak
  the entire org chart. Know whether yours is exposed.
- **The bind is a password oracle.** Your app now sees the plaintext password to bind with —
  the same anti-pattern OAuth exists to avoid ([F01](../track-f/F01-the-problem-oauth-solves.md)).
  This is the strongest reason to front LDAP with SAML/OIDC instead.

---

## Kerberos — the ticket protocol

**Kerberos** is the ticket-based authentication protocol behind Windows domain login. It is
the answer to the key distribution problem ([B10](../track-b/B10-key-distribution-problem.md))
via a **trusted third party**: everyone shares a key with a central authority, and the
authority mints session tickets.

The mental model (simplified):

```
   1. You log in once. The Key Distribution Center (KDC) gives you a
      Ticket-Granting Ticket (TGT) — proof you authenticated.
   2. To reach a service, you present the TGT and get a SERVICE TICKET for it.
   3. You present the service ticket to the service. No password re-entry.
```

This *is* single sign-on ([G11](G11-federated-sessions-single-logout.md)), invented decades
before the web — one authentication, many services, via tickets instead of re-typing
credentials. On a Windows domain, logging into your laptop gets you a TGT, and every domain
resource accepts service tickets derived from it, invisibly.

You almost never implement Kerberos. You *benefit* from it when an enterprise wants
"seamless" login — where domain-joined machines authenticate to your app with no prompt. That
integration usually happens through **Integrated Windows Authentication** at a gateway, or is
bridged to SAML/OIDC by AD FS or Entra ID.

The relevant sharp edges are legendary (Kerberoasting, golden tickets, pass-the-ticket), but
they are attacks on the *domain*, not on your app's integration — infrastructure security,
below the line this book teaches ([appendix/excluded.md](../../appendix/excluded.md)).

---

## Active Directory — the whole thing

**Active Directory** (AD) is Microsoft's directory service, and for most enterprises it *is*
"our identity system." It bundles:

```
   Active Directory
     ├─ LDAP        ← the directory (users, groups, computers)
     ├─ Kerberos    ← authentication (tickets)
     ├─ DNS         ← service location
     └─ Group Policy ← configuration management
```

Everything a large organisation knows about its people lives here: accounts, group
memberships, org structure, machine trust. When a customer says "we use AD," they mean this.

### How you actually integrate with it

**Not** by speaking LDAP or Kerberos to their domain controllers. Through a federation bridge:

| Bridge | What it does |
|---|---|
| **AD FS** (Active Directory Federation Services) | On-premise; exposes AD as a **SAML/OIDC** IdP ([G07](G07-saml-survival-guide.md)) |
| **Microsoft Entra ID** (formerly Azure AD) | Cloud; the modern successor; native **OIDC/SAML** |
| **Entra Connect** | Syncs on-premise AD into Entra ID |

So the picture, end to end:

```
   Their AD (LDAP + Kerberos on-premise)
        │  bridged by AD FS or Entra ID
        ▼
   SAML assertion / OIDC ID token  ← YOU integrate here. G07 / G02.
        │
        ▼
   Your app validates it, creates YOUR session. G04 / E03.
```

**You integrate at the SAML/OIDC layer, and never below it.** The directory protocols stay on
the customer's side of the boundary. This is deliberate and correct: it keeps their plaintext
passwords and domain internals out of your system, and gives you the same clean
"validate an assertion, issue your own session" model as every other federated login
([G01](G01-sign-in-with-google.md), [G08](G08-saml-vs-oidc.md)).

---

## The one thing to take away

> **Enterprises run AD; AD is LDAP + Kerberos; you integrate via SAML or OIDC, not the raw
> protocols.**

If a customer or a legacy system pushes you to bind against LDAP directly, understand what you
are taking on: plaintext passwords in your app, injection risk, TLS configuration, and a much
larger attack surface — all to reach a directory you could reach through a signed assertion
instead. Push back toward SAML/OIDC; it exists precisely to spare you this.

Where direct LDAP is genuinely unavoidable (an old on-premise app, an air-gapped environment),
use a maintained library, `ldaps://`, escaped filters, and treat the bind credential like the
high-value secret it is ([I05](../track-i/I05-secrets-management.md)).

---

## Terms defined in this chapter

`LDAP`, `Active Directory`, `Kerberos`

---

## What to remember

1. **AD is the identity backbone of most enterprises.** "We use AD" means LDAP + Kerberos +
   DNS + Group Policy.
2. **LDAP** queries a directory tree; a **bind** is a password check. Watch LDAP injection,
   use `ldaps://`, and note that binding means your app sees the plaintext password.
3. **Kerberos** is ticket-based SSO, decades old — one login, many services, via tickets.
4. **You integrate via SAML or OIDC**, not the raw protocols — through **AD FS** (on-premise)
   or **Entra ID** (cloud).
5. **Never speak LDAP/Kerberos to a customer's domain directly** if a federation bridge
   exists. It exists to spare you plaintext passwords and injection risk.
6. Same clean ending as all federation: **validate the assertion, issue your own session.**

---

## Sources

- [RFC 4511 — Lightweight Directory Access Protocol (LDAP): The Protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4120 — The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
- [Microsoft: Active Directory / Entra ID documentation](https://learn.microsoft.com/en-us/entra/)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)

---

**Next:** [G14 — SSO's failure modes: signature wrapping, replay, and identity confusion](G14-attack-your-own-sso.md)
