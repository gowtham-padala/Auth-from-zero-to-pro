# K06 — Where to go next: specs, papers, and staying current

**Part K · Capstone** · *Builds on [K05](K05-the-decision-tree.md)*
> The last chapter. You've built and broken all five layers. This is how to keep learning, where the
> authoritative sources are, and how to stay current in a field that moves.

---

## You now know the whole graph

143 chapters ago, this book started with a byte ([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).
It ends with AI agents authenticating to tools over MCP ([J08](../track-j/J08-mcp-and-oauth-21.md)) —
and the last chapter's reassurance was that MCP is *built entirely from the fundamentals in the
earlier chapters.* That's the meta-lesson: **auth is not a pile of disconnected specs. It's a small
set of primitives — hashing, randomness, MACs, signatures, certificates ([Track B](../track-b/B01-bits-bytes-text-as-numbers.md)) —
arranged into five layers ([C01](../track-c/C01-auth-is-five-different-problems.md)), over and over.**
Every new development you'll meet is those primitives rearranged. You have the graph now; new nodes
attach to it.

---

## The primary sources, by track

The authoritative references — read the *spec*, not a blog summary of it, when something matters
([K05](K05-the-decision-tree.md), [appendix/rfc-index.md](../../appendix/rfc-index.md)):

| Track | Read first |
|---|---|
| **A** (web) | [MDN HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP); Grigorik, *High Performance Browser Networking* (free) |
| **B** (crypto) | Wong, *Real-World Cryptography*; Aumasson, *Serious Cryptography*; [Cryptopals](https://cryptopals.com/) |
| **C** (map) | Wilson & Hingnikar, *Solving Identity Management in Modern Applications* (2nd ed) — **the structural spine** |
| **D** (authn) | [The Copenhagen Book](https://thecopenhagenbook.com/); [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final); [OWASP Auth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html); [passkeys.dev](https://passkeys.dev/) |
| **E** (sessions/JWT) | The Copenhagen Book; [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)/[7515](https://www.rfc-editor.org/rfc/rfc7515); [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725); OWASP Session Cheat Sheet |
| **F** (OAuth) | [oauth.net](https://oauth.net/) (Parecki); [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749); **[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)** (Security BCP); Richer & Sanso, *OAuth 2 in Action* |
| **G** (federation) | [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html); [NIST SP 800-63C](https://csrc.nist.gov/pubs/sp/800/63/c/4/final); OASIS SAML Technical Overview |
| **H** (authz) | [Google Zanzibar paper](https://research.google/pubs/pub48190/); [zanzibar.academy](https://zanzibar.academy/); [OpenFGA docs](https://openfga.dev/); OPA/Cedar docs |
| **I** (ops) | [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) (SCIM); *Solving Identity Management*; cloud KMS docs |
| **J** (machine/agent) | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) (mTLS); [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP); [SPIFFE](https://spiffe.io/); [MCP auth spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| **K** (capstone) | Madden, *API Security in Action* — **the best technical writing in the field**; [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700); [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) ch. 2, 3, 7 |

Two books carry disproportionate weight ([SOURCES.md](../../SOURCES.md)): **Solving Identity
Management in Modern Applications** — the only book whose structure maps onto all five layers — and
**API Security in Action** — the reference for the technical work in E, F, and H.

---

## How to read a spec

RFCs are dense but authoritative, and learning to read them is what separates people who *know* auth
from people who've read blogs about it:

- **RFC 2119 keywords** — `MUST`, `SHOULD`, `MAY` have precise meanings. `MUST` is a requirement;
  `SHOULD` is a strong recommendation with rare exceptions; `MAY` is optional. The security is
  usually in the `MUST`s ([J08](../track-j/J08-mcp-and-oauth-21.md)).
- **The Security Considerations section** is where the attacks and mitigations live — read it first
  when evaluating whether you're using a spec safely.
- **BCPs (Best Current Practice)** like [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) distil
  years of vulnerabilities into requirements — often more useful than the original spec, because
  they encode what went wrong.
- **Drafts** ([datatracker.ietf.org](https://datatracker.ietf.org/)) are where the field is heading
  — OAuth 2.1, MCP, and browser-based-apps guidance are all drafts you should track.

---

## Staying current: what's actually moving

The evergreen fundamentals ([Track B](../track-b/B01-bits-bytes-text-as-numbers.md), five layers)
won't change. These *are* moving, and are worth watching ([README](../../README.md) dated them):

| Area | Status (2026) | Watch |
|---|---|---|
| **Passkeys** | Mainstream; WebAuthn L3 (Related Origins, Signal API) | [passkeys.dev](https://passkeys.dev/), [W3C WebAuthn](https://www.w3.org/TR/webauthn-3/) |
| **OAuth 2.1** | Stable draft, not yet an RFC | [datatracker](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) |
| **Agent / MCP auth** | Fast-moving frontier | [MCP spec](https://modelcontextprotocol.io/specification/), the [ext-auth repo](https://github.com/modelcontextprotocol/ext-auth) |
| **Sender-constrained tokens** | DPoP RFC published; adoption growing | [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) |
| **Certificate lifetimes** | Shrinking to 47 days by 2029 | [CA/Browser Forum](https://cabforum.org/) |
| **Post-quantum** | Migration beginning | (out of scope here — a dated blog post is the right medium) |

How to keep up without drowning: **follow the working groups, not the hype.** The IETF OAuth WG, the
W3C WebAuthn WG, the OpenID Foundation, and the FIDO Alliance are where the real changes happen.
Aaron Parecki (oauth.net), the OWASP cheat sheets, and the primary-source authors above are reliable
signal.

---

## The honest note on getting it wrong

The book's uncomfortable truth ([README](../../README.md)): **auth content that is subtly wrong
causes breaches in other people's products.** Tracks A–E most people can write correctly from
experience; Tracks F, G, H, and J are where subtle errors hide, and where a mistake in *your* code
harms *your users*.

So, three habits for the rest of your career:

1. **Anchor to primary sources.** When it matters, read the RFC, the NIST publication, the W3C rec —
   not a summary. This book anchored every normative claim to one; do the same in your own work.
2. **Get the F/G/H/J work reviewed.** For anything high-stakes in delegation, federation,
   authorization, or machine/agent identity, budget for expert review before shipping
   ([C05](../track-c/C05-build-vs-buy.md), [I07](../track-i/I07-testing-auth.md)). Name the reviewer;
   it does more for credibility than any amount of polish.
3. **Test the failure modes.** Turn the failure-mode chapters into a regression suite
   ([I07](../track-i/I07-testing-auth.md)) and run it on every change. The attacks don't go stale.

---

## What was deliberately left out

So you know the edges of what you've learned ([appendix/excluded.md](../../appendix/excluded.md)):
cryptographic *implementation* (you learned what AES does, never how to build it — "don't roll your
own crypto," taught by not teaching it); post-quantum migration (real, moving too fast for
evergreen material); DIDs and verifiable credentials (a separate curriculum); vendor-specific
configuration (rots in months); and network-layer security below TLS. If you meet these, you're at a
different edge of the graph — go learn them from *their* primary sources.

---

## The end, and the beginning

You started not knowing what a byte was. You can now build a login you won't regret, keep someone
logged in safely, let one app act for a user on another, accept another system's authentication,
decide what a known user may do, run all of it in production, and authenticate machines and AI
agents — and you can *break* every one of those, which is how you know you understand it.

More than any specific technique, you have the **map** ([C01](../track-c/C01-auth-is-five-different-problems.md)):
five separable problems, a small set of cryptographic primitives, and the judgement to know which
tool each situation needs ([K05](K05-the-decision-tree.md)). New specs will come — post-quantum,
whatever succeeds MCP, standards not yet drafted. They'll attach to the graph you now hold, and
you'll read them as arrangements of primitives you already understand.

That's the whole of it. Auth, from zero to pro.

Go build something, and break it before someone else does.

---

## What to remember

1. **Auth is a small set of primitives, arranged into five layers, over and over.** New developments
   attach to the graph you now hold.
2. **Two books carry disproportionate weight:** *Solving Identity Management in Modern Applications*
   (the five-layer spine) and *API Security in Action* (the technical reference).
3. **Read the spec, not the summary, when it matters** — and read the Security Considerations first.
   The security is in the `MUST`s.
4. **Watch the working groups, not the hype** — IETF OAuth, W3C WebAuthn, OpenID Foundation, FIDO.
5. **The fundamentals are evergreen; passkeys, OAuth 2.1, and agent/MCP auth are what's moving.**
6. **F/G/H/J is where subtle errors hide** — anchor to primary sources, get it reviewed, run the
   failure-mode regression suite.
7. **You have the map.** That's what makes you a pro — not any single technique.

---

## Sources

- [SOURCES.md](../../SOURCES.md) — the full reading list by track
- [appendix/rfc-index.md](../../appendix/rfc-index.md) — every spec, what it's for
- [appendix/excluded.md](../../appendix/excluded.md) — the boundary of scope
- Everything cited throughout this book — anchored to primary sources, on purpose

---

*Auth, from Zero to Pro — complete. 143 chapters, eleven tracks, one running application, built and
broken end to end.*

**Back to:** [the table of contents](../../README.md) · [the glossary](../../GLOSSARY.md) · [the decision tree](../../appendix/decision-tree.md)
