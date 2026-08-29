# A10 — Where secrets live: env vars, and never in your frontend bundle

**Part A · How the web actually works** · *Builds on [A07](A07-client-vs-server.md)*
---

## Why it matters

A team ships a Next.js app. Someone needs the Stripe secret key on a page, gets an
"undefined" error, sees the framework docs mention `NEXT_PUBLIC_`, adds the prefix, and
the error goes away.

```js
// .env
NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51H8xK2...
```

It works. It ships. Nothing warns them — not the compiler, not the linter, not the
framework, not code review, because the line *looks* like configuration.

Eleven minutes after the deploy, a bot that watches JavaScript bundles for the string
`sk_live_` finds it. GitHub's secret scanning would have caught it in a repo; this was in
a compiled asset served from a CDN.

The prefix means **"inline this string into the browser bundle."** That is documented,
intentional behaviour. The word "environment variable" made it feel server-side. It was
never server-side.

---

## What a secret is

> **A secret is a value whose security depends entirely on nobody else having it.**

That definition has a useful corollary: the moment you cannot enumerate everyone who has
a copy, it is no longer a secret. Not "probably compromised" — *not a secret*, as a matter
of definition.

Things that are secrets: password hashing peppers, signing keys, database passwords, API
keys for services you pay for, OAuth client secrets, webhook signing secrets, encryption
keys.

Things people mistake for secrets: your OAuth **client ID** (public by design), your
database *hostname* (obscurity, not secrecy), your API's URL, a JWT's *public* key, a user
ID.

The confusion costs real effort. Teams put client IDs in vaults and secret keys in
bundles, which is exactly backwards.

---

## The one question

For every value in your configuration:

> **Does this value need to be present on a machine an attacker controls?**

- **No** → it is a server secret. It goes in a secret manager, injected as an environment
  variable, never in git.
- **Yes** → **it is not a secret.** Whatever you were relying on, stop. Redesign so no
  secret is needed there.

There is no third branch. There is no "secret, but obfuscated." There is no "secret, but
only in the mobile app." [A07](A07-client-vs-server.md) is the proof.

---

## Where server secrets go, worst to best

### ❌ Hardcoded in source

```python
STRIPE_KEY = "sk_live_51H8xK2..."
```

In git forever, even after you delete it — `git log -p` finds it, and so do the dozens of
bots that clone public repos continuously. Visible to every contributor, every CI job,
every laptop backup, every fork.

If this has happened: **rotate the key first, then clean the history.** In that order.
Removing it from history without rotating accomplishes nothing; the clones already exist.

### ❌ In a committed config file

`config.json`, `settings.py`, `application.yml` with real values. Same problem, with a
thin layer of feeling organised.

### ⚠️ In a `.env` file

```bash
# .env  — and .gitignore MUST contain .env
DATABASE_URL=postgres://user:pass@localhost/db
SESSION_SECRET=8f14e45fceea167a5a36dedd4bea2543
```

Fine for local development. **Not fine for production**, because:

- One `git add -A` and it is in history. (Add `.env` to `.gitignore` *before* creating it.)
- It sits in plaintext on disk on every machine that runs the app.
- No rotation story, no audit trail, no access control.
- It gets copied — into Slack, into a ticket, onto a new laptop. **Secret sprawl.**

Commit a `.env.example` with the *keys* and dummy values, so the shape is documented and
the values are not.

### ✅ Environment variables, injected at runtime

```bash
export SESSION_SECRET="$(vault kv get -field=session_secret secret/app)"
./server
```

An **environment variable** is a named value handed to a process by whatever started it.
Never on disk in your repo; supplied by the platform.

This is the baseline for production, and it is what "12-factor config" means. Caveats
worth knowing:

- Environment variables are visible to the process **and its children**. Any subprocess
  you spawn inherits them.
- On Linux, `/proc/<pid>/environ` exposes them to anything running as the same user or
  root.
- They frequently leak into **crash dumps, error trackers, and debug endpoints**. A stack
  trace page that prints the environment is a full credential dump. Disable debug modes in
  production, and configure your error tracker's scrubbing rules.

### ✅✅ A secret manager, with short-lived credentials

AWS Secrets Manager, GCP Secret Manager, HashiCorp Vault, Azure Key Vault, or your
platform's built-in store. The app authenticates using its *workload identity* — the fact
of running where it runs — and fetches secrets at start-up.

You get versioning, rotation, access control, audit logs, and no long-lived credential on
disk anywhere. [I05](../track-i/I05-secrets-management.md) is the full chapter.

### ✅✅✅ A key management service, where the secret never leaves

For signing and encryption keys specifically, the best answer is that your application
**never holds the key at all**. You send data to a KMS or HSM and it returns a signature.
The private key has no exportable form.

An attacker with full application compromise can *use* the key while they are inside — and
that use is logged, rate-limitable, and revocable. They cannot *take* it. That difference
turns a permanent catastrophe into a bounded incident.
([I05](../track-i/I05-secrets-management.md), [I10](../track-i/I10-incident-response.md).)

---

## The audit: find the secrets already in your bundle

Do this now, on your actual project. It takes two minutes and finds things surprisingly
often.

```bash
# 1. Build production assets, then grep the output for the obvious prefixes.
npm run build
grep -rIn -E 'sk_live_|sk_test_|AKIA[0-9A-Z]{16}|ghp_|gho_|xox[baprs]-|-----BEGIN [A-Z ]*PRIVATE KEY-----' dist/ build/ .next/ 2>/dev/null

# 2. Any "public" env var whose name suggests a secret.
grep -rIn -E '(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z_]*(SECRET|KEY|TOKEN|PASSWORD|PRIVATE)' . \
  --exclude-dir=node_modules --exclude-dir=.git

# 3. High-entropy strings in shipped JS (crude, but it finds things).
grep -rIoE '[A-Za-z0-9+/]{40,}={0,2}' dist/ 2>/dev/null | sort -u | head -50

# 4. What is actually in your git history.
git log --all -p -- '*.env' '*.pem' '*.key' 2>/dev/null | head -50
```

Then wire the real tools in, so it is not a one-off:

- **[gitleaks](https://github.com/gitleaks/gitleaks)** or
  **[trufflehog](https://github.com/trufflesecurity/trufflehog)** as a pre-commit hook and
  a CI step. Scan history, not just the diff.
- **GitHub secret scanning + push protection.** Free on public repos. It blocks the push.
  This is why key prefixes like `sk_live_` exist at all
  ([J02](../track-j/J02-api-keys.md)) — a recognisable prefix is what makes automated
  detection possible. Design your own keys with one.

---

## The three-question test for any client-side key

When someone says "but I need this key in the frontend":

**1. Is it *meant* to be public?** Some are. A Stripe **publishable** key (`pk_live_`),
a Google Maps browser key, a PostHog project key, an OAuth **client ID**. These are
designed to be public and are protected by origin restrictions and server-side limits, not
by secrecy. Fine — but confirm it in the vendor's docs, do not assume from the name.

**2. Can the operation move to your server?** Almost always yes. The browser calls *your*
endpoint; your server holds the key and calls the third party. You get to add
authorization, rate limiting, and audit logging while you are there. This is the same
reasoning that produces the backend-for-frontend pattern
([F17](../track-f/F17-oauth-for-spas-and-bff.md)).

**3. If neither, what is the blast radius?** Sometimes there is genuinely no server (a
static site, a CLI tool). Then: use the most restricted key the vendor offers, bind it to
your domain, set a spend cap, alert on anomalies, and **plan for it to leak**. Write down
what happens when it does.

---

## Things that are not secrets, and stop treating them as such

| Value | Why it is public |
|---|---|
| OAuth **client ID** | Sent in every authorization URL, in the address bar |
| A JWT **public** key / JWKS | Published at a `.well-known` URL on purpose ([E07](../track-e/E07-jose-family.md)) |
| Your API base URL | In every request the browser makes |
| A user's ID | In the UI, in URLs. Security must not depend on it being unguessable ([H14](../track-h/H14-attack-your-own-authorization.md)) |
| Your database schema | Obscurity, not security |
| A password **hash** | Not a secret in the cryptographic sense — but still treat as sensitive; it enables offline cracking ([B07](../track-b/B07-fast-hashes-wrong-for-passwords.md)) |

---

## Terms defined in this chapter

`environment variable`, `bundle`, `secret`

---

## What to remember

1. A secret is a value whose security depends on nobody else having it. If you cannot
   list the holders, it is not one.
2. **`NEXT_PUBLIC_` / `VITE_` / `REACT_APP_` means "put this in the browser."** By design.
   Go grep your build output today.
3. Ladder: hardcoded ❌ → committed config ❌ → `.env` ⚠️ → env vars ✅ → secret manager
   ✅✅ → KMS where the key never leaves ✅✅✅.
4. Leaked key: **rotate first, clean history second.** Reversing that order accomplishes
   nothing.
5. If a key must be in a client, either it was never secret, or you need to redesign so
   the operation happens server-side.
6. Client IDs and public keys are *supposed* to be public. Do not waste protection on
   them.

---

## Sources

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [The Twelve-Factor App — III. Config](https://12factor.net/config)
- [GitHub: About secret scanning](https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning)
- [Next.js docs: Environment Variables — bundling for the browser](https://nextjs.org/docs/app/guides/environment-variables)

---

**Next:** [A11 — Same-origin policy and CORS, explained without the panic](A11-same-origin-and-cors.md)
