# D07 — User enumeration: how your error messages leak your user list

**Part D · Authentication** · *Builds on [D06](D06-build-login-part-2-login.md)*
---

## The attack

Fifteen lines. Point it at almost any application and it will produce a list.

```python
import requests, statistics, time

CANDIDATES = open("emails.txt").read().split()
found = []

for email in CANDIDATES:
    r = requests.post("https://app.example.com/login",
                      data={"email": email, "password": "definitely-wrong"})

    if "No account found" not in r.text:      # or: status, length, timing, redirect
        found.append(email)

print(f"{len(found)} of {len(CANDIDATES)} addresses are registered")
```

That is the whole attack. No exploit, no payload, no cleverness. It reads the difference
between two responses your application deliberately produced.

**Why it matters**, in ascending order of severity:

1. **Targeting.** Credential stuffing against confirmed accounts is far more efficient than
   against a guess list ([D08](D08-rate-limiting-and-stuffing.md)).
2. **Spear-phishing.** "You have an account with us" is a credible opening.
3. **The membership itself is the harm.** For a dating site, a medical service, a support
   group, a political organisation, an addiction service, or a whistleblowing platform,
   *"this person has an account"* is the sensitive fact. There is no data breach required.

That third category is why this is not a "low severity, informational" finding, whatever
your scanner says. For some products it is the whole threat model.

---

## Every channel that leaks

Fixing the error message is the first step of about seven. Here is the complete list.

### 1. Different messages

```
"No account found with that email"     vs.  "Incorrect password"
```

The obvious one. **Fix:** one message for every failure.

### 2. Different status codes

```
404 for unknown user, 401 for wrong password
```

Invisible in the UI, trivially visible to a script. **Fix:** `401` for both.

### 3. Different response length

Even with identical messages, a difference of a few bytes — a hidden field, a different
template branch, a `Set-Cookie` on one path — is measurable.

**Fix:** render the same template with the same data.

### 4. Different timing

The big one, and the one that survives every message fix.

```
Unknown user:  find_user() → None → return          ~2 ms
Known user:    find_user() → verify() → Argon2id    ~300 ms
```

**150× difference.** No statistics required — you can see it in a browser's network tab.

**Fix:** verify a dummy hash for unknown users
([D06](D06-build-login-part-2-login.md), [B16](../track-b/B16-timing-attacks.md)).

### 5. Different redirect behaviour

```
Known user + wrong password → 200, form redisplayed
Unknown user                → 302 to /register?email=...
```

Well-intentioned UX, complete disclosure.

### 6. Registration

```
"That email is already registered."
```

The mirror image of the login leak, and often forgotten because the fix in
[D05](D05-build-login-part-1-registration.md) feels counterintuitive.

**Fix:** identical response either way; email the real owner.

### 7. Password reset

```
"We've sent a reset link to alice@example.com"     ← account exists
"No account found with that email"                 ← it does not
```

**Fix:** *"If an account exists for that address, we've sent a link."* Every time. And send
nothing on the negative branch — but keep the **timing** uniform, which means doing the
email dispatch asynchronously so both paths return at the same speed.

### 8. Rate limit and lockout behaviour

```
5 attempts on a real account   → "Account temporarily locked"
5 attempts on a fake account   → still "Invalid credentials"
```

Your *defence* became the oracle. **Fix:** rate limit unknown accounts identically — track
attempts by the submitted email whether or not it resolves.

### 9. MFA prompts

```
Correct password → "Enter your 2FA code"     ← account exists AND has 2FA
Wrong password   → "Invalid credentials"
```

Harder to avoid, because the flow genuinely differs. Mitigation: this only leaks after a
*correct* password, so the attacker already has the credential — the enumeration is no
longer the main problem. Accept it.

### 10. Side channels nobody checks

- **`Set-Cookie` on one branch only** — a pending-MFA cookie appears for real users.
- **Email delivery itself.** An attacker who controls a catch-all domain sees which
  addresses receive mail.
- **Password strength feedback on registration** — some implementations check the email
  against a breach corpus and behave differently.
- **SSO / home realm discovery** — "this domain uses SSO" reveals the tenant exists
  ([G10](../track-g/G10-home-realm-discovery.md)).
- **GraphQL introspection or a `users` query** returning different errors for missing vs
  forbidden.
- **Profile URLs.** `/u/alice` returning `404` vs `403`
  ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)).

---

## Test your own

```python
import requests, time, statistics

URL = "https://app.example.com/login"
KNOWN   = "your-real-test-account@example.com"
UNKNOWN = "definitely-not-registered-9f2a@example.com"

def probe(email, n=30):
    lengths, times, statuses = [], [], []
    for _ in range(n):
        t0 = time.perf_counter()
        r = requests.post(URL, data={"email": email, "password": "wrong-9f2a"},
                          allow_redirects=False)
        times.append(time.perf_counter() - t0)
        lengths.append(len(r.content))
        statuses.append(r.status_code)
    return {
        "status":  set(statuses),
        "length":  set(lengths),
        "median_ms": round(statistics.median(times) * 1000, 1),
        "min_ms":    round(min(times) * 1000, 1),      # least-perturbed sample
    }

k, u = probe(KNOWN), probe(UNKNOWN)
print("known  :", k)
print("unknown:", u)

for field in ("status", "length"):
    if k[field] != u[field]:
        print(f"❌ LEAK via {field}: {k[field]} vs {u[field]}")

if abs(k["min_ms"] - u["min_ms"]) > 20:
    print(f"❌ LEAK via timing: {k['min_ms']} ms vs {u['min_ms']} ms")
```

Run it against login, registration, password reset, and email change. Four endpoints,
four minutes. Most applications fail at least one.

---

## The fix, in general

> **Every response an unauthenticated user can trigger must be identical in message, status
> code, byte length, and timing — regardless of whether the account exists.**

Concretely:

```python
GENERIC = "The email or password is incorrect."

def login():
    user = find_user(canonicalize(email))

    # 1. Constant work
    try:
        ph.verify(user.password_hash if user else DUMMY_HASH, password)
        ok = user is not None
    except VerifyMismatchError:
        ok = False

    # 2. Rate limiting keyed on the SUBMITTED email, real or not
    record_attempt(canonicalize(email), client_ip())

    if not ok:
        # 3. Same message, same status, same template
        return render("login.html", error=GENERIC), 401
    ...
```

```python
def request_password_reset():
    user = find_user(canonicalize(email))
    if user:
        enqueue_reset_email(user)        # async — do not block the response
    # 4. Identical response, identical timing
    return render("reset-sent.html",
                  message="If an account exists for that address, "
                          "we've sent a password reset link."), 200
```

The `enqueue_` matters. If you send the mail synchronously, the "account exists" path takes
200 ms longer than the other and you have reintroduced the leak at step 4 after fixing it
at step 3.

---

## When you cannot fully close it

Some products genuinely cannot. Be honest about the trade-off rather than pretending.

**Public profiles.** If `/u/alice` exists and is public, usernames are enumerable by design.
That is fine — the leak is only meaningful if membership is meant to be private.

**Invitation flows.** "This user is already a member of your team" is useful and reveals
membership *within a tenant*, which is usually acceptable.

**Enterprise SSO.** Home realm discovery must route by email domain
([G10](../track-g/G10-home-realm-discovery.md)), which reveals that the domain is
configured. Mitigate by revealing *domain* configuration, not *user* existence.

**When you accept a leak, compensate:**

- Aggressive rate limiting on the enumerable endpoint.
- Alerting when one source probes many identifiers.
- CAPTCHA after a threshold.
- **Assume the user list is public** and make the credentials strong enough that it does not
  matter — passkeys ([D14](D14-webauthn-and-passkeys-concepts.md)), breach blocklists
  ([D04](D04-password-policies.md)), MFA.

That last point is the mature position. Enumeration resistance is defence in depth
([C04](../track-c/C04-threat-modeling.md)), not a load-bearing control. A system whose
security depends on nobody knowing the usernames is a system with one control.

---

## The user experience objection

*"But users get confused when we do not tell them the account does not exist."*

Real, and manageable:

- **Send email on both branches.** *"Someone tried to log in to an account with this
  address, but no account exists — did you mean to register?"* The right person gets the
  right information, on a channel they control. And it is a takeover warning.
- **Offer both actions on the failure page.** "Forgot password?" and "Create an account?"
  side by side. The user picks; you disclose nothing.
- **Be specific after authentication.** Once the password is correct, you may say "your
  email is not verified." The attacker who gets that far already has the credential.

The conversion cost is small. The alternative is publishing your user list.

---

## Terms defined in this chapter

`user enumeration`, `response oracle`

---

## What to remember

1. Enumeration leaks through **message, status, length, timing, redirects, cookies, and
   emails**. Fixing the message is one of seven.
2. **Timing is the leak that survives every other fix.** Hash a dummy.
3. Registration and password reset leak just as loudly as login. Fix all three.
4. **Your rate limiter can be the oracle.** Track attempts on unknown accounts too.
5. Send the specific information **by email**, to the address in question.
6. Send reset emails **asynchronously**, or the timing leaks again.
7. Where you cannot close it, compensate — and never let it be a load-bearing control.

---

## Sources

- [OWASP Web Security Testing Guide — Testing for Account Enumeration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account)
- [OWASP Authentication Cheat Sheet — Authentication and Error Messages](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-and-error-messages)
- [The Copenhagen Book — Password authentication](https://thecopenhagenbook.com/password-authentication)

---

**Next:** [D08 — Rate limiting, lockout, and credential stuffing defense](D08-rate-limiting-and-stuffing.md)
