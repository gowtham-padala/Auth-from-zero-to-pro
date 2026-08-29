# I08 — Observability for auth: what to log, and what never to log

**Part I · Identity lifecycle & operations** · *Builds on [H13](../track-h/H13-audit-logging.md)*
---

## Why it matters

A team enables verbose request logging to debug an auth issue. It works — they find the bug. The
logs also, from that day forward, capture every request header:

```
2026-08-28 14:03 INFO GET /api/me
  headers: {Authorization: "Bearer eyJhbGci...", Cookie: "session=8f14e45f..."}
```

Those logs flow to a log aggregator that the whole engineering team can search, that's retained
for a year, and that's backed up to a bucket. **Every live session token and access token in
the system is now sitting in plaintext, searchable, in a place far less protected than the auth
system that issued them.** A leak of the *logs* is now a leak of every user's credentials — and
the logs are a much softer target than the auth database.

Logging is necessary for security ([I09](I09-detecting-account-takeover.md),
[I10](I10-incident-response.md)). Logging *the wrong things* turns your observability stack into
a credential store. The skill is logging enough to investigate, and never the secrets themselves.

---

## The two questions

Auth observability has two halves, and they pull in opposite directions:

```
   WHAT TO LOG        — enough to detect attacks and investigate incidents
   WHAT NEVER TO LOG  — nothing that is itself a credential or sensitive
```

The tension: the values most useful for correlating an investigation (the session ID, the token)
are exactly the values that must never be logged, because logging them makes them exploitable.
The resolution — log a *hash* of the identifier, never the identifier itself.

---

## What NEVER to log

The list, because it is violated constantly and the violation is invisible until a log leak:

```
   ❌ Passwords (login, change, reset — any field named *password*)
   ❌ Session IDs / session tokens        → log SHA-256(session_id) for correlation
   ❌ Access tokens, refresh tokens, ID tokens
   ❌ Full Authorization headers          → the #1 accidental leak
   ❌ Cookies (they contain the session)
   ❌ API keys, client secrets            J02
   ❌ Password reset / magic links / MFA codes / recovery codes   D09/D10/D13
   ❌ Full PII beyond what you need       → log user_id, not the whole profile   I11
   ❌ Private keys, TOTP secrets          B08/D12
```

Two of these are the ones teams actually leak:

**Full `Authorization` headers.** "Log the request for debugging" serialises the header, and now
`Bearer <live-token>` is in the log. This is the opening example, and it is the single most
common credential leak into logs.

**Session IDs.** People log them "to trace a user's requests" — which is a real need, solved
correctly by logging `hash(session_id)`: you get a stable correlation key across log lines
*without* the actual credential ([B05](../track-b/B05-hashing-vs-encryption.md)).

```python
# ❌ leaks the credential
log.info("request", session_id=session_id, auth=request.headers["Authorization"])

# ✅ correlation without exposure
log.info("request",
         session_ref=sha256(session_id)[:16],       # stable, non-reversible key
         user_id=user_id,                            # an identifier, not a secret
         auth_scheme=request.headers["Authorization"].split()[0])   # "Bearer", not the token
```

---

## Redaction must be structural, not hopeful

You cannot rely on developers remembering not to log secrets on every log line
([I07](../track-i/I07-testing-auth.md)'s "everyone skips it" applies here). Make redaction a
property of the logging infrastructure:

```python
REDACT_KEYS = {"password", "token", "authorization", "cookie", "secret",
               "access_token", "refresh_token", "api_key", "code", "otp"}

def redact(obj):
    if isinstance(obj, dict):
        return {k: ("***REDACTED***" if k.lower() in REDACT_KEYS else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, str) and looks_like_a_token(obj):    # jwt pattern, sk_live_, etc.
        return "***REDACTED***"
    ...

logger.add_processor(redact)     # applied to EVERY log line, automatically
```

Belt and braces:

- **A redaction processor** in the logging pipeline (above) — catches known-sensitive keys and
  token-shaped values everywhere.
- **The same list applied at the error tracker and APM** — these serialise requests too, and are
  a common leak path ([A10](../track-a/A10-where-secrets-live.md)).
- **A CI check** that greps for logging of forbidden fields, so a new `log.info(password=...)`
  fails the build ([I07](../track-i/I07-testing-auth.md)).

Structural redaction is the only kind that holds. "We're careful" leaks eventually.

---

## What TO log — the security signal

The purpose of auth logging is detection and forensics ([I09](I09-detecting-account-takeover.md),
[I10](I10-incident-response.md)). Log the *events*, with *identifiers* (not secrets):

```
   Authentication
     ☐ login success / FAILURE (failures are the attack signal)   D08
     ☐ MFA challenge / success / failure                          D12
     ☐ password change / reset requested / completed              D09
     ☐ new device / new location login                            I09
   Authorization
     ☐ authorization DENIALS (bursts = an attack)                 H13/H14
     ☐ privileged actions, impersonation                          I04
   Lifecycle
     ☐ account created / disabled / deprovisioned                 I03
     ☐ role / permission granted or revoked                       H13
   Tokens & keys
     ☐ refresh-token reuse detected (compromise signal)           E10
     ☐ token validation failures (alg:none attempts, bad aud)     E06/F08
     ☐ key rotation events                                        I06
```

For each, log: **who** (user_id), **what** (the event), **when** (precise UTC), **where** (IP,
approximate location, device), **result**, and a **request/correlation ID** to tie related lines
together. This overlaps the audit log ([H13](../track-h/H13-audit-logging.md)) — the audit log is
the *authoritative, tamper-evident, retained* record for accountability; operational logs are the
*searchable, high-volume* stream for detection and debugging. Keep both; keep secrets out of
both.

---

## Failures are the signal

The single most valuable thing to log well is **failure and denial**:

- **Failed logins** ([D08](../track-d/D08-rate-limiting-and-stuffing.md)) — a spike, especially
  across many accounts (spraying) or from one source (stuffing), is an attack in progress.
- **Authorization denials** ([H14](../track-h/H14-attack-your-own-authorization.md)) — a user
  probing many object IDs and getting 403s is attempting IDOR.
- **Token validation failures** ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) —
  `alg:none` attempts and bad-audience tokens are attackers testing your validation.
- **Refresh-token reuse** ([E10](../track-e/E10-token-lifetimes-and-rotation.md)) — a
  near-certain compromise signal.

A system that logs only *successes* sees only the attacks that *worked* — by which point it's an
incident, not a detection. The failures are the early warning, and they feed directly into
takeover detection ([I09](I09-detecting-account-takeover.md)) and alerting.

---

## Alerting, metrics, and traces

Observability is more than logs ([three pillars](https://opentelemetry.io/)):

- **Metrics** — login success rate, MFA adoption, denial rate, token-validation-failure rate.
  Auth *health* as dashboards. A sudden drop in login success rate is an outage
  ([I06](I06-key-rotation.md)'s bad rotation) or an attack.
- **Traces** — follow one authenticated request across services ([H12](../track-h/H12-authz-in-microservices.md)),
  carrying the correlation ID (never the token).
- **Alerts** — the failures above, wired to page a human: a failed-login spike, refresh reuse, a
  burst of denials, a spike in `alg:none` attempts.

The goal is that an attack ([I09](I09-detecting-account-takeover.md)) or an outage
([I06](I06-key-rotation.md)) is *visible* — in a dashboard, in an alert — not discovered weeks
later in a breach report.

---

## The privacy dimension

Auth logs contain IPs, locations, and behavioural data — that is **personal data**
([I11](I11-compliance.md)). Observability trades off against privacy:

- **Log the minimum that serves detection** ([I11](I11-compliance.md)'s data minimisation) — you
  need the IP for anomaly detection, not the user's precise GPS.
- **Retention limits** — security logs are retained for investigation, but *bounded* by policy,
  not forever.
- **Access-control the logs** — who can search auth logs is itself a sensitive permission
  ([H13](../track-h/H13-audit-logging.md)); an over-broad log-search grant is how an insider
  reads everyone's activity.

The logs are a security asset *and* a privacy liability. Protect them like the sensitive data
they contain — which brings the chapter full circle: the same care that keeps credentials *out*
of logs must keep the logs themselves *controlled*.

---

## Terms defined in this chapter

`observability`, `redaction`

---

## What to remember

1. **Logging the wrong things turns observability into a credential store** — a log leak becomes
   a credential leak, and logs are a softer target than your auth DB.
2. **Never log:** passwords, session IDs, tokens, full `Authorization` headers, cookies, secrets,
   reset links, MFA/recovery codes. **Log `hash(session_id)`** for correlation instead.
3. **Full `Authorization` headers and session IDs are the two most common accidental leaks.**
4. **Redaction must be structural** — a pipeline processor, applied everywhere, plus the error
   tracker and a CI check. "We're careful" leaks.
5. **Log the events and identifiers, not the secrets:** who / what / when / where / result /
   correlation ID.
6. **Log failures and denials** — a system that logs only successes sees only the attacks that
   worked.
7. **Metrics, traces, and alerts** make attacks and outages *visible* — not found in a later
   breach report.
8. **Auth logs are personal data** — minimise, bound retention, and access-control who can search
   them.

---

## Sources

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) — including what not to log
- [OWASP Top 10 — A09: Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [OpenTelemetry](https://opentelemetry.io/docs/) — metrics, traces, logs

---

**Next:** [I09 — Detecting account takeover: signals and risk scoring](I09-detecting-account-takeover.md)
