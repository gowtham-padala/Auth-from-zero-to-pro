# I12 — Migrating auth: rehashing passwords, cutting over, not logging everyone out

**Part I · Identity lifecycle & operations** · *Builds on [D03](../track-d/D03-how-to-store-passwords.md), [E03](../track-e/E03-build-server-side-sessions.md)*
> The episode nobody makes and everybody needs. Rehash-on-login is the technique, and it isn't
> obvious.

---

## The password problem: you can't re-hash

The central obstacle: **you cannot convert existing password hashes to a new algorithm, because
hashing is one-way** ([B05](../track-b/B05-hashing-vs-encryption.md)). You have
`MD5(password)`; you want `Argon2id(password)`; but you don't have `password` — only the user
does, and only when they type it.

So the naive options are both bad:

- **Force everyone to reset** → the churn event above.
- **Keep the old weak hashes forever** → you never actually migrate; MD5 hashes linger for years
  ([B06](../track-b/B06-collisions.md)).

The technique that avoids both: **rehash on login.**

---

## Rehash on login — the technique

> **Upgrade each password hash to the new algorithm the next time that user logs in — the one
> moment you hold the plaintext.**

```python
def login(email, password):
    user = find_user(email)
    stored = user.password_hash

    if stored.startswith("$argon2id$"):
        # Already migrated — verify normally. D03.
        if not argon2.verify(stored, password):
            return fail()

    elif stored.startswith("$2b$"):                    # bcrypt — verify, then upgrade
        if not bcrypt.verify(stored, password):
            return fail()
        user.password_hash = argon2.hash(password)     # ← rehash NOW, while we have plaintext
        db.save(user)

    else:                                              # legacy MD5/SHA1
        if not legacy_verify(stored, password):
            return fail()
        user.password_hash = argon2.hash(password)     # ← upgrade the weak hash
        db.save(user)

    return success()
```

Every successful login silently upgrades that user's hash. Over time, as users log in naturally,
the population migrates itself — **no forced resets, no user friction, invisible.** This is the
same `check_needs_rehash` pattern from [D03](../track-d/D03-how-to-store-passwords.md), applied as
a migration strategy.

The two refinements that make it complete:

**Wrap the weak hashes immediately, don't wait for login.** Rehash-on-login upgrades *active*
users, but dormant accounts keep their MD5 hashes indefinitely — a standing risk
([B06](../track-b/B06-collisions.md)). So, in a batch job *today*, wrap every legacy hash inside a
strong one ([D03](../track-d/D03-how-to-store-passwords.md)):

```python
# Batch, over the whole table, immediately:
new_hash = argon2.hash(base64(bytes.fromhex(old_md5_hash)))   # Argon2id OVER the MD5 digest
# Now the weak hash is gone from the DB. On login: MD5 the password first,
# then verify against the Argon2id wrapper — and opportunistically replace
# with a direct Argon2id hash.
```

This converts "we have MD5 hashes lying around" from *catastrophic* to *contained* in one batch
job, while rehash-on-login handles the clean upgrade. It's what breached companies wish they'd
done ([B08](../track-b/B08-salts-peppers-slow-hashes.md)).

**Set a deadline for the stragglers.** After N months, accounts still on legacy hashes get a
forced reset and the legacy hash is deleted. You don't carry weak hashes forever for the sake of a
few dormant accounts.

---

## Migrating to a *provider* (not just an algorithm)

If you're moving to an auth provider ([C05](../track-c/C05-build-vs-buy.md)), the rehash-on-login
idea generalises to **lazy migration**:

```
   Provider supports importing hashes?
   │
   ├── YES ──> Bulk-import your (bcrypt/Argon2id) hashes. Users log in
   │           against the provider transparently.  ← ask BEFORE you sign!  C05
   │
   └── NO ───> LAZY MIGRATION:
               1. Keep your old system as a fallback.
               2. On login, try the provider first.
               3. If the user isn't there yet, verify against YOUR old system,
                  then CREATE them in the provider with the plaintext you just
                  received.  ← same "we hold the plaintext at login" trick.
               4. Over time, everyone migrates on their next login.
```

This is why [C05](../track-c/C05-build-vs-buy.md) insists on asking **"can I export/import
password hashes?"** *before* signing with a provider — the answer decides whether migration *in*
or *out* is a clean bulk import or a lazy, months-long login-driven process. A provider that can't
import your hashes forces mass resets on the way in; one that can't *export* traps you on the way
out.

---

## Don't log everyone out: session migration

The password migration is half of it. The other half is **not invalidating everyone's session**
on cutover. If the new system doesn't recognise old sessions, everyone is logged out — friction,
support load, churn.

Approaches ([E03](../track-e/E03-build-server-side-sessions.md), [E09](../track-e/E09-should-you-use-jwts-for-sessions.md)):

- **If both use server-side sessions** ([E03](../track-e/E03-build-server-side-sessions.md)):
  migrate the session store, or run both and check both during the overlap. Sessions keep working.
- **If migrating token formats** ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)): accept
  *both* old and new formats during a transition window, then drop the old — the same overlap
  principle as key rotation ([I06](I06-key-rotation.md)). New logins get the new format; existing
  sessions ride out their lifetime.
- **Worst case, if you must invalidate:** do it *gradually* (as sessions naturally expire) rather
  than all at once, and communicate it.

The recurring pattern across this whole chapter — and [I06](I06-key-rotation.md) — is **overlap:
run old and new simultaneously, migrate gradually, then retire the old.** Big-bang cutovers are
what cause mass logout; overlapping transitions are what make migration invisible.

---

## The safe migration playbook

Putting it together:

```
   1. STAND UP the new system alongside the old (don't replace yet).
   2. SHADOW / dual-run where possible — write to both, compare.
   3. BULK-import what you can (hashes if the provider allows; sessions).
   4. LAZY-migrate the rest on login (rehash-on-login / provider-create-on-login).
   5. WRAP weak legacy hashes immediately in a batch job (contain the risk).  D03
   6. ACCEPT both old and new (hashes, session/token formats) during overlap.  I06
   7. MONITOR the migration — % migrated, error rates, login success.  I08
   8. DEADLINE the stragglers — forced reset + delete legacy after N months.
   9. RETIRE the old system only when the population has moved.
   10. Have a ROLLBACK plan at every step.  ← never a one-way door
```

Two non-negotiables: **monitor** ([I08](I08-observability.md)) so you can see the migration
progressing and catch a spike in login failures (a broken verification path affects *everyone*),
and keep a **rollback** at every step, because an auth migration gone wrong locks out your entire
user base at once.

---

## Terms defined in this chapter

`rehash on login`, `shadow write`

---

## What to remember

1. **The hard part of an auth migration is moving *existing users* invisibly** — no forced resets,
   no mass logout. Forced resets are a churn event you inflict on yourself.
2. **You can't re-hash passwords** (hashing is one-way) — you only hold the plaintext when the user
   logs in.
3. **Rehash on login:** upgrade each user's hash on their next successful login. The population
   migrates itself, silently.
4. **Wrap weak legacy hashes immediately** in a batch job ([D03](../track-d/D03-how-to-store-passwords.md)) —
   containing the risk *now* — and **deadline the stragglers.**
5. **Migrating to a provider:** bulk-import hashes if it supports it (ask *before* signing —
   [C05](../track-c/C05-build-vs-buy.md)); otherwise lazy-migrate on login.
6. **Don't log everyone out:** migrate the session store, or **accept both old and new formats
   during an overlap** ([I06](../track-i/I06-key-rotation.md)), then retire the old.
7. **Overlap, don't big-bang.** Run old and new together, migrate gradually, monitor
   ([I08](I08-observability.md)), and keep a rollback at every step.

---

## Sources

- [OWASP Password Storage Cheat Sheet — upgrading hashes](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) ([D03](../track-d/D03-how-to-store-passwords.md))
- [Auth0 / Okta: bulk import & lazy migration ("automatic migration")](https://auth0.com/docs/manage-users/user-migration)
- [The Copenhagen Book — Password migration](https://thecopenhagenbook.com/)

---

**Track I complete.** You can run an identity system in production — provision, deprovision,
manage secrets and keys, test it, observe it, detect attacks, respond to incidents, stay
compliant, and migrate it. Track J is the frontier: identity when there's no human at all.

**Next:** [J01 — Machine identity is not user identity](../track-j/J01-machine-identity-is-not-user-identity.md)
