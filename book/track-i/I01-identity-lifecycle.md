# I01 — The identity lifecycle: joiner, mover, leaver

**Part I · Identity lifecycle & operations** · *Builds on [C01](../track-c/C01-auth-is-five-different-problems.md)*
> The half of auth that only shows up in production. Tracks D–H build the mechanisms; Track I
> is what happens to identities *over time* — and it is where audits fail.

---

## The three events

Every identity, human or machine, passes through three lifecycle events — **joiner, mover,
leaver** (JML):

```
   JOINER ──────────▶ MOVER ──────────▶ LEAVER
   account created    role/access       access
   with correct       changes as they   fully
   initial access     change position   removed

   Provisioning       Re-provisioning   Deprovisioning
   I02                (grant + REVOKE)   I03
```

| Event | What must happen | The failure if it doesn't |
|---|---|---|
| **Joiner** | Create the account, grant *exactly* the right access | Over-provisioning; delays that push people to share accounts |
| **Mover** | Grant new access **and revoke old** | **Privilege accumulation** — the accountant who's now in sales keeps financial access |
| **Leaver** | Remove *all* access, everywhere, promptly | **Orphaned accounts** — the audit-failing 147 |

The three are not equally hard. Joiners get attention (a new hire can't work without access, so
someone notices). **Movers and leavers get neglected**, because *nothing breaks* when they're
done wrong — the person keeps working; the ex-employee's account just sits there. The absence
of a forcing function is precisely why these fail.

---

## The mover is the sneakiest

Joiners and leavers are at least conceptually simple (add everything / remove everything). The
**mover** is where the subtle, dangerous failure lives: **you remember to *grant* the new
access and forget to *revoke* the old.**

```
   Alice: Finance (payroll access) ──moves to──▶ Marketing (campaign access)
                                                          │
   If you grant campaign access but forget to revoke payroll access:
   Alice now has BOTH — access she no longer needs, that nobody is watching.
```

Over a career of moves, an employee accumulates permissions like sediment — **privilege
accumulation** (also "access creep"). The result is a workforce where most people have far more
access than their current job needs, which is:

- A **larger blast radius** ([I10](I10-incident-response.md)) — a compromised account reaches
  more than it should.
- An **insider risk** — access nobody remembers granting is access nobody is monitoring.
- An **audit finding** — least privilege ([H01](../track-h/H01-where-does-authz-live.md)) is violated by
  definition.

The fix is to make "mover" mean **replace, not add**: reset to the new role's baseline access,
then grant exceptions — rather than layering new grants on old. This is where role-based models
([H04](../track-h/H04-rbac-and-when-it-breaks.md)) help: change the role, and the permissions
follow, old ones dropping automatically.

---

## The leaver is the audit failure

The 147 orphaned accounts. **Deprovisioning is the step that fails audits** because it has the
weakest forcing function of all — when someone leaves, no legitimate user is inconvenienced by
their account lingering, so nothing prompts the removal.

The dangers of an orphaned account ([I03](I03-deprovisioning.md)):

- The person may still have the credentials — and now a grievance.
- The account is a **standing, unmonitored entry point** an attacker can find and use.
- Shared and service accounts ([J03](../track-j/J03-service-accounts.md)) are worst: nobody
  "owns" them, so nobody removes them.

Deprovisioning must be **prompt** (an ex-employee should lose access within minutes of leaving,
not weeks), **complete** (every system, including the ones IT forgot about — SaaS apps
provisioned by a team, not central IT), and **verified** (someone confirms it happened). This
is [I03](I03-deprovisioning.md)'s whole chapter.

---

## Why this needs automation

The manual failure mode: HR notifies IT, IT logs into each of forty systems and disables the
account by hand. It doesn't scale, it's error-prone, and it *silently* misses systems. The 147
orphans are what manual deprovisioning produces.

The automation is **provisioning protocols** — chiefly **SCIM**
([I02](I02-provisioning-and-scim.md)) — that connect your **source of truth for identity**
(usually the HR system or the corporate IdP) to every downstream application, so that:

```
   HR system / IdP  ──SCIM──▶  App A
   (source of truth)  push     App B
                      changes   App C
   Joiner  → create in all
   Mover   → update in all
   Leaver  → deactivate in all   ← the one that fixes the 147
```

One event at the source (HR marks someone as departed) propagates to every connected app
automatically. This is what turns JML from a hopeful manual process into a reliable one, and it
is why enterprise buyers demand SCIM ([G09](../track-g/G09-multi-tenant-sso.md),
[I02](I02-provisioning-and-scim.md)).

---

## Machines have a lifecycle too

JML is not only for humans. Service accounts, API keys, and workloads
([Track J](../track-j/J01-machine-identity-is-not-user-identity.md)) also join, change, and
leave — and their leaver problem is *worse*, because a machine never quits or complains, so an
orphaned service account or an unrotated API key ([J02](../track-j/J02-api-keys.md)) can persist
for years:

- A **service account** for a decommissioned service, still valid ([J03](../track-j/J03-service-accounts.md)).
- An **API key** issued for a one-off integration, never revoked.
- A **CI credential** for a pipeline that no longer exists.

These are orphaned accounts with no human to notice, and they accumulate silently. The same
JML discipline applies: provision with least privilege, rotate/re-scope on change
([I06](I06-key-rotation.md)), and *deprovision* — including a policy that credentials with no
recent use are automatically flagged and disabled.

---

## The through-line for Track I

The identity lifecycle is where the theory of Tracks D–H meets the mess of production:

```
   Provisioning        who gets access, and how it's created        I02
   Deprovisioning      the audit-failing gap                        I03
   Impersonation       support acting as a user, safely             I04
   Secrets & keys      the operational credentials                  I05, I06
   Testing & observ.   proving it works, seeing what happens        I07, I08
   Detection & IR      when it goes wrong                           I09, I10
   Compliance          proving it to an auditor                     I11
   Migration           changing the system without breaking it      I12
```

None of it is a *mechanism* — it's the *operation* of the mechanisms over time, at scale, under
change. It is the work nobody warns you about, and the reason "we added auth" and "we have a
working identity system" are two very different claims.

---

## Terms defined in this chapter

`joiner-mover-leaver` (JML), `identity lifecycle` (from C01, expanded)

---

## What to remember

1. **The identity lifecycle — joiner, mover, leaver — is where audits fail.** It's invisible to
   Tracks D–H, which assume a static, correct set of identities.
2. **The mover is the sneakiest:** you grant new access and forget to revoke old, producing
   **privilege accumulation**. Make "mover" mean *replace*, not *add*.
3. **The leaver is the audit failure:** orphaned accounts, because nothing breaks when
   deprovisioning is skipped ([I03](I03-deprovisioning.md)).
4. **The weak forcing function is the root cause** — nobody is inconvenienced by a lingering
   account, so nobody removes it.
5. **Automate with SCIM** ([I02](I02-provisioning-and-scim.md)): one event at the HR/IdP source
   propagates to every app.
6. **Machines have a lifecycle too** — and a worse leaver problem, because no one notices an
   orphaned service account or unrotated key ([J02](../track-j/J02-api-keys.md), [J03](../track-j/J03-service-accounts.md)).

---

## Sources

- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 10 (provisioning)
- [NIST SP 800-53 — AC-2 (Account Management)](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [RFC 7644 — SCIM Protocol](https://www.rfc-editor.org/rfc/rfc7644) ([I02](I02-provisioning-and-scim.md))

---

**Next:** [I02 — Provisioning: manual, just-in-time, and SCIM](I02-provisioning-and-scim.md)
