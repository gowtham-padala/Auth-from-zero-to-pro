# A02 — Reading HTTP requests and responses in your browser dev tools

**Part A · How the web actually works** · *Builds on [A01](A01-what-happens-when-you-type-a-url.md)*
---

## Open it

`F12`, or `Cmd+Opt+I` on a Mac, or right-click → Inspect. Then the **Network** tab.

Three settings to change immediately, before you do anything else:

1. **Preserve log.** On. Without it, a redirect or a form submission wipes the list
   before you can read it — which is exactly when you most need it. Every login flow is a
   sequence of redirects. Turning this off means you will never see the interesting one.
2. **Disable cache.** On, while dev tools are open. Otherwise you debug a response from
   twenty minutes ago.
3. **Filter: Fetch/XHR or Doc.** The list is mostly images and fonts. You want documents
   and API calls.

---

## The columns that matter

| Column | Read it for |
|---|---|
| **Name** | Which request this is. |
| **Status** | 200, 302, 401, 403, 500. This alone resolves most confusion. |
| **Type** | `document` = a page navigation. `fetch`/`xhr` = a script made this call. |
| **Initiator** | *What caused this request.* Underrated. Click it to see the chain. |
| **Size** | `(from disk cache)` means the server was never asked. |
| **Time** | Timing attacks live here ([B16](../track-b/B16-timing-attacks.md)). |

Click any row and you get four panes: **Headers**, **Payload**, **Preview/Response**, and
**Timing**.

---

## Exercise 1 — Watch a login, redirect by redirect

Log in to any site with dev tools open and "Preserve log" on. You will see something like
this, and the shape is the same almost everywhere:

```
#  Method  Status  Name                        Type
1  GET     200     /login                      document
2  POST    302     /login                      document
3  GET     200     /dashboard                  document
```

Read it as a story:

- **Row 1** — you asked for the login page. `200 OK`, an HTML form came back.
- **Row 2** — you submitted. The server answered `302 Found`. Look at its **Response
  Headers**: there is a `Location: /dashboard` and a `Set-Cookie: session=...`. This
  single response is the entire act of logging in. The server created a session and told
  the browser two things at once: store this, and go there.
- **Row 3** — the browser obeyed the `Location` header. Look at this request's
  **Request Headers**: there is now a `Cookie: session=...` that you did not write.

That third row is the moment authentication becomes session management. The credential
was presented once, in row 2. Every request from row 3 onward proves nothing except
possession of a cookie. That is the whole of Track E, visible in three lines.

### Why `302` and not `200`?

Because of the double-submit problem. If `POST /login` returned HTML directly, pressing
refresh would re-POST the form. The redirect converts the result into a `GET` that is
safe to reload — the **POST/Redirect/GET** pattern. You will see it after every form
submission on any competently built site.

---

## Exercise 2 — Find the cookie, and find the flags

Go to the **Application** tab (Chrome) or **Storage** tab (Firefox) → **Cookies** → your
origin. You get a table:

| Name | Value | Domain | Path | Expires | Size | HttpOnly | Secure | SameSite |
|---|---|---|---|---|---|---|---|---|
| `session` | `8f14e45f...` | `app.example.com` | `/` | Session | 44 | ✓ | ✓ | Lax |

Now the exercise that makes it real. Open the **Console** tab and type:

```js
document.cookie
```

The session cookie **is not in the output**. That is `HttpOnly` working. JavaScript on the
page — including any script you accidentally included from a compromised CDN — cannot read
it. It still gets *sent* on every request; it just cannot be *read* by script.

This is the single highest-value cookie flag, and it is the reason
[E12](../track-e/E12-where-to-store-a-token.md) concludes what it concludes about
`localStorage`. Everything in `localStorage` shows up in that console output. A session
cookie with `HttpOnly` does not.

---

## Exercise 3 — Read a request you did not make

Load any content-heavy page and look at the full unfiltered list. You will find requests
to domains you never typed: analytics, fonts, CDNs, ad networks, error trackers.

Click one going to a third party and look at its **Request Headers**. Two are worth your
attention:

- **`Referer`** (misspelled in the spec, permanently) — tells the third party which page
  you were on. If your URL contains a token, a password reset code, or an internal
  document ID, you just sent it to a company you have never heard of. This is why
  `Referrer-Policy` exists and why secrets do not go in URLs.
- **`Cookie`** — whether it is present depends on that cookie's `SameSite` attribute
  ([E02](../track-e/E02-cookie-attributes.md)).

Each of those third-party scripts runs with your origin's full privileges
([A07](A07-client-vs-server.md)). The Network tab is where you find out how many of them
there are.

---

## Exercise 4 — Copy as cURL

Right-click any request → **Copy** → **Copy as cURL**. Paste it in a terminal.

```bash
curl 'https://app.example.com/api/documents/42' \
  -H 'Cookie: session=8f14e45fceea167a5a36dedd4bea2543' \
  -H 'Accept: application/json'
```

Run it. It works. The API cannot tell the difference between your browser and your
terminal, because there is no difference — it is the same bytes.

Sit with that for a second, because it is one of the load-bearing facts of this book:

> **Your server cannot tell what software sent a request. Every header is attacker-controlled.
> The only thing that distinguishes a legitimate request is a credential it carries.**

Not `User-Agent`. Not `Origin` (which the browser sets honestly, but `curl` sets to
anything you like). Not the absence of unusual headers. The credential, and nothing else.

Now delete the `Cookie` line and run it again. You should get `401`. If you get `200`, you
have found a real vulnerability, and you should read
[H14](../track-h/H14-attack-your-own-authorization.md) immediately.

---

## Exercise 5 — Change something and replay it

In Firefox: right-click a request → **Edit and Resend**. In Chrome, use the cURL command
from exercise 4 and edit it there.

Change the document ID from `42` to `43`. Send it.

If you get back a document belonging to someone else, that is **IDOR** — insecure direct
object reference — and it is statistically the most common serious vulnerability in real
applications. It gets a full treatment in
[H14](../track-h/H14-attack-your-own-authorization.md). The reason it is so common is
that the ID looks like it comes from your UI, and your UI only ever shows the user their
own documents. But the request does not come from your UI. It comes from whoever is
holding the cookie, typing whatever they like.

---

## Reading a response body

The **Response** pane gives you raw bytes. **Preview** gives you a parsed view — formatted
JSON, rendered HTML. For debugging auth, prefer **Response**: you want to see the actual
characters, including whitespace, encoding, and the exact error string. The formatting in
Preview can hide a stray byte-order mark or a subtly different error message, and in
[D07](../track-d/D07-user-enumeration.md) a subtly different error message is the entire
vulnerability.

---

## A debugging checklist for "the login isn't working"

Work down it in order. Each step eliminates a whole class of cause.

1. **Is the request being sent at all?** No row in Network → it is a client-side bug.
   JavaScript threw before the fetch, or the form has no `action`.
2. **What is the status code?** `4xx` is your request. `5xx` is their server.
   `3xx` means look at `Location`. ([A03](A03-methods-status-codes-401-vs-403.md).)
3. **Was a `Set-Cookie` returned?** Response Headers. If not, the server did not create a
   session — the failure is before the cookie stage.
4. **Was the cookie actually stored?** Application → Cookies. A `Set-Cookie` that the
   browser rejected is *silent*. Common causes: `Secure` on plain HTTP, a `Domain` that
   does not match, `SameSite=None` without `Secure`. Chrome shows rejected cookies with a
   warning triangle in the Network tab's Cookies pane — look there.
5. **Is the cookie being sent back?** Request Headers on the *next* request. Present in
   storage but absent from the request usually means `SameSite` or a `Path` mismatch.
6. **Only now**, look at the server logs.

Steps 1–5 take under a minute and resolve the large majority of auth bugs. Most people
start at step 6.

---

## Terms defined in this chapter

`user agent`, `dev tools`, and working familiarity with: `Set-Cookie`, `Location`,
`Referer`, POST/Redirect/GET

---

## What to remember

1. Turn on **Preserve log**, or you will never see the redirect that matters.
2. A login is `GET 200` → `POST 302 + Set-Cookie` → `GET 200 + Cookie`. Three rows.
3. `document.cookie` not showing your session cookie is `HttpOnly` working correctly.
4. **Copy as cURL** proves your server cannot tell who is calling it. Only the credential
   distinguishes callers.
5. A rejected cookie fails *silently*. Always verify in the storage tab, never assume.

---

## Sources

- [Chrome DevTools: Network features reference](https://developer.chrome.com/docs/devtools/network/reference)
- [MDN: Firefox Network Monitor](https://firefox-source-docs.mozilla.org/devtools-user/network_monitor/)
- [MDN: Referer header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer)

---

**Next:** [A03 — HTTP methods, status codes, and why 401 is not 403](A03-methods-status-codes-401-vs-403.md)
