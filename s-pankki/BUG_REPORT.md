# S-Pankki — CSRF-able session destruction in e-banking (online.s-pankki.fi)

**Target:** `online.s-pankki.fi` (in scope — S-Pankki e-banking)
**Severity:** Medium (High in banking context — see Impact)
**Type:** Session Management / Application Logic + Cross-Site Request Forgery
**Auth:** Authenticated (any logged-in e-banking user, including demo)
**Tested:** 2026-10-14

## Summary

A **single unauthenticated-cross-site GET request** destroys the entire e-banking session:

```
GET https://online.s-pankki.fi/ebank/accountview/showAccountDetails.do
```

- No query parameters required (the URL also works with an invalid/absent `accountId`).
- No CSRF token, no custom header, no `Referer` check.
- The kill response explicitly expires the session cookie:
  `Set-Cookie: JSESSIONID=...; Max-Age=0; Expires=Thu, 01-Jan-1970 00:00:00 GMT; SameSite=None`
- `JSESSIONID` is `SameSite=None` → the cookie **is sent on cross-site GET requests**.
- All subsequent requests return the "Verkkopankin yhteys on suljettu" (connection closed) page until the user logs in again.

Because the session cookie is `SameSite=None` and the trigger is a plain GET with no token, an attacker can force the kill cross-origin with one HTML tag:

```html
<img src="https://online.s-pankki.fi/ebank/accountview/showAccountDetails.do">
```

See `poc/session_kill_csrf.html` (load it while logged in as the demo user) and `poc/session_kill.sh` (curl repro).

## Reproduction steps (demo user)

1. Log in to `https://online.s-pankki.fi` with demo credentials (or any valid session).
2. Verify session is alive: `GET /ebank/accountview/overview.do?menuId=mybank` → 200, overview page.
3. Request the kill URL (bare, zero params, no Referer):
   `GET /ebank/accountview/showAccountDetails.do`
   → 200, body = "Verkkopankin yhteys on suljettu", header `Set-Cookie: JSESSIONID=...; Max-Age=0; ...; SameSite=None`
4. Repeat step 2 → same "closed" page. **Session is gone.** User must log in again.
5. Control test: a *valid* `accountId` on the same URL returns the account page (200, ~56 KB) and the session survives.

Full raw captures: `evidence/session-kill/test_log.txt`,
`evidence/session-kill/kill_bare_url_response.txt` (kill response w/ headers),
`evidence/session-kill/session_dead_after_kill.html`,
`evidence/session-kill/valid_accountid_baseline.html`,
`evidence/session-kill/jsessionid_samesite_none.txt`.

Verified kill variants (all destroy the session):

| Variant | Result |
|---|---|
| `showAccountDetails.do` (no params) | session killed |
| `showAccountDetails.do?accountId=0000…0` (32×0) | session killed |
| `showAccountDetails.do?accountId=<short/long/injection strings>` | session killed |
| `showAccountDetails.do?accountId=<valid demo hash>` | session survives (control) |

Fresh-login → kill → confirmed-dead was repeated for each variant (test log F1–F3, T1–T5).

## Why it is exploitable cross-site (CSRF)

1. Trigger is a plain **GET** — fires from `<img>`, `<script>`, `<link>`, or a link click.
2. `JSESSIONID` attributes: `Secure; HttpOnly; path=/ebank; SameSite=None` → sent on cross-site top-level/subresource GETs.
3. Server performs the kill **without checking `Referer`/`Origin`** (verified: kill requests were sent with no Referer at all).
4. No CSRF token in the request or required headers.

## Impact

- **Forced re-authentication / session DoS:** any logged-in customer visiting an attacker page (or clicking a link) loses their e-banking session mid-operation.
- **Banking-specific impact:** kill the session **mid payment / mid confirmation / mid OTP flow** → interrupts a transfer in flight and forces the customer to re-authenticate on attacker timing (classic login-fatigue / phishing window). A bank's session is the most sensitive object on the user's browser; destroying it on demand is a reliable disruption primitive.
- The bank's own closed-session page says *"connection was closed for security reasons, because the online bank has not been used for 15 minutes"* — users cannot distinguish a forced kill from normal idle timeout, so the kill is stealthy.
- Not client-side only: the server actively invalidates the server-side session and expires the cookie (`Max-Age=0`).

## Root cause

`showAccountDetails.do` treats a missing/unresolvable `accountId` as a fatal condition and calls session invalidation instead of returning an error page within the session. Combined with `SameSite=None` (needed for cross-domain embedding, e.g. CrossKey frames) and a tokenless GET, the fatal path becomes a CSRF-able session-kill primitive.

## Suggested fix

1. Return an in-session error page (or the overview) for missing/invalid `accountId` — do not invalidate the session.
2. If the session must be invalidated on this path, require `Referer`/`Origin` on `/ebank/` or add an anti-CSRF token to state-changing GETs.
3. Consider `SameSite=Lax` for `JSESSIONID` if cross-site subresource GETs to `/ebank/` are not functionally required.
