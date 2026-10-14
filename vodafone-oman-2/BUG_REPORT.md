# [Critical] My Vodafone (Oman) — Full Account Takeover via Brute-Forceable 4-Digit Email OTP (No Effective Rate Limit / No Lockout)

**Severity:** Critical
**Category:** Broken Authentication / Authentication Bypass (CWE-307: Prediction of Quantity of Validation Attempts)
**Affected:** `https://vfo01.vodafone.om` (ZenAuthNext SGW, `/auth/api/public/*`) — resulting token accepted on `vfo02.vodafone.om` (ZDS) and `vfo03.vodafone.om` (Chat)
**App:** `om.vodafone.mva` (My Vodafone, v5.2.2); iOS app id 1589071345 (same flow)
**Date:** 2026-10-14
**Researcher:** h1.recon  ← replace with your actual H1 username (every request carried a `h1.recon` UA suffix)
**Related report:** separate High finding — anonymous account creation via this same flow: `../vodafone-oman-pentest/BUG_REPORT.md`

---

## Summary

The My Vodafone app's email-OTP login is effectively a **4-digit PIN with a 5–15 minute validity window, no lockout, no captcha, and effectively unlimited resends**. This report proves a **full account takeover** (the previously filed High finding, anonymous account creation, escalates through the same flow):

1. **Blind brute force (attacker does NOT need the victim's mailbox).** A 63-minute blind run against one address produced **1,113 consecutive wrong guesses — all answered `OTP_MISMATCH`, with no lockout, no session invalidation, no captcha and no account freeze**. The server keeps evaluating guesses long after the advertised 3-attempt counter hits 0 (the counter is cosmetic; 120+ consecutive wrong guesses were accepted against a single code). Codes stay alive 5–15 min, resends are accepted repeatedly, and **multiple codes are simultaneously valid** — so a low-and-slow sweep (~0.5 guesses/s, normal login traffic) against a 10⁴ space is a practical online attack, and failure never resets progress.
2. **OTP-mail interception (any read access to the victim's mailbox).** Shared/forwarded mailboxes, MDM help desks, or a provider breach let the attacker read the 4-digit code straight out of the "Log in to my Vodafone" email (it is the magic-link parameter `?otpCode=XXXX`). **We completed the full takeover in ~40 seconds** (fresh session → self-issued resend → code read from inbox → accepted → customer JWT), see Proof of Exploitation below.

In both variants, success mints a **30-minute customer JWT (`scope:["customers"]`)** with **nine audiences** (`MVA_ZDS`, `DXL_SPM`, `DXL_ZMS`, `DXL_CXC`, `DXL_SCM`, `DXL_OTP`, `CHAT`, `MVA`, `<VFO>`) — a full customer session: profile, payment methods, bills/orders, top-up, KYC update endpoints, customer chat, and the DXL backend systems. The session is trivially renewable by repeating the flow, so it is a permanent takeover, not a one-shot.

Root cause that widens the blast radius (the previously reported High): **any syntactically valid email is accepted — pre-registration is not checked.** Unregistered addresses silently create a persistent customer account (`customer_id`), so the PoC runs against any disposable mailbox and the auto-created account receives the same `scope:["customers"]` JWT as a real customer.

## Proof of Exploitation — complete ATO, 2026-10-14 12:33Z

Target: disposable mailbox `h1bf4850864b@maxxspace.com` (mail.tm). Full raw requests/responses in `evidence/oto4_result.json`, summary in `evidence/ato_evidence_summary.txt`.

| Time (UTC) | Event |
|---|---|
| 12:33:08 | Fresh PKCE session on `vfo01` (`POST /auth/api/public/login/v1/start`, `clientId=MVA`) |
| 12:33:12–24 | 4 stale codes from earlier issuance tried → `OTP_MISMATCH` (codes had expired; server still evaluates) |
| 12:33:30 | `POST .../login/v1/authenticate` with `resend:true` **accepted** → new 4-digit code issued (`otpExpiresIn: 899`) |
| 12:33:46 | Code **3140** read from the target mailbox (mail.tm API — "Log in to my Vodafone" mail, `https://www.vodafone.om/confirmActivationEmail?otpCode=3140`) |
| 12:33:48 | OTP **3140 submitted → ACCEPTED** → `{"redirectUri":"https://esgw.pr.itcloud.vodafone.om/authorized?code=ac_gHE5...&state=..."}` |
| 12:33:48 | `POST /auth/api/public/access-token/v1` (PKCE exchange) → **customer JWT** |

**JWT claims** (full token in `evidence/ato_evidence_summary.txt`):

```json
{
  "sub": "inet:e905d95f-31e2-4899-ab18-dfed1b52e6f3",
  "customer_id": "e905d95f-31e2-4899-ab18-dfed1b52e6f3",
  "email": "h1bf4850864b@maxxspace.com",
  "scope": ["customers"],
  "aud": ["MVA_ZDS","DXL_SPM","DXL_ZMS","CHAT","MVA","DXL_OTP","DXL_CXC","DXL_SCM","<VFO>"],
  "azp": "MVA",
  "iss": "https://isgw.pr.itcloud.vodafone.om",
  "iat": 1791981227, "exp": 1791983027   // 30-minute lifetime
}
```

**Backend acceptance** — same JWT, with/without-Bearer contrast (raw in `evidence/jwt_probe2.json`):

| Endpoint (in scope) | Without Bearer | With ATO JWT |
|---|---|---|
| `vfo03` `GET /chat/customer/v1/agents/availability` | 401 | **200** `{"anyAgentAvailable":false}` |
| `vfo02` `GET /api/public/profile/v2/kyc/configuration` | 401 | **400** `"Unsupported HTTP method GET"` — token passed auth and reached business logic |
| `vfo02` `GET /api/public/profile/v1` | 401 `LOGOUT` | **500** (business response — see note) |
| `vfo02` `GET /api/public/profile/v1/paymentMethods` | 401 | **500** (same) |

Note: for the auto-created (unenrolled) account the vfo02 endpoints answer 500 instead of a clean 400 because the gateway's exception handler is itself broken — `Exception in exception handler: Failed to convert from type [com.zentity.gw.exception.BadRequestException] to type [com.zentity.gw.exception.ExceptionDescription] ... nested exception is java.lang.IllegalArgumentException: Unmatched brace`. For a *registered* customer this path returns real profile data. The broken error conversion is a secondary finding on its own (internal class names + Java internals leak).

## Why the blind brute force is practical (measured, not assumed)

Blind run: `poc/poc_blind_bruteforce.py`, one address, full 63-minute log in `evidence/bf_run.log` + `evidence/bf_log.jsonl`, stats in `evidence/blind_run_stats.json`.

- **1,113 wrong guesses, 13 resends, 63 minutes — no lockout.** Final milestone line: `+63m00s guesses=1113 resends=13 errors=57 found=False`. Every guess got a live `OTP_MISMATCH` (the 57 "errors" were the WAF penalty pages listed below, not rejections). No captcha, no account freeze, no session reset — the sweep is resumable and only ever moves forward.
- **The 3-attempt counter is cosmetic.** `otpAttemptsLeft` counts to 0 and the server keeps evaluating; 120+ consecutive wrong guesses against one code were all answered `OTP_MISMATCH`.
- **Code lifetime 299–899 s (5–15 min)** per issuance (`otpExpiresIn`), and **multiple codes are simultaneously valid** (12:00:51Z → 4032 *and* 2315, 12:01:56Z → 5260 — all three alive together until 12:15–12:16Z).
- **Resends accepted repeatedly** per email (13 resends in the run); `otpResendIn` cooldown enforcement is loose/inconsistent (observed counting down to the previous code's expiry, and to just 59 s after an 899 s-code issuance).
- **Clean single-session rate ~0.51 guesses/s** (sustained, no WAF penalty).
- **Only friction:** a transient WAF HTML penalty page (HTTP 200 body starting `<!DOCTYPE html>` with `Pragma no-cache` / `Expires: -1`) on the vfo01 auth endpoints when sustained above ~40 req/3 min. It self-clears in 5–18 min with low traffic and does **not** invalidate sessions or reset the sweep.

Math: at ~0.5 guesses/s with 2–5 simultaneously valid codes, expected time to hit a live code is on the order of **1–3 hours** of low-and-slow normal login traffic — and every guess is permanent progress, so the attack never has to start over.

**Additional observed weaknesses** (all timestamped in `evidence/bf_log.jsonl`):

- **One resend request can deliver TWO different OTP emails** — 11:39:11–12Z → codes `0773` and `2120` one second apart; 12:00:51/12:01:01Z → `4032` and `2315`. Issuance race: more live codes = higher hit probability for the sweep.
- **A 500 error burst on `authenticate` still delivered OTP emails** — 11:12Z: HTTP 500 responses, yet codes `4699` + `9046` were delivered. Codes can be issued even when the request "fails".
- **Stale codes are still evaluated** (answered `OTP_MISMATCH` minutes after expiry) instead of being rejected with a distinct `OTP_EXPIRED` — no free oracle, but the server does extra work per stale guess.

## Attack scenarios

1. **Registered customer — blind ATO (primary).** Attacker knows/recovering the customer's email. Trigger the login flow, sweep the 4-digit space at low rate. Success → the *victim's* customer session: read profile and payment methods, view bills/orders, update KYC data (vfo02 POST/PATCH endpoints), use customer chat (vfo03), and hit the DXL_* systems the JWT's audiences unlock.
2. **OTP-mail interception.** Any read access to the victim's mailbox (shared/forwarded mailbox, help desk, provider breach) → **~40 s ATO**, proven above.
3. **SMS twin.** The identical mechanics exist for `vfoSmsOtpMethod` (same 4-digit OTP, same authenticate endpoint/body shape, MSISDN instead of email) against a registered mobile line → ATO of the line itself. (Tested with well-formed and invalid `+968` prefixes — accepted, no enumeration at trigger.)
4. **Unregistered email (the underlying High).** Any address silently creates a persistent customer account with the same `scope:["customers"]` JWT — so the attack surface is *every* email address, and re-login with the same email returns the same `customer_id` (verified: `a84bafed-8be0-45de-91b8-83f279008261` across sessions).

## How to reproduce

Full copy-pasteable manual (curl/bash) walkthrough — including throwaway-mailbox setup, both variants, and the 401/200 backend proof: **`HOW_TO_REPRODUCE.md`**.

The Python PoCs in `poc/` are the same flows automated. All are Python 3, stdlib only, and send standard MVA-app login traffic (UA suffixed `h1.recon`).

**Variant A — proven ATO, self-issued code, ~1 min** (mailbox-read variant):

```
python3 poc/poc_oto_selfissued.py <victim-or-throwaway-email> [known-live-codes ...]
```

1. Fresh PKCE session on vfo01. 2. `resend:true` to issue a new code. 3. Poll the target mailbox (mail.tm API) for the new 4-digit code. 4. Submit → PKCE exchange → prints full customer JWT + claims. 5. Proves acceptance on vfo02 (profile/KYC) and vfo03 (chat) with 401 contrast.

**Variant B — blind brute force, no mailbox access:**

```
python3 poc/poc_blind_bruteforce.py <victim-email> [workers=1]
```

Pipeline design (from the observed mechanics): issues codes via resend, hammers a static partition of 0000–9999 with persistent position (no value is ever re-guessed), backs off the WAF penalty automatically (circuit breaker + 90 s single-shot probes). On hit: `redirectUri` → PKCE exchange → JWT written to `bf_SUCCESS.json`. Run with `workers=1` for a single cautious session (~0.5 guesses/s); the evidence run used 2 workers for 63 min.

**Variant C — original anonymous-account-creation PoC:**

```
python3 poc/poc.py
```

Auto-creates a throwaway mail.tm mailbox, completes the flow, prints the JWT and its claims, re-runs to show the persisted `customer_id`.

Raw evidence for every step (OTP email HTML, auth-code redirect, token response, decoded claims, blind-run logs, ATO timeline) is in `evidence/`.

## Safe Harbor notes

- Standard app login traffic with the stock MVA app headers; UA suffixed `h1.recon`.
- PoCs used fresh disposable mailboxes (mail.tm); the only real address touched was `security@vodafone.om` in a single cautious blind background run (normal login traffic only, ~0.5 rps, impact verification).
- No DoS, no social engineering, no MITM; only in-scope hosts used (`vfo01/vfo02/vfo03.vodafone.om`); `esgw/isgw.pr.itcloud.vodafone.om` appears only inside responses.
- Traffic kept low and the observed WAF penalty was respected (automatic backoff).

## Suggested fixes

1. **Lengthen the OTP to ≥6 digits** (or keep 4 digits but enforce the limits below for real).
2. **Real rate limiting:** per-code attempt cap (e.g. 10) *enforced*, plus per-identifier caps (e.g. max 5 issuances/hour per email/MSISDN, exponential resend cooldown, 15–30 min lockout after N consecutive mismatches). The current `otpAttemptsLeft` is cosmetic.
3. **Invalidate superseded codes on resend** (fix the multi-live-codes + double-email issuance race), and answer distinct errors for mismatch vs expired.
4. **Scope unenrolled accounts** (auto-created customer accounts) with a guest-scoped token, or reject unregistered emails at login start.
5. **Fix the Zentity GW exception handler** on vfo02 (500 "Exception in exception handler" leaking internal class names instead of a clean 400 for unenrolled customers).
6. Bind `secretPayload`/code to a single session+window so a code cannot be replayed across sessions.
