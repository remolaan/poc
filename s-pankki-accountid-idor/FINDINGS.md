# S-Pankki (s-pankki.fi) — findings overview

Program: HackerOne / S-Pankki. Test date 2026-10-14. Demo user `12345678/123456`, UA `@wearehackerone`.

## Headline — Critical (this folder: `s-pankki-accountid-idor/`)

**`accountId` Broken Object Level Authorization (IDOR) — authenticated read chain incl. server-generated PDF report.**
`accountId` (opaque 64-hex, salted/derived, not an IBAN hash) is the sole global account key.
`GET /ebank/pad/fees/getReport.ds?accountId=<A>&year=<Y>` (plain GET, no CSRF token, no Referer check)
generates account A's official 2-page PDF (customer name, address, IBAN, period, fees/interest)
for whatever `accountId` is in the URL — proven URL-driven over session context with an 8-cell fresh-login matrix.
The same key drives `fetchTransactionList.do` (full balance + transaction history with counterparty names)
and the CSV export. Validity oracles on `getReport.ds` (PDF vs 509B error) and `exportRangedTransactions.ds`
(302 vs error). `JSESSIONID` is `SameSite=None` → cross-site top-level navigation fires the same tokenless GET.
See `BUG_REPORT.md`, `evidence/`, `poc/pad_report_idor.sh`, `poc/xsite_pdf_steal.html`.

## Companion — Medium (folder `s-pankki/`, `BUG_REPORT.md` there)

**CSRF-able session destruction:** bare/invalid `GET /ebank/accountview/showAccountDetails.do`
→ 200 + `Set-Cookie: JSESSIONID=…; Max-Age=0` + closed-session page. Tokenless GET + `SameSite=None`
cookie → one cross-site `<img>` kills a victim session mid-payment. Same `accountId`-validation
root cause family as the Critical (invalid id treated as fatal instead of in-session error).

## Supporting / demo-blocked (context for triage)

- **Statement PDF** (`/ebank/account/fetch.ds` POST, all field combos) → demo error `!!lbl_demo_user_error!!` (endpoint exists, demo-restricted).
- **CSV export** (`/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=…&fileType=sba-CSV`) → **live-verified accountId-keyed CSV** (real header w/ recipient name/IBAN/BIC columns; valid empty range → 200 CSV, invalid → 53–56 KB error = oracle, valid w/ data → 302 → `processTransactionList.do` one-shot; demo blocks the full row-stream there). Evidence `12_…15_`.
- **Transaction detail page** → demo message "Tutustuessasi palveluon et voi katsoa tapahtumaerittely".
- **MyEconomy summary** (`POST /ebank/budget/getTransactions.do`, all variants incl. fresh Struts token, both accounts) → generic server error (demo-restricted).
- **fundamental-api payee-verifications** → demo-blocked at proxy (High potential in production).
- **`.ds` sweeps:** 25 authed + 21 unauth endpoints probed; unauth read consistently blocked (1367B closed page) → the IDOR is an authenticated cross-user read, not unauth.
- **CSP/cookie inventory, subdomain map** (217.29.228.x, CrossKey, Chat proxy `chat.inet.s-pankki.fi` AWAITING_VISITOR_ID/LIGHT): see `s-pankki/evidence/subdomains_2026-10-14.json`, `s-pankki/evidence/extranet_oidc_redirect.txt` (OIDC client_id exposure), `s-pankki/evidence/digili_auth_oracle.txt`, `s-pankki/evidence/status_poll_unauth_500_json.txt`.
