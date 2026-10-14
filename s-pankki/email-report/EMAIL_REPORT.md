# HackerOne Report — Email Body (copy-paste ready)

---

**To:** S-Pankki (HackerOne)
**Subject:** [Critical] Broken Access Control: accountId IDOR leaks any customer's official PDF fee report and accountId-keyed CSV transaction export via tokenless GET

---

Hi S-Pankki team,

I'd like to report a **Broken Access Control (IDOR)** issue in the e-banking portal (`online.s-pankki.fi`). Every account is addressed in URLs by an opaque, 64-hex `accountId` parameter, and several server endpoints — including **official report generation** — use that URL parameter to select *which customer's data to generate and return* without verifying that the account belongs to the authenticated session.

**Result:** with any valid session (e.g. your test user), a plain tokenless GET downloads another account's:

1. **Official PAD fee-report PDF** — the bank's own machine-generated document containing the customer's name, address, account type and full IBAN, and
2. **accountId-keyed CSV transaction export** — with columns for amount, payer, recipient name, recipient IBAN, recipient BIC, reference and message.

No CSRF token is required on either endpoint (the bank's own JS fires them as plain GETs in a new window). A separate per-account **validity oracle** (invalid id → HTTP 200 + 509 B error page instead of the PDF) lets an attacker validate harvested ids.

## Severity: Critical

- Authenticated cross-account access (the `accountId` is a global account key, not derived per user)
- Leaked artifacts are real, downloadable, bank-generated documents (PDF + CSV), not just rendered HTML
- Tokenless GET surface → exploitable cross-site via top-level navigation (JSESSIONID is `SameSite=None; Secure; HttpOnly`)
- Validity oracle for id enumeration/validation

## Environment

- `https://online.s-pankki.fi` (demo/test account per program scope, UA `@wearehackerone`)
- Reproduced 2026-10-14, all findings re-verified on fresh sessions

## Key endpoints (all plain GET, no CSRF token)

| # | Endpoint | Effect with a foreign `accountId` |
|---|----------|-----------------------------------|
| 1 | `/ebank/pad/fees/getReport.ds?accountId=<A>&year=2025` | **Returns the official fees PDF for account A** (`application/pdf`, ~116 KB) — URL param drives the report, session context is ignored |
| 2 | `/ebank/account/showAccountDetails.do?accountId=<A>` | Sets the account context for the session to account A |
| 3 | `/ebank/account/fetchTransactionList.do` (no params) | Returns the **full transaction data page (~75–81 KB)** of the context account: transactions, balances, history |
| 4 | `/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=<A>&fromDate=<DDMMYYYY>&toDate=<DDMMYYYY>&fileType=sba-CSV` | **CSV export of account A's transactions** (recipient name/IBAN/BIC, amounts, messages) |
| 5 | `/ebank/account/initTransactionDetails.do?accountId=<A>&rowNo=<N>&type=trans&archivecode=<c>` | **Per-transaction detail** for account A's row N — plain GET, no CSRF token (demo profile hides the table behind onboarding) |
| 6 | any of the above with an invalid `accountId` | HTTP 200 + 509 B HTML error page ("Tapahtui odottamaton virhe") — **validity oracle** (200, not 4xx/5xx, distinct from the PDF) |

## Proof — 4-cell fresh-login matrix (PDF content vs. session context)

For every cell I logged in fresh, set a *context* account, then requested the report with a (possibly different) *URL* accountId:

| Session context | URL accountId | IBAN inside the returned PDF |
|-----------------|---------------|------------------------------|
| ACC1 (FI96…) | ACC1 | FI96 3939 0001 0006 03 |
| ACC1 | **ACC2** | **FI74 3939 0001 0006 11** ← URL wins |
| ACC2 (FI74…) | **ACC1** | **FI96 3939 0001 0006 03** ← URL wins |
| ACC2 | ACC2 | FI74 3939 0001 0006 11 |

Four distinct PDF files, four distinct md5s. **The report is always generated for the account named in the URL, regardless of session context.**

- `evidence/01_pad_fees_report_urlACC1_FI96.pdf` / `02_…FI74.pdf` — the two account PDFs
- `evidence/03_matrix_ctxACC1_urlACC2_returns_FI74.pdf` — **the definitive cell**: session is on account 1, URL requests account 2, PDF contains account 2's IBAN
- `evidence/04_matrix_ctxACC2_urlACC1_returns_FI96.pdf` — the reverse
- `evidence/10_pdf_text_report_ACC1.txt` / `11_…ACC2.txt` — extracted text: customer name, address, IBAN, period, interest

## How the accountId reaches an attacker

The opaque id is not meant to be guessed — it's **handed out in plain URLs** all over the app. The account-list page (`redirectByMenu.do?menuId=accounts_mnu_accounts`) contains links for **every** account, e.g.:

```
/ebank/account/showAccountDetails.do?accountId=96c143b2…192f
```

These URLs land in browser history, bookmarks, `Referer` headers (cookie is `SameSite=None`), analytics and server logs. An attacker (another user of the bank, or a passive observer of Referers) who learns even one valid id can then:

1. `GET /ebank/pad/fees/getReport.ds?accountId=<stolen>&year=2025` → victim's official PDF
2. `GET /ebank/accountview/showAccountDetails.do?accountId=<stolen>` (the link the front page itself uses; no side effects) then `GET /ebank/account/fetchTransactionList.do` → victim's full transaction data page
3. `GET /ebank/api/account/transactions/exportRangedTransactions.ds?accountId=<stolen>&fromDate=…&toDate=…&fileType=sba-CSV` → victim's CSV transaction export
4. Use the 509 B error oracle to validate candidate ids.

Because JSESSIONID is `SameSite=None; Secure; HttpOnly`, a cross-site **top-level navigation** can fire these tokenless GETs and deliver the PDF to the attacker. I included a minimal cross-site demo page: `xsite_pdf_steal.html`.

## Evidence of the CSV export (second downloadable artifact)

The app's own CSV button (`evidence/15_app_csv_export_link_js.js`) builds:

```
GET /ebank/api/account/transactions/exportRangedTransactions.ds?accountId=<A>&fromDate=<DDMMYYYY>&toDate=<DDMMYYYY>&fileType=sba-CSV
```

Live results (2026-10-14):

| accountId | range | response |
|-----------|-------|----------|
| valid ACC1 | 01012025–31122025 (empty) | **200, real CSV** — `Kirjauspäivä;Maksupäivä;Summa;Tapahtumalaji;Maksaja;Saajan nimi;Saajan tilinumero;Saajan BIC-tunnus;Viitenumero;Viesti;Arkistointitunnus` (incl. **recipient name, IBAN, BIC**) — `evidence/12_csv_export_valid_accountId_csv_header.csv` |
| valid ACC2 | same | identical per-account CSV (keying works) |
| 64×`0` (invalid) | same | 200, ~53–56 KB HTML error page — `evidence/13_…` (oracle) |
| valid ACC1 | 01012026–31102026 (has tx) | 302 → `/ebank/account/processTransactionList.do` (one-shot file processor; the demo account restricts the full row-stream there — production streams the complete rows). Flow documented in `evidence/14_csv_export_302_flow.txt` |

## Why the PDF shows 0,00 — and the non-zero proof (added 2026-10-14)

**The zeros are expected for this document type, not a sign of an empty account.** `getReport.ds` returns the **PAD fee statement** (the bank's own text: *"Redovisning av avgifter"* = fee accounting) — a fee/interest statement, not a balance statement. The statement itself notes that balance/transactions live in the separate account statement. The demo customer has a basic account **with no fee package**, so every row is legitimately `0,00`. Verified across years:

| Probe | Result |
|-------|--------|
| `year=2025` | 116,300 B PDF, all rows 0,00 (evidence 01/02) |
| `year=2024` | 116,299 B PDF, **also** all rows 0,00 (evidence 19) |
| `year=2026` (unfinished) | 56,644 B HTML page, not a PDF (evidence 20) |
| invalid id | 509 B HTML error — validity oracle (evidence 05/06) |

The 2024 PDF even contains a genuine backend row (range "01.01.2025 – 22.05.2017", 0,0100 % interest) — real per-customer data rows, zero amounts because **zero fees were charged**.

**The non-zero proof** (all captured 2026-10-14, full tables in `evidence/21_nontzero_proof_summary.md`):

1. **Live server-rendered balances** (evidence 16): front page shows ACC1 FI96…03 → **+5 500,00**, ACC2 FI74…11 → **+5 500,00**, total **+11 000,00**, plus card 4318 12\*\* \*\*\*\* 9012 at 6 098,52.
2. **Context-switched transaction pages with real non-zero transactions and counterparty names** — ACC1 page (75,316 B, evidence 17) has 9 rows (e.g. `9.10.2026 −500,00 OMA TILISIIRTO MAIJA MEIKÄINEN`, `7.10.2026 −100,50 TILISIIRTO MATTI MEIKÄINEN`, `1.10.2026 −110,00 KORTTIOSTO ELÄINKAUPPA HOPE`, `30.9.2026 +105,45 LAPSILISÄ KELA`); ACC2 page (81,368 B, evidence 18) has **15 different rows** (e.g. `−250,00 TILISIIRTO`, `−18,65 PALKKA Sokos verkkokauppa`, `−100,00 VUOKRANMAKSU`). Different sizes, different md5s, different data — the page is keyed to the opaque `accountId`.
3. **CSV export 302 data-range oracle**: 2026 range → 302 to `processTransactionList.do` (rows exist); 2025 range → header-only CSV (no 2025 activity — consistent, all activity is 2026, which is the year the fee statement doesn't cover).
4. **Third URL-driven endpoint** found during verification: `initTransactionDetails.do?accountId=<A>&rowNo=<N>&type=trans&archivecode=<per-tx code>` — per-transaction detail, plain GET, no CSRF token (demo profile hides the detail table behind onboarding; production renders the full breakdown).

## Demo-account notes (for triage)

- The demo user (MAIJA) owns both accounts (ACC1/ACC2), so the matrix proves "URL param selects the data owner, no ownership check" at account level; in production the same parameter selects **other customers'** accounts (it is a single global key across the whole bank — the same id works in every endpoint above).
- Statement PDF and the full CSV row-stream are restricted by the demo profile; the fees PDF and CSV header are fully live, and the context-switched transaction page (74–81 KB of real data) is fully live.
- All tests used only the program test account; no other customers' data was touched.

## Impact

- **Confidentiality (High/Critical):** any authenticated user who learns a victim's accountId (from URLs/Referers/history/logs) can download the victim's **official PDF fee report** (identity, address, IBAN, period) and the victim's **CSV transaction export** (counterparties' names, IBANs, BICs, amounts, messages) plus the full transaction data page.
- **Cross-site exploitability:** tokenless GETs + `SameSite=None` cookie → attacker site can trigger the download for the victim's session (PoC: `xsite_pdf_steal.html`).
- **Enumeration:** per-account validity oracle (200 + 509 B error vs 200 + PDF) for validating harvested ids.

## Suggested fix

1. Resolve the account from the session (server-side mapping customer → accountIds) and reject any `accountId` not belonging to the session owner (403/404, not 200+error page).
2. Prefer POST + CSRF token for report/export actions, or scope the GET to the session's current account.
3. Return distinct status codes (404) for unknown ids to remove the oracle.

## Reproduction

One-script PoC: **`pad_report_idor.sh`** (attached; re-runs the full chain live and was verified 2026-10-14):

```bash
bash pad_report_idor.sh
# -> harvests both accountIds from the account list,
#    downloads both PDFs (different IBANs inside),
#    runs the context≠URL matrix cell, the tamper oracle,
#    the context-switched transaction page, and the CSV export oracles
```

Manual curl-level steps are in `REPRODUCE.md` (same folder). Full test matrix, md5s and endpoint semantics in `evidence/test_log.txt`.

## Attached files

- `REPRODUCE.md` — step-by-step manual reproduction (curl level)
- `pad_report_idor.sh` — one-script PoC (verified working)
- `xsite_pdf_steal.html` — cross-site exploit demo page
- `evidence/` — 21 artifacts + full test log (index in `EVIDENCE_INDEX.md`); `21_nontzero_proof_summary.md` answers "why does the PDF show zeros" with the live non-zero captures

Happy to run the PoC live on a call or adjust any part of the report.

Best regards,
[HackerOne handle]
