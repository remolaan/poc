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
| 5 | any of the above with an invalid `accountId` | HTTP 200 + 509 B HTML error page ("Tapahtui odottamaton virhe") — **validity oracle** (200, not 4xx/5xx, distinct from the PDF) |

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
2. `GET /ebank/account/showAccountDetails.do?accountId=<stolen>` then `GET /ebank/account/fetchTransactionList.do` → victim's full transaction/balance data page
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
- `evidence/` — 15 artifacts + full test log (index in `EVIDENCE_INDEX.md`)

Happy to run the PoC live on a call or adjust any part of the report.

Best regards,
[HackerOne handle]
