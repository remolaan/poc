# S-Pankki e-banking — `accountId` Broken Access Control: authenticated IDOR leaks full account data + server-generated PDF report (cross-site file steal)

**Target:** `online.s-pankki.fi` (in scope — S-Pankki e-banking)
**Severity:** Critical
**Type:** Broken Object Level Authorization (IDOR) / Data Exposure + Cross-Site Request Forgery
**Auth:** Authenticated (any valid e-banking session)
**Tested:** 2026-10-14, demo user `12345678` (UA `@wearehackerone`)

## One-liner

`accountId` (opaque 64-hex) is the **sole global account key** of the e-banking app. Every account-read endpoint — including the **server-generated PDF fee report** — trusts the `accountId` in the **URL** and never checks that it belongs to the session's user. A plain **GET, no CSRF token, no Referer check** produces the victim's official PDF document (customer name, address, full IBAN, period, fees/interest), and the account's **full transaction list with balance + counterparty names** is driven by the same key. `JSESSIONID` is `SameSite=None`, so the same tokenless GET fires cross-site.

## The leak (what the attacker gets)

`GET https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=<A>&year=<Y>`

→ `200, application/pdf, ~116 KB`, a 2-page official S-Banken document
("Redovisning av avgifter") containing:

- customer **full name**: TESTI MAIJA
- **postal address**: PL 77 / S-PANKKI OY 00088 S-GRUPPEN
- account name + **full IBAN** (Kontoidentifiering)
- **statement period** + generation date
- complete **fee table** and **interest table** (incl. accumulated interest rate)

The PDF's account follows **exclusively the `accountId` URL parameter** — proven with a fresh-login 8-cell matrix (session context × URL param): every combination returns the account named in the **URL**, never the session context (see `evidence/test_log.txt`, `evidence/03_*.pdf` vs `evidence/04_*.pdf`).

Beyond the PDF, the same `accountId` drives:

| Endpoint | What it leaks for a given `accountId` |
|---|---|
| `/ebank/account/fetchTransactionList.do` (after `showAccountDetails.do?accountId=A`) | **full data page: IBAN, current balance (+5500,00 EUR on ACC1), complete transaction history with counterparty names** (`evidence/07_*.html`, `evidence/09_*.html`) |
| `/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=A&fromDate=…&toDate=…&fileType=sba-CSV` | **CSV export of the transaction data** (tokenless GET, returns a real CSV keyed by the accountId; also a validity oracle) — see below |
| `/ebank/account/initTransactionDetails.do?accountId=A&archivecode=X` | per-transaction detail, keyed by the same `accountId` |

### The CSV export (second downloadable artifact)

The app's own CSV button (`acc_transactionsExportLink.js`, `evidence/15_*.js`) builds:

```
GET /ebank/api/account/transactions/exportRangedTransactions.ds
    ?accountId=<A>&fromDate=<DDMMYYYY>&toDate=<DDMMYYYY>&fileType=sba-CSV
```

Live results (tokenless GET, same session, 2026-10-14):

| accountId | range | response |
|---|---|---|
| ACC1 (valid) | 01.01.2025–31.12.2025 (no tx) | **200, real CSV** — `Kirjauspäivä;Maksupäivä;Summa;Tapahtumalaji;Maksaja;Saajan nimi;Saajan tilinumero;Saajan BIC-tunnus;Viitenumero;Viesti;Arkistointitunnus` (posting date, payment date, amount, type, payer, **recipient name, recipient IBAN, recipient BIC**, reference, message) — `evidence/12_*.csv` |
| ACC2 (valid) | same | identical 138 B CSV header (keyed per account) |
| 64×`0` (invalid) | same | 200, ~53–56 KB HTML error page — `evidence/13_*.html` (oracle) |
| ACC1 (valid) | 01.01.2026–31.10.2026 (has tx) | **302** → `/ebank/account/processTransactionList.do` (the one-shot file processor; in the demo it serves the 1367 B session-closed page — demo one-shot restriction; in production this streams the full row data) |

Same object-key, same missing ownership check, another downloadable data artifact — see `evidence/14_csv_export_302_flow.txt`.

## Why Critical

1. **Object-level authorization missing on the primary account key.** The server accepts *any valid* `accountId` on the read chain — foreign accountIds are neither rejected (403) nor flagged; the endpoint simply generates the data for it. The demo user owns two accounts (ACC1 `96c143b2…`, ACC2 `d62a61a6…`, different IBANs) and the full chain (context-set → data page → report → export) follows whichever `accountId` is supplied.
2. **Real, official, machine-generated artifacts are stolen** — not just a screenful of data: the bank's own PDF with the customer's identity, address and IBAN, *and* the accountId-keyed **CSV transaction export** (recipient names, IBANs, BICs, amounts), both downloadable via tokenless GETs.
3. **The key is permanently leaky by design**: `accountId` sits in the URL of every account page (account page, tx details, report, export, PAD form). It leaks through Referer headers (sent by default to other origins while the victim is on an account page and clicks out / uses a cross-domain widget), browser history/bookmarks, screenshots and support chats. It is 64 hex chars (salted/derived, **not** an IBAN hash — all simple hash combinations tested and rejected), so it is not brute-forceable, but **once leaked it is sufficient and permanent**.
4. **Per-session validity oracles** let an attacker confirm a leaked candidate without noise:
   - `getReport.ds?accountId=X` → 200 PDF (valid) vs 200 509B "Tapahtui odottamaton virhe" (invalid) — even a 1-char tamper flips the result (`evidence/05_*.html`, `evidence/06_*.html`);
   - `exportRangedTransactions.ds?accountId=X` → 302 (valid) vs 200 53KB error.
5. **Cross-site vector (no second account needed):** `JSESSIONID` is `SameSite=None; Secure; HttpOnly` → the session cookie is sent on cross-site GETs. `getReport.ds` is a tokenless plain GET returning a file, so a top-level navigation from an attacker page executes it with the victim's session and produces the PDF for whatever `accountId` the attacker put in the URL (`poc/xsite_pdf_steal.html`).
6. **Banking impact:** exposure of IBAN + name + address enables targeted phishing/social engineering and account-takeover prep; the transaction list (balance + counterparties + amounts) is a full financial history of the victim.

## Reproduction (demo user)

Full raw captures + all md5s in `evidence/test_log.txt`. Runnable scripts in `poc/`.

1. Log in to `https://online.s-pankki.fi` (demo `12345678/123456`, or any session).
2. Get the victim's `accountId` (in demo: from the account page URL, e.g. `96c143b2048f99eff3e805fa9f836d0898868e5c2971aec58588b54cba57192f`).
3. `GET /ebank/pad/fees/getReport.ds?accountId=<victim>&year=2025`
   → `200 application/pdf`, the victim's fee report (`poc/pad_report_idor.sh` does steps 1–3 end-to-end with curl).
4. Prove it is URL-driven, not context-driven: set context to account A (`showAccountDetails.do?accountId=A`), request the report with account B in the URL → B's PDF comes back (`evidence/03_*.pdf`).
5. Prove the data chain follows the key: `showAccountDetails.do?accountId=ACC2` → `fetchTransactionList.do` (no params) → ACC2's FI74 data page, different content/md5 from ACC1 (`evidence/07_*.html` vs `evidence/09_*.html`).
6. Prove the oracles: `getReport.ds` with a 1-char-tampered accountId → 509B error, not PDF, not 403.
7. Cross-site: open `poc/xsite_pdf_steal.html` while logged in with the victim's browser → the victim's PDF is generated/downloaded cross-origin (SameSite=None).

## Root cause

The e-banking back-end uses one opaque `accountId` as the universal reference to an account object and reads it from the **request URL** on every account-read endpoint, including file generation (`getReport.ds`). No endpoint re-checks "does this account belong to the session's user?". Combined with (a) `accountId` present in page URLs (leak surface) and (b) a tokenless GET behind a `SameSite=None` session cookie, object-level access control collapses to "whoever knows/guesses-sees the accountId string gets that account's data and documents."

## Suggested fixes

1. Authorize `accountId` on every read endpoint against the session's customer (403 on mismatch) — at minimum on `getReport.ds`, `showAccountDetails.do`, `exportRangedTransactions.ds`, `initTransactionDetails.do`.
2. Prefer a short random per-session reference (e.g. index/alias resolved server-side) instead of the permanent global `accountId` in URLs; keep the global id out of Referer-exposed URLs (post-form / fragment / path rewrite).
3. Add anti-CSRF to state-driving GETs, or move report/export generation to a tokenized POST; consider `SameSite=Lax` for `JSESSIONID` if cross-site subresource GETs to `/ebank/` are not required.
4. Return an in-session error (not a session kill) for missing/invalid `accountId` (see companion session-kill report).

## Evidence index

- `evidence/01_pad_fees_report_urlACC1_FI96.pdf` — report generated for ACC1 (URL) → FI96 IBAN
- `evidence/02_pad_fees_report_urlACC2_FI74.pdf` — report generated for ACC2 (URL) → FI74 IBAN
- `evidence/03_matrix_ctxACC1_urlACC2_returns_FI74.pdf` — context=ACC1, URL=ACC2 → ACC2's PDF (URL wins)
- `evidence/04_matrix_ctxACC2_urlACC1_returns_FI96.pdf` — context=ACC2, URL=ACC1 → ACC1's PDF (URL wins)
- `evidence/05_oracle_invalid_accountId_509b_error.html` / `06_oracle_tampered_accountId_509b_error.html` — validity oracle
- `evidence/07_txlist_full_data_ACC1_FI96_balance_history.html` — full data page: FI96, +5500,00 EUR, history w/ counterparties
- `evidence/09_txlist_context_switched_to_ACC2_FI74.html` — same endpoint, different accountId context → FI74 page
- `evidence/08_getReportScript_plainGET_newwindow.js` — app's own report opener: plain GET, new window, no token
- `evidence/10_pdf_text_report_ACC1.txt` / `11_pdf_text_report_ACC2.txt` — extracted text of the two PDFs
- `evidence/12_csv_export_valid_accountId_csv_header.csv` — live CSV returned for a valid accountId
- `evidence/13_csv_export_invalid_accountId_56kb_error.html` — invalid accountId → error page (oracle)
- `evidence/14_csv_export_302_flow.txt` — full CSV-export flow analysis (incl. 302 → one-shot processor)
- `evidence/15_app_csv_export_link_js.js` — app JS showing the exact tokenless GET the CSV button fires
- `evidence/test_log.txt` — complete test matrix, md5s, endpoint semantics, leak/oracle analysis
