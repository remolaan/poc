# Evidence Index — S-Pankki accountId IDOR (Critical)

All artifacts captured 2026-10-14 against `online.s-pankki.fi` (program test account, UA `@wearehackerone`). Full test matrix, md5s and endpoint semantics: `test_log.txt`.

## PDF report IDOR (headline)

| File | Size | What it shows |
|------|------|---------------|
| `01_pad_fees_report_urlACC1_FI96.pdf` | 116,300 B | Official PAD fee report for ACC1 — IBAN FI96 3939 0001 0006 03 inside |
| `02_pad_fees_report_urlACC2_FI74.pdf` | 116,300 B | Same endpoint, URL accountId=ACC2 — IBAN FI74 3939 0001 0006 11 inside |
| `03_matrix_ctxACC1_urlACC2_returns_FI74.pdf` | 116,300 B | **Definitive IDOR cell**: session context = ACC1, URL = ACC2 → PDF contains ACC2's IBAN |
| `04_matrix_ctxACC2_urlACC1_returns_FI96.pdf` | 116,300 B | Reverse matrix cell |
| `05_oracle_invalid_accountId_509b_error.html` | 509 B | Invalid accountId → HTTP 200 + 509 B HTML error (validity oracle, not 4xx/5xx) |
| `06_oracle_tampered_accountId_509b_error.html` | 509 B | 1-char-tampered real id → same 509 B error (oracle confirms per-id validation) |
| `07_txlist_full_data_ACC1_FI96_balance_history.html` | 75,316 B | Full transaction data page for ACC1 (context-driven) |
| `08_getReportScript_plainGET_newwindow.js` | 601 B | Bank's own JS: report is opened as a plain GET in a new window (no CSRF token) |
| `09_txlist_context_switched_to_ACC2_FI74.html` | 81,368 B | After `showAccountDetails.do?accountId=ACC2`, the parameterless `fetchTransactionList.do` returns ACC2's data (FI74) — context fully driven by the opaque id |
| `10_pdf_text_report_ACC1.txt` | 1,518 B | Extracted text of PDF #01 (customer name, address, IBAN, period, interest) |
| `11_pdf_text_report_ACC2.txt` | 1,518 B | Extracted text of PDF #02 |

## CSV transaction export (second downloadable artifact)

| File | Size | What it shows |
|------|------|---------------|
| `12_csv_export_valid_accountId_csv_header.csv` | 145 B | Live CSV returned for a valid accountId — header incl. recipient name, IBAN, BIC, amount, message columns |
| `13_csv_export_invalid_accountId_56kb_error.html` | 56,692 B | Invalid accountId on the CSV endpoint → error page (second oracle surface) |
| `14_csv_export_302_flow.txt` | 1,905 B | Full 302 → `processTransactionList.do` flow for a data-bearing range (demo one-shot restriction documented) |
| `15_app_csv_export_link_js.js` | 2,746 B | Bank's own JS building the tokenless CSV export GET (exact URL/params) |

## Logs & PoC

| File | What it is |
|------|-----------|
| `test_log.txt` | Complete test matrix: 8-cell fresh-login matrix, md5s, endpoint semantics, oracle analysis, demo-blocked endpoints |
| `pad_report_idor.sh` | One-script PoC — login → harvest ids → dual PDF → matrix cell → tamper oracle → context-switched txlist → CSV oracles (verified working 2026-10-14) |
| `xsite_pdf_steal.html` | Cross-site demo: top-level navigation to `getReport.ds` (cookie is `SameSite=None; Secure; HttpOnly`) |
