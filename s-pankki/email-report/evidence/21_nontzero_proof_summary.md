# Why the PDF shows zero — and the non-zero proof of leaked data

Prepared 2026-10-14, all artifacts captured live on `online.s-pankki.fi` (program test account, UA `@wearehackerone`).

## 1. Why the fees PDF shows 0,00 everywhere

`getReport.ds` returns the **PAD fee statement** — in the bank's own Swedish text: *"Redovisning av avgifter"* ("fee accounting"). It is a **fee/interest statement, not a balance or transaction statement**. The statement itself says so: the balance and transactions are in the separate account statement (*kontoutdrag*).

The demo customer (TESTI MAIJA MEIKÄINEN) has a basic account **with no paid fee package**, so every fee/interest row for a completed year is legitimately `0,00`:

| Probe | Result |
|-------|--------|
| `year=2025` | 116,300 B PDF — all rows 0,00 (evidence `01/02`) |
| `year=2024` | 116,299 B PDF — **also** all rows 0,00 (evidence `19`) |
| `year=2026` (year not finished) | 56,644 B **HTML** demo page, not a PDF (evidence `20`) — the report only exists for finished years |
| invalid `accountId` | 509 B HTML error (validity oracle, evidence `05/06`) |

The 2024 PDF additionally contains a genuine backend data row (range "01.01.2025 – 22.05.2017", interest 0,0100 %, amount 0,00) — i.e. the statement carries real per-customer rows; the amounts are zero because **zero fees were charged**, not because the document is empty or the account fake.

**Zero in this document type ≠ empty account.** The account's money is visible on the other, non-zero artifacts below.

## 2. Non-zero proof of real customer data

### 2a. Live server-rendered balances (front page) — evidence `16`

The post-login overview page (*Verkkopankin yhteenveto*, 68,139 B) server-renders:

| Account | Holder | Balance |
|---------|--------|---------|
| FI96 3939 0001 0006 03 (ACC1) | MAIJA MEIKÄLÄINEN | **+5 500,00** |
| FI74 3939 0001 0006 11 (ACC2) | MAIJA MEIKÄLÄINEN | **+5 500,00** |
| Yhteensä (total) | | **+11 000,00** |

Plus card `4318 12** **** 9012` (S-Etukortti Visa Credit/Debit) with balance **6 098,52** and a card row of 1,00.

### 2b. Context-switched transaction data page — real non-zero transactions with counterparty names

After `GET /ebank/accountview/showAccountDetails.do?accountId=<A>` (plain GET, no CSRF token), the parameterless `GET /ebank/account/fetchTransactionList.do` returns the **account A's full transaction page**. Fresh captures 2026-10-14, single session, both accounts, different md5s and different data:

**ACC1 (FI96 …03) — 75,316 B page, 9 non-zero transactions (evidence `17`):**

| Date | Amount (EUR) | Type | Counterparty |
|------|-------------|------|--------------|
| 9.10.2026 | −500,00 | OMA TILISIIRTO | MAIJA MEIKÄINEN |
| 8.10.2026 | +50,00 | TILISIIRTO | MINNI MEIKÄINEN |
| 7.10.2026 | −100,50 | TILISIIRTO | MATTI MEIKÄINEN |
| 7.10.2026 | −21,00 | KORTTIOSTO | OSUUSKAUPPA SUOMI |
| 6.10.2026 | −11,00 | KORTTIOSTO | MODERN LIVING |
| 2.10.2026 | −50,00 | TILISIIRTO | MINNI MEIKÄINEN |
| 1.10.2026 | −110,00 | KORTTIOSTO | ELÄINKAUPPA HOPE |
| 30.9.2026 | +105,45 | LAPSILISÄ | KELA/LAPSILISÄT |
| 30.9.2026 | −130,00 | KORTTIOSTO | HUONEKALULIIKE JAKKARA |

**ACC2 (FI74 …11) — 81,368 B page, 15 non-zero transactions, all 9.10.2026 (evidence `18`):**

| Amount (EUR) | Type | Counterparty |
|-------------|------|--------------|
| −500,00 | OMA TILISIIRTO | MAIJA MEIKÄINEN |
| −50,00 | TILISIIRTO | MINNI MEIKÄINEN |
| −100,00 | TILISIIRTO | MAIJA MEIKÄINEN |
| −250,00 | TILISIIRTO | MAIJA MEIKÄINEN |
| −74,20 | TILISIIRTO | OSUUSKAUPPA SUOMI |
| −18,65 | PALKKA | Sokos verkkokauppa |
| −105,45 | LAPSILISÄ | KELA/LAPSILISÄT |
| −130,00 | KORTTIOSTO | HUONEKALULIIKE JAKKARA |
| −110,00 | KORTTIOSTO | ELÄINKAUPPA HOPE |
| −50,00 | TILISIIRTO | MINNI MEIKÄINEN |
| −11,00 | KORTTIOSTO | MODERN LIVING |
| −100,50 | TILISIIRTO | MATTI MEIKÄINEN |
| −21,00 | KORTTIOSTO | OSUUSKAUPPA SUOMI |
| −74,20 | TILISIIRTO | OSUUSKAUPPA SUOMI |
| −100,00 | VUOKRANMAKSU | MAIJA MEIKÄINEN |

The two pages have **different sizes (75,316 B vs 81,368 B), different md5s and different row sets** — the page really is keyed to the opaque `accountId`, and it carries real amounts + counterparty names (retailers KELA, Sokos, Osuuskauppa Suomi, Modern Living, Eläinkauppa Hope, Huonekaluliike Jakkara).

### 2c. CSV export confirms data exists in 2026 (the year the PDF does not cover)

- range 01012026–31102026 → **302** to one-shot `processTransactionList.do` = rows exist in range (evidence `14`)
- range 01012025–31122025 → 200 with **header-only CSV** = no 2025 activity (evidence `12`) — consistent: all demo account activity is 2026, while the fee statement (which covers 2024/2025) shows zero fees

## 3. Third URL-driven endpoint found while verifying: per-transaction detail

The transaction page links every row to:

```
/ebank/account/initTransactionDetails.do?backLink=reset&accountId=<A>&rowNo=<N>&type=trans&archivecode=<per-tx code>
```

Plain GET, 64-hex `accountId` + per-transaction `archivecode` in the URL, no CSRF token. On the demo profile the detail table is hidden behind onboarding ("Tutustuessasi palveluun et voi katsoa tapahtumaerittelyä") — in production the same endpoint renders the full transaction breakdown (reference, message, counterparty account). Same ownership-check gap as the other endpoints.

## 4. Operational notes (demo behavior, 2026-10-14)

- `accountview/showAccountDetails.do?accountId=<A>` (the link the front page itself uses) is the **reliable** context setter: 200 + 56,437 B shell, no side effects.
- `account/showAccountDetails.do?accountId=<A>` (the link in the account list) intermittently kills the session (1,361 B "Verkkopankin yhteys on suljettu" + `JSESSIONID Max-Age=0`) — separate session-kill finding, reported alongside.
- `fetchTransactionList.do?accountId=<A>&tab=tab1` — the direct `accountId` param is **ignored**: response is byte-identical (same md5) to the last session-context account's page. Context, not the param, drives the data — same root cause as the PDF endpoint (no ownership check), just via session state instead of the URL.
