import subprocess, concurrent.futures as cf, json, re

PROVIDERS = {
 "heroku":   r"herokudns\.com$|herokuapp\.com$",
 "s3":       r"s3\.amazonaws\.com$|s3-website\.[a-z0-9-]+\.amazonaws\.com$|s3\.[a-z0-9-]+\.amazonaws\.com$",
 "github":   r"github\.io$|github\.com$",
 "bitbucket":r"bitbucket\.(io|org)$",
 "netlify":  r"netlify\.(app|com)$",
 "ghost":    r"ghost\.io$",
 "azure":    r"azurewebsites\.net$|cloudapp\.net$|core\.windows\.net$|trafficmanager\.net$|z\d\.web\.core\.windows\.net$",
 "fastly":   r"fastly\.net$|f\.fastly\.net$",
 "cloudfront":r"cloudfront\.net$",
 "vercel":   r"vercel\.app$|now\.sh$",
 "fly":      r"fly\.dev$",
 "render":   r"onrender\.com$|\.render\.com$",
 "shopify":  r"myshopify\.com$",
 "pantheon": r"pantheonsite\.io$|getpantheon\.com$",
 "cloudways":r"cloudways\.in$",
 "acquia":   r"acquia-sites\.com$",
}

def dig(host, typ):
    try:
        out = subprocess.run(["dig","+short","CNAME" if typ=="CNAME" else "A", host],
                             capture_output=True,text=True,timeout=12).stdout.strip()
        return out
    except Exception:
        return ""

def resolve(t):
    cname = dig(t,"CNAME")          # last CNAME target
    a = dig(t,"A")
    # full cname chain for reporting
    chain = subprocess.run(["dig","+short","CNAME",t],capture_output=True,text=True,timeout=12).stdout.split()
    res={"target":t,"a":a.split(),
         "cname":cname.split(),
         "nx":("NXDOMAIN" in subprocess.run(["dig","+noall","+answer","A",t],capture_output=True,text=True,timeout=12).stdout)}
    prov=None
    for line in res["cname"]+res["a"]:
        for name,pat in PROVIDERS.items():
            if re.search(pat,line): prov=name
    res["provider"]=prov
    return res

targets=[l.strip() for l in open("targets_all.txt") if l.strip() and "." in l]
print("scanning",len(targets))
out=[]
with cf.ThreadPoolExecutor(max_workers=16) as ex:
    for r in ex.map(resolve,targets):
        out.append(r)
json.dump(out,open("scan_results.json","w"))

live=[r for r in out if r["a"] or r["cname"]]
nxd=[r for r in out if r["nx"] and not r["a"]]
cn=[r for r in out if r["cname"]]
prov=[r for r in out if r["provider"]]
print("live",len(live),"| cx(nxdomain)",len(nxd),"| with CNAME",len(cn),"| provider-CNAME",len(prov))
print("\n=== CNAME / provider flags (takeover candidates) ===")
for r in cn:
    tag=" <== "+r["provider"].upper() if r["provider"] else ""
    print(f"{r['target']:45} CNAME->{r['cname']} A={r['a'][:2]}{tag}")
print("\n=== provider-CNAME summary ===")
for r in prov:
    print(f"  [{r['provider']:12}] {r['target']} -> {r['cname']}")
open("live_targets.txt","w").write("\n".join(sorted(r["target"] for r in live)))
