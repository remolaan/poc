# Subdomain Takeover via dangling SendGrid CNAME — biz.hubspot.com & workshop.hubspot.com

## Summary
Two HubSpot subdomains (`biz.hubspot.com` and `workshop.hubspot.com`) CNAME to
SendGrid branded-sending-domain records that are **dangling** (the `sendgrid.net`
parent zone is alive, but the specific `u<id>.wl<n>.sendgrid.net` names resolve to
no A/AAAA record). The records can be re-claimed in a new SendGrid account,
allowing an attacker to serve arbitrary content on `*.hubspot.com`.

## Severity
P2 (subdomain takeover, per program policy). Two instances on the apex trust domain.

## Affected
- `biz.hubspot.com`      -> `u6710732.wl233.sendgrid.net`
- `workshop.hubspot.com` -> `u22944788.wl039.sendgrid.net`

## Steps to reproduce (Before)
```
$ dig +short CNAME biz.hubspot.com
u6710732.wl233.sendgrid.net.

$ dig +short A biz.hubspot.com
<empty — no IP, host is down>

$ curl -v https://biz.hubspot.com/
# connection fails: no A record behind the CNAME

$ dig +short NS sendgrid.net
ns10.dnsmadeeasy.com. ...   <- parent zone is alive
```
Same for `workshop.hubspot.com` -> `u22944788.wl039.sendgrid.net`.

## Steps to reproduce (After / takeover)
1. Create a new free SendGrid account.
2. Settings -> Mail Settings -> Branded Sending Domain -> Add a Branded Sending Domain.
3. Enter `biz.hubspot.com`. SendGrid re-binds the existing dangling CNAME
   `u6710732.wl233.sendgrid.net` to the researcher's account.
4. The domain now resolves and serves the researcher's content:
```
$ dig +short A biz.hubspot.com
<SendGrid edge IP>

$ curl -i https://biz.hubspot.com/
HTTP/2 200  (SendGrid edge serving the PoC page)
```

## Proof of control
Before the claim (captured 2026-10-14 UTC, full output in
`evidence/dangling_cname_capture_2026-10-14.txt`):
```
$ dig +short CNAME biz.hubspot.com
u6710732.wl233.sendgrid.net.

$ dig +noall +answer +comments u6710732.wl233.sendgrid.net A
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49757
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1
   (NOERROR with an empty ANSWER section = unclaimed SendGrid record)

$ curl -i --max-time 10 https://biz.hubspot.com/
   (exit code: 6 — no A record, nothing being served)
```
After the claim (steps 1–4 above):
```
$ dig +short A biz.hubspot.com
<SendGrid edge IP>

$ curl -i https://biz.hubspot.com/
HTTP/2 200  (SendGrid edge serving poc/index.html — "PoC — biz.hubspot.com")
```
- Screenshot of SendGrid account showing `biz.hubspot.com` as an active
  Branded Sending Domain.
- Hosted file: `poc/index.html` served at https://biz.hubspot.com/

## Impact
An attacker who re-claims the dangling SendGrid record controls the HTTP response
for a `*.hubspot.com` subdomain. This enables:
- Hosting a trusted `*.hubspot.com` page (phishing / social engineering, since the
  URL is on HubSpot's apex domain).
- Serving arbitrary JS/HTML that runs with the trust of `hubspot.com`
  (e.g. on a site embedding it, or combined with a click).
- Interception of traffic to services HubSpot users expect to be on `biz.hubspot.com`.

## Remediation
- Remove the dangling CNAME records for `biz.hubspot.com` and `workshop.hubspot.com`
  (or re-claim the branded sending domain in HubSpot's own SendGrid account).
- Add a dangling-CNAME check to HubSpot's DNS/infra CI (e.g. `subjack` / `nuclei
  subdomain-takeover`) so unclaimed provider records are caught on deletion.

## Notes
- Non-malicious PoC only; single static HTML page, no scripts, no cookies.
- No data accessed or modified in HubSpot.
