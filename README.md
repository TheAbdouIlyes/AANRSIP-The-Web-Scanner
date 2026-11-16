# AANRSIP - Adaptive Network Reconnaissance & Service Investigation Platform

Flask + Python scanning platform for **explicitly authorised laboratory networks**. It does more than run nmap:
it enumerates ports independent of defaults, identifies services by *behaviour*, validates banners against
observed protocol responses, adapts its investigations to earlier results (and records *why*), and backs off when it
sees signs of rate limiting or blocking. It never evades blocks.

## Layout
```
app/            Flask: auth, CSRF, security headers, pages (templates/static), JSON API (routes/api.py)
scanner/        Engine, independent of Flask
  validation.py          allowlist + whitelist config validation (the only door for user input)
  discovery/             nmap runner (argument arrays, XML parsing) + built-in connect/UDP scanner
  protocols/probes.py    banner/HTTP/TLS/UDP probes
  fingerprinting/        claim-vs-behaviour validator, decoy indicators
  investigation/         investigator registry: each step has an applicability rule and a logged reason
  adaptive/              scan protection (rate-limit / blocking assessment) + throttle
  engine.py, manager.py  scan runner (pause/cancel/checkpoint/resume) and lifecycle manager
  reporting/             report builder (JSON/CSV/PDF), scan comparison
  storage.py             SQLite persistence (plain SQL; PostgreSQL later = swap this module)
tests/          unit + integration tests; tests/mock_lab.py simulates the defender network
```

## Install - Arch Linux
```
sudo pacman -S --needed python python-pip nmap
cd network_scanner
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests -q          # everything should pass, no external network needed
SCANNER_ALLOWED="192.168.56.0/24" python run.py     # http://127.0.0.1:5000
```
Optional SYN/OS detection: see `docs/PERMISSIONS.md`.

## Scanning from Kali Linux
Option A - run the platform on Kali (simplest; Kali ships nmap):
```
sudo apt install -y nmap python3-venv && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
SCANNER_ALLOWED="<lab CIDR>" python run.py
```
Option B - platform on Arch, scans launched from Kali: bind to the lab-facing address with a token, open it from Kali's browser:
```
SCANNER_TOKEN="$(openssl rand -hex 24)" SCANNER_BIND=<arch-ip> SCANNER_ALLOWED="<lab CIDR>" python run.py
```
(`run.py` refuses a non-loopback bind without `SCANNER_TOKEN`.) The scan runs **from the machine running the platform** - that is
the vantage point; use the "Vantage label" field so scans from different locations can be compared (segmentation).

## Try it without a lab
```
python scripts/run_mock_lab.py        # prints random ports for: HTTP, SSH-banner-that-speaks-HTTP, decoy, rate-limited, UDP, knock
```
Scan `127.0.0.1` with TCP ports `all` (and UDP on the printed UDP port). Add the printed knock sequence + `protected` port to see before/after.

## Safety model
* Targets must be literal IPs/CIDRs inside the allowlist; hostnames, public IPs and ranges > 256 addresses are rejected server-side. Scope is re-checked on resume.
* No shell: nmap is invoked with an argument array and a hard timeout; all options are whitelisted/bounded.
* CSRF token on every state-changing request; token login (and refusal to serve non-local clients without a token); CSP, `nosniff`, `X-Frame-Options`; all scan output is rendered with `textContent`; CSV exports neutralise formula injection; security events go to `logs/security.log`.
* Knock sequences and source ports are **operator-supplied and replayed once** (max 16 / 5). No guessing, no spoofing, no IP rotation, no evasion.

## How findings are graded
Verdicts: `confirmed`, `probable`, `unknown`, `inconsistent`, `potential_decoy`. Findings carry a category: **observed** (fact), **probable** (best explanation), **hypothesis** (unconfirmed). "Potential decoy" needs concrete indicators (identical bytes for different probes, several unrelated protocols, a banner reused across services) and is a hypothesis unless two agree.

## Known limitations
See the final section of the generated report and the notes delivered with this project; short list: SYN/OS need privileges; UDP default is a common-port list (full UDP is possible but slow); "blocking confirmed" is behavioural, never proof; IPv6 is supported but was only unit-tested; the front end has not been exercised in a real browser by the author.
