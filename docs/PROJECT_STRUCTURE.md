# Network Scanner Project Structure

## 1. Project Purpose

This project is a Flask-based network reconnaissance and service investigation platform for authorized laboratory networks.

It combines:

- A web interface for starting and monitoring scans.
- A JSON API for scan control and report access.
- An nmap backend for advanced discovery and fingerprinting.
- A built-in Python scanner as a fallback.
- Protocol-specific service investigation.
- Adaptive detection of rate limiting and temporary blocking.
- SQLite persistence, checkpoints, findings, and reports.

The scanner is designed for explicitly authorized lab targets only.

## 2. Top-Level Layout

```text
network_scanner/
|
|-- run.py                         Application entry point
|-- config.example.py              Environment variable reference
|-- requirements.txt               Python dependencies
|-- README.md                      Quick-start documentation
|
|-- app/                           Flask web application
|   |-- __init__.py                Flask factory and security middleware
|   |-- routes/
|   |   |-- api.py                 JSON API endpoints
|   |   |-- auth.py                Login and token authentication
|   |   |-- pages.py               HTML page routes
|   |   `-- __init__.py
|   |-- static/
|   |   |-- app.js                 Browser behavior and API calls
|   |   `-- style.css              Web interface styles
|   `-- templates/                 Jinja HTML templates
|       |-- base.html              Shared page layout
|       |-- dashboard.html         Scan summary dashboard
|       |-- history.html            Previous scans
|       |-- host.html               Host details
|       |-- live.html               Live scan progress
|       |-- login.html              Login page
|       |-- new_scan.html           Scan configuration form
|       |-- report.html             Generated report page
|       `-- service.html            Service details
|
|-- scanner/                       Scanner engine
|   |-- config.py                  nmap path, database path, privilege flags
|   |-- engine.py                  ScanRunner thread and scan lifecycle
|   |-- manager.py                 Scan creation, limits, resume, and controls
|   |-- storage.py                 SQLite persistence layer
|   |-- validation.py              Target and configuration validation
|   |-- adaptive/
|   |   `-- protection.py           Rate-limit/block assessment and throttling
|   |-- discovery/
|   |   |-- builtin.py              TCP and UDP socket scanner
|   |   `-- nmap_runner.py          Safe nmap command construction and XML parsing
|   |-- fingerprinting/
|   |   `-- validator.py             Claimed service versus observed behavior
|   |-- investigation/
|   |   `-- engine.py                Investigation module registry and execution
|   |-- protocols/
|   |   `-- probes.py                Banner, HTTP, TLS, DNS, and protocol probes
|   |-- reporting/
|   |   |-- compare.py               Compare two scan results
|   |   `-- report.py                JSON, CSV, and PDF reports
|   `-- __init__.py
|
|-- tests/                          Automated tests
|   |-- conftest.py                 Shared fixtures
|   |-- mock_lab.py                 Local dummy services and defenses
|   |-- test_api.py                 Flask/API tests
|   |-- test_fingerprint.py         Fingerprint validation tests
|   |-- test_integration.py         End-to-end scanner tests
|   |-- test_nmap_parse.py          nmap XML and argument tests
|   |-- test_protection.py          Blocking and rate-limit tests
|   |-- test_validation.py           Scope and configuration tests
|   `-- __init__.py
|
|-- docs/
|   |-- ARCHITECTURE.md             Short runtime data-flow summary
|   |-- PERMISSIONS.md              nmap capability and privilege model
|   `-- PROJECT_STRUCTURE.md        This document
|
|-- config/                         Runtime configuration data
|-- database/                       SQLite database files
|-- logs/                           Application and security logs
`-- scripts/
    `-- run_mock_lab.py             Start the local mock laboratory
```

## 3. Application Startup

The application starts through `run.py`:

```text
run.py
  -> app.create_app()
      -> Flask configuration
      -> SQLite storage
      -> ScanManager
      -> API, page, and authentication routes
```

The server defaults to:

```text
http://127.0.0.1:5000
```

The Flask application should run as an unprivileged user. nmap receives narrowly scoped Linux capabilities when SYN scans, UDP scans, or OS detection are required.

## 4. Scan Request Flow

```text
Browser form
    |
    v
POST /api/scans
    |
    v
ScanManager.start()
    |
    +--> validate_config()
    |
    +--> parse_target()
    |
    +--> create scan record in SQLite
    |
    `--> start ScanRunner thread
              |
              v
          discovery
              |
              v
          TCP/UDP enumeration
              |
              v
          adaptive protection checks
              |
              v
          service investigation
              |
              v
          fingerprint validation
              |
              v
          findings and reports
```

## 5. Main Scanner Components

### `scanner/validation.py`

This is the input boundary for scan parameters.

It validates:

- Literal IP addresses and CIDR ranges.
- Membership in the authorized allowlist.
- Maximum target size.
- TCP and UDP port specifications.
- Timing, retry, timeout, and rate limits.
- Enabled investigation modules.
- HTTP paths and virtual hosts.
- Operator-supplied knock sequences.
- Operator-supplied source ports.

Hostnames and shell commands are not accepted as targets.

### `scanner/manager.py`

`ScanManager` owns scan lifecycle operations:

- Starts scans.
- Limits concurrent scans.
- Loads previous results for adaptive comparisons.
- Resumes interrupted scans.
- Pauses, unpauses, cancels, and releases blocking pauses.

### `scanner/engine.py`

`ScanRunner` executes one scan in a background thread.

For every host it:

1. Enumerates TCP ports.
2. Enumerates UDP ports when enabled.
3. Saves checkpoints after chunks.
4. Checks for rate limiting or blocking.
5. Investigates open services.
6. Runs optional port-knocking and source-port experiments.
7. Creates host and service findings.
8. Completes cross-host analysis.

Partial results are preserved when a scan is canceled, interrupted, or paused.

### `scanner/discovery/nmap_runner.py`

This module builds nmap arguments as a list and runs nmap with `shell=False`.

Supported features include:

- Host discovery.
- TCP connect scans.
- TCP SYN scans when privileges are available.
- UDP scans.
- Service detection with `-sV`.
- OS detection with `-O` when privileged nmap is enabled.
- IPv4 and IPv6.
- nmap XML output parsing.

### `scanner/discovery/builtin.py`

This is the pure-Python fallback scanner.

It uses sockets to identify:

- Open TCP ports.
- Closed TCP ports.
- Filtered TCP ports.
- Open UDP ports.
- UDP `open|filtered` ports.

It cannot perform raw-packet OS detection. OS detection therefore requires the nmap backend.

### `scanner/adaptive/protection.py`

This module records probe outcomes and looks for behavioral evidence of defenses.

It can identify signs of:

- Rate limiting.
- Connection resets.
- Ports changing from refused to timed out.
- Previously open services becoming unreachable.
- Temporary blocking.

When rate limiting is suspected, the scanner slows down. When blocking is suspected, the scanner pauses and requires operator action. It does not attempt stealth evasion.

### `scanner/investigation/engine.py`

This module decides which investigations apply to a discovered service and records the reason for each investigation.

Typical investigations include:

- Protocol identification.
- Banner collection.
- HTTP probing.
- TLS inspection.
- UDP protocol probes.
- Consistency checks.

### `scanner/protocols/probes.py`

This contains protocol-specific probes used to identify services that do not use standard ports.

Examples include:

- Generic TCP banners.
- HTTP requests and response metadata.
- TLS handshakes and certificate information.
- DNS and NTP UDP probes.

### `scanner/fingerprinting/validator.py`

This compares nmap claims, banners, and protocol behavior.

Possible verdicts include:

- `confirmed`
- `probable`
- `unknown`
- `inconsistent`
- `potential_decoy`

A service is not considered identified only because its port number is commonly associated with that service.

### `scanner/storage.py`

This module is the persistence boundary for SQLite.

It stores:

- Scan configuration and status.
- Hosts.
- Ports and states.
- Service fingerprints.
- Investigation results.
- Findings.
- Events and warnings.
- Raw nmap output.
- Checkpoints for resume support.

## 6. Web Application Components

### API routes

The API is under `/api`.

Important endpoints include:

```text
POST /api/scans                  Start a scan
GET  /api/scans                  List scans
GET  /api/scans/<id>              Scan status and summary
GET  /api/scans/<id>/ports        Port results
GET  /api/scans/<id>/events       Live event log
GET  /api/scans/<id>/findings     Findings and evidence
POST /api/scans/<id>/control      Pause, resume, or cancel
POST /api/scans/<id>/resume       Resume from checkpoint
GET  /api/scans/<id>/report       JSON report data
GET  /api/scans/<id>/report.json  Download JSON report
GET  /api/scans/<id>/report.csv   Download CSV report
GET  /api/scans/<id>/report.pdf   Download PDF report
```

### Browser client

`app/static/app.js`:

- Builds scan configuration from the form.
- Sends JSON requests to the API.
- Polls live scan status.
- Renders ports, findings, events, and reports.
- Uses `textContent` and DOM construction for scan output.

### Security middleware

`app/__init__.py` provides:

- CSRF protection for state-changing requests.
- Optional bearer-token authentication.
- Refusal of non-local clients when no token is configured.
- Security headers.
- Request size limits.
- Rotating security logs.

## 7. nmap Privilege Model

The scanner process itself should remain unprivileged.

On Arch Linux or Ryoku, configure nmap with capabilities once:

```fish
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip (readlink -f (which nmap))
```

Start the scanner with:

```fish
env SCANNER_ALLOWED='127.0.0.0/8,192.168.0.0/24' SCANNER_NMAP_PRIVILEGED=1 python run.py
```

The `SCANNER_NMAP_PRIVILEGED=1` flag permits the scanner to add privileged nmap options such as:

- `-sS` for SYN scanning.
- `-sU` for UDP scanning.
- `-O` for OS detection.

If OS detection is unavailable, verify all of the following:

1. The backend is `nmap`, not `builtin`.
2. OS detection is enabled in the scan form.
3. `SCANNER_NMAP_PRIVILEGED=1` was set before starting the server.
4. nmap has the required capabilities.
5. The target has reachable open and closed TCP ports.

## 8. Authorized Lab Scope

The current lab network is:

```text
192.168.0.0/24
```

Loopback is also enabled for local testing:

```text
127.0.0.0/8
```

The allowlist is read when the application starts. After changing `SCANNER_ALLOWED`, restart the server.

## 9. Mock Laboratory

The mock lab creates services with different behaviors for testing:

- HTTP on an unusual port.
- A misleading SSH-style service.
- A decoy service.
- A rate-limited service.
- A UDP service.
- A port-knocking protected service.

Start it with:

```bash
python scripts/run_mock_lab.py
```

The script prints the dynamically selected ports. Use those ports in a scan targeting `127.0.0.1`.

## 10. Reports and Evidence

Reports are generated from persisted SQLite data.

A report can include:

- Executive summary.
- Scope and methodology.
- Discovered hosts.
- Port states.
- Services and versions.
- OS estimates.
- Findings and evidence.
- Blocking or rate-limit observations.
- Limitations and recommendations.
- Raw nmap output references.

For the exercise report, compare the scanner output with the defending group paper and explain which observations were facts, probable explanations, or unconfirmed hypotheses.

## 11. Testing

Run all tests with:

```bash
python -m pytest tests -q
```

The tests cover:

- Target and option validation.
- API behavior and CSRF.
- TCP and UDP discovery.
- Service fingerprinting.
- nmap XML parsing and argument generation.
- Rate-limit detection.
- Blocking detection.
- Port knocking.
- Checkpoint and resume behavior.
- Report generation.

## 12. Recommended Usage for the Exercise

For a normal lab scan:

1. Start the server with the authorized lab allowlist.
2. Enter the other group VM address.
3. Select the nmap backend.
4. Use a focused port list first, then scan `all` if needed.
5. Enable service detection.
6. Enable OS detection when nmap privileges are configured.
7. Enable UDP only when required because it is slower.
8. Record events, findings, and report evidence.
9. Use the results to explain filtering, rate limiting, decoys, or port knocking.

The scanner should describe defenses accurately rather than claim that a timeout proves a firewall or that a guessed service name proves an identity.
