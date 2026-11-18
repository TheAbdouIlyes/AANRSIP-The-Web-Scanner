# Architecture

AANRSIP is a Flask application backed by a checkpointed Python scan engine. It is
designed for authorised laboratory networks: the web layer accepts scan intent,
the manager validates and schedules it, and the engine records observable
results without attempting to evade controls.

## System context

```text
Operator
   |
   v
Browser UI --------------------> Flask application
   |                                  |
   |                                  +--> authentication, CSRF, headers
   |                                  +--> HTML pages
   |                                  `--> JSON API
   |                                             |
   |                                             v
   |                                      ScanManager
   |                                             |
   |                              validation + lifecycle control
   |                                             |
   |                                             v
   |                                       ScanRunner
   |                                  (one background thread/scan)
   |                                             |
   |                 +---------------------------+--------------------------+
   |                 |                           |                          |
   |                 v                           v                          v
   |             Discovery                 Investigation              Reporting
   |          nmap or built-in          probes + fingerprinting       JSON/CSV/PDF
   |                 |                           |                          |
   |                 +---------------------------+--------------------------+
   |                                             |
   |                                             v
   |                                      SQLite Storage
   |                              state, evidence, events, checkpoints
   |
   `--> authorised targets only
```

The browser never executes scanner commands. The server constructs all scanner
arguments from validated values and persists results through the storage layer.

## Application boundaries

### Flask application

`app.create_app()` creates the Flask application, configures SQLite and the
`ScanManager`, then registers three route groups:

- `app/routes/auth.py` handles login and session authentication.
- `app/routes/pages.py` renders the HTML interface.
- `app/routes/api.py` exposes scan control, status, events, findings, comparison,
  raw output, and report downloads.

The request guard applies the common security policy:

- local-only access when no token is configured;
- bearer-token authentication for remote/API access;
- CSRF protection for state-changing requests;
- a request-size limit and secure response headers.

The application does not perform discovery itself. Routes delegate scan work to
`ScanManager`, so HTTP requests remain short-lived while scans run in background
threads.

### Scan manager

`scanner/manager.py` is the lifecycle boundary between Flask and the engine. It:

1. Parses and validates the target and scan configuration.
2. Enforces the maximum host count and concurrent-scan limit.
3. Creates the scan record before starting work.
4. Starts, pauses, resumes, cancels, and resumes checkpointed scans.
5. Keeps active `ScanRunner` instances associated with their scan IDs.

Invalid input fails at this boundary; it is not passed to a shell command or
scanner backend.

### Scan runner

`scanner/engine.py` executes the work for one scan. Its normal sequence is:

```text
load scan configuration
        |
        v
enumerate hosts and ports in bounded chunks
        |
        v
record port states and checkpoint progress
        |
        v
assess rate limiting or blocking
        |
        v
investigate eligible services
        |
        v
compare claims with observed protocol behaviour
        |
        v
write findings and complete the scan
```

The runner checks pause and cancellation state between units of work. A
checkpoint is written after completed chunks, allowing a restart to skip work
that is already persisted. A pause caused by suspected blocking is explicit and
requires operator control; the engine does not rotate identities, spoof
addresses, or otherwise evade a defence.

## Discovery and investigation

### Discovery backends

`scanner/discovery/nmap_runner.py` supports nmap-based discovery, service
detection, XML parsing, and optional privileged operations. Arguments are built
as an array and executed with `shell=False`.

`scanner/discovery/builtin.py` provides a socket-based fallback for TCP and UDP
discovery. It is useful when nmap is unavailable, but it does not provide
raw-packet OS detection.

The backend reports observations such as open, closed, filtered, or
`open|filtered`; it does not infer a service identity from a port number alone.

### Protection assessment

`scanner/adaptive/protection.py` consumes probe outcomes and records evidence of
timeouts, resets, changing reachability, rate limiting, or temporary blocking.
The result affects pacing and lifecycle state:

- suspected rate limiting slows subsequent work;
- suspected blocking can move a scan to `paused_blocking`;
- observations remain findings or events rather than proof of operator intent.

### Protocol investigation

`scanner/investigation/engine.py` selects investigations for discovered
services. `scanner/protocols/probes.py` contains protocol-aware probes such as
generic banners, HTTP, TLS, DNS, and NTP checks.

Each investigation records its reason and result. This preserves the difference
between a port observation, a protocol response, and an interpretation.

### Fingerprint validation

`scanner/fingerprinting/validator.py` compares backend claims, banners, and
protocol behaviour. A service can be reported as:

`confirmed`, `probable`, `unknown`, `inconsistent`, or `potential_decoy`.

`potential_decoy` is a hypothesis supported by concrete reuse or inconsistency
indicators; it is never treated as proof of deception.

## Persistence model

`scanner/storage.py` is the only persistence boundary. SQLite stores:

- scan configuration, lifecycle status, and timestamps;
- hosts, port states, service claims, and fingerprints;
- investigation results and evidence;
- findings, warnings, and ordered events;
- raw nmap output;
- chunk checkpoints used for resume.

Writes occur during the scan rather than only at the end. Consequently, a
cancelled, interrupted, or paused scan still has useful partial results. The
API reads the same persisted state for live polling, history, reports, and
comparison.

## API surface

The API is mounted at `/api`:

| Endpoint | Responsibility |
|---|---|
| `POST /scans` | Validate and start a scan |
| `GET /scans` | List stored scans |
| `GET /scans/<id>` | Return status, counts, and hosts |
| `POST /scans/<id>/control` | Pause, resume, cancel, or release a block pause |
| `POST /scans/<id>/resume` | Resume a checkpointed scan |
| `GET /scans/<id>/events` | Read incremental events |
| `GET /scans/<id>/ports` | Read port observations |
| `GET /scans/<id>/service` | Read one service and its investigations |
| `GET /scans/<id>/findings` | Read findings and evidence |
| `GET /scans/<id>/report[.json\|.csv\|.pdf]` | Build or download a report |
| `GET /compare?a=<id>&b=<id>` | Compare two stored scans |

The browser client polls status and events, then renders returned data without
injecting scan output as HTML.

## Security and privilege model

The Flask process and scan engine run as an unprivileged user. The default TCP
connect path needs no special privileges. When required, only the nmap binary
receives narrowly scoped capabilities for SYN scans, raw UDP operations, or OS
detection; the application itself is not run as root.

The safety boundary is layered:

1. Targets must be literal IP addresses or CIDRs inside the configured
   authorised allowlist.
2. Target ranges, ports, timings, retries, modules, paths, and experiments are
   bounded and validated.
3. nmap arguments use a fixed option whitelist and are passed without a shell.
4. Authentication, CSRF checks, security headers, and no-store responses protect
   the web surface.
5. Findings distinguish facts from probable explanations and unconfirmed
   hypotheses.

Port knocking and source-port tests are operator-supplied experiments with
bounded inputs. IP spoofing, address rotation, discovery evasion, and block
evasion are intentionally outside the architecture.

## Failure and resume behaviour

| Condition | Behaviour |
|---|---|
| Invalid target or configuration | Request is rejected before scan creation |
| nmap unavailable | Built-in discovery can be selected where supported |
| Rate limiting suspected | Probe pacing is reduced and evidence is recorded |
| Blocking suspected | Scan pauses explicitly for operator action |
| Operator cancellation | Current state and completed checkpoints remain stored |
| Process interruption | A later resume continues from persisted checkpoints |
| Probe or report error | The event/finding records the failure without discarding prior results |

This design favours recoverability and evidence preservation over a single
all-or-nothing scan result.

## Extension points

New functionality should preserve the existing boundaries:

- add validation in `scanner/validation.py` before accepting new input;
- add a discovery backend behind the discovery interface;
- add protocol probes and register them with the investigation engine;
- persist new evidence through `Storage`;
- expose results through the API and report builders;
- cover the behaviour with focused tests and mock-lab scenarios.

Changes that introduce a new privileged operation, target-selection mechanism,
or evasion behaviour require an explicit security review because they alter the
authorisation and safety model.
