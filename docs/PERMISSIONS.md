# Privilege model

* The Flask app and the scan engine run as an **unprivileged user**. Never run `run.py` as root.
* Default scans use TCP connect (`-sT`) and need no privileges.
* For SYN scans (`-sS`), UDP via raw sockets and OS detection (`-O`), give **only the nmap binary** the two capabilities it needs:

      sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f "$(which nmap)")"
      export SCANNER_NMAP_PRIVILEGED=1

  The scanner then adds `--privileged` itself. Everything passed to nmap is built from validated values as an
  argument array (`shell=False`), so the privileged surface is: nmap, with options from a fixed whitelist
  (`scanner/discovery/nmap_runner.py`), against targets that passed the allowlist check.
* Revoke with `sudo setcap -r "$(readlink -f "$(which nmap)")"`.
* This is deliberately simpler than a separate privileged daemon; the limitation is that any local user who can
  run that nmap binary gets the capabilities. On a shared machine, copy nmap to a private path and `setcap` only that copy
  (set `SCANNER_NMAP` to it).
