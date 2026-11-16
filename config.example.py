# Configuration is read from environment variables (no secrets in source):
#   SCANNER_TOKEN            access token; REQUIRED to bind to anything but 127.0.0.1
#   SCANNER_SECRET_KEY       Flask session key (auto-generated into config/.secret_key, mode 0600, if unset)
#   SCANNER_ALLOWED          comma-separated authorised CIDRs, e.g. "192.168.56.0/24,10.10.10.0/24"
#                            (default: loopback + RFC1918 + link-local + ULA; public IPs are always rejected unless listed)
#   SCANNER_BIND / SCANNER_PORT   default 127.0.0.1 / 5000
#   SCANNER_DB               SQLite path (default database/scanner.db)
#   SCANNER_NMAP             path to nmap (default: first on PATH)
#   SCANNER_NMAP_PRIVILEGED  "1" only if nmap has cap_net_raw/cap_net_admin (enables -sS and -O)
