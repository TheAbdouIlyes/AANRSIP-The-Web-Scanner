# Set these environment variables when starting the application:
#   SCANNER_TOKEN           required for non-localhost access
#   SCANNER_SECRET_KEY      Flask session key; generated if omitted
#   SCANNER_ALLOWED         comma-separated authorized CIDRs
#   SCANNER_BIND / SCANNER_PORT  default: 127.0.0.1 / 5000
#   SCANNER_DB              default: database/scanner.db
#   SCANNER_NMAP            nmap path; uses PATH if omitted
#   SCANNER_NMAP_PRIVILEGED set to 1 only when nmap has raw-socket privileges
