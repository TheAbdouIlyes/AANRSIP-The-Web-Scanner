import os
import shutil

NMAP_PATH = os.environ.get("SCANNER_NMAP") or shutil.which("nmap")
# Set to 1 only if nmap was given cap_net_raw/cap_net_admin (see docs/PERMISSIONS.md).
NMAP_PRIVILEGED = os.environ.get("SCANNER_NMAP_PRIVILEGED") == "1"
DB_PATH = os.environ.get("SCANNER_DB", os.path.join(os.path.dirname(__file__), "..", "database", "scanner.db"))
