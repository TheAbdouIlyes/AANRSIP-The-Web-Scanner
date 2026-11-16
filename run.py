import os
import sys

from app import create_app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("SCANNER_BIND", "127.0.0.1")
    if host not in ("127.0.0.1", "::1") and not app.config["SCANNER_TOKEN"]:
        sys.exit("Refusing to bind to a non-loopback address without SCANNER_TOKEN set.")
    app.run(host=host, port=int(os.environ.get("SCANNER_PORT", "5000")), threaded=True)
