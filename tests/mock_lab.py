"""Local simulated defender network on 127.0.0.1 (random free ports). No external dependencies."""
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _listener(handler, host="127.0.0.1", port=0):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(32)
    s.settimeout(0.2)
    return s


class MockLab:
    def __init__(self, knock_seq_len=3, rate_limit=8, rate_window=3.0, knock_open_seconds=8):
        self.stop_ev = threading.Event()
        self.ports = {}
        self.threads = []
        self.rate_limit, self.rate_window = rate_limit, rate_window
        self.conn_times = []
        self.knock_open_seconds = knock_open_seconds
        self.knock_sequence = []
        self.knock_progress = 0
        self.knock_open_until = 0

    def _spawn(self, fn, *a):
        def safe(*args):
            try:
                fn(*args)
            except OSError:
                pass   # scanners reset connections; the mock must not spam tracebacks
        t = threading.Thread(target=safe, args=a, daemon=True)
        t.start()
        self.threads.append(t)

    def _accept_loop(self, sock, on_conn):
        while not self.stop_ev.is_set():
            try:
                c, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._spawn(on_conn, c, addr)
        sock.close()

    # ---- services
    def start(self):
        # 1. HTTP on an unusual port
        lab = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html><title>Lab Intranet</title><body>hi</body></html>"
                self.send_response(200)
                self.send_header("Server", "lab-httpd/1.0")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Allow", "GET, HEAD, OPTIONS")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *a):
                pass

            def handle(self):
                try:
                    super().handle()
                except OSError:
                    pass
        srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.ports["http"] = srv.server_address[1]
        self._spawn(srv.serve_forever)
        self._http = srv

        # 2. misleading banner: says SSH, behaves like HTTP when asked
        s = _listener(None)
        self.ports["fake_ssh"] = s.getsockname()[1]

        def fake_ssh(c, _):
            c.settimeout(2)
            c.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
            try:
                d = c.recv(1024)
                if d.startswith(b"GET"):
                    c.sendall(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 2\r\n\r\nok")
            except OSError:
                pass
            c.close()
        self._spawn(self._accept_loop, s, fake_ssh)

        # 3. decoy: identical bytes for any probe
        s = _listener(None)
        self.ports["decoy"] = s.getsockname()[1]
        decoy_bytes = b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.3\r\nContent-Length: 0\r\n\r\n"

        def decoy(c, _):
            c.settimeout(1)
            try:
                c.sendall(decoy_bytes)
                c.recv(1024)
                c.sendall(decoy_bytes)
            except OSError:
                pass
            c.close()
        self._spawn(self._accept_loop, s, decoy)

        # 4. rate-limited service
        s = _listener(None)
        self.ports["ratelimited"] = s.getsockname()[1]

        def rl(c, _):
            now = time.time()
            self.conn_times = [t for t in self.conn_times if now - t < self.rate_window] + [now]
            if len(self.conn_times) > self.rate_limit:
                c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                c.close()      # RST
                return
            c.sendall(b"+OK rate-limited-pop3 ready\r\n")
            c.close()
        self._spawn(self._accept_loop, s, rl)

        # 5. UDP DNS-like service
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        u.settimeout(0.2)
        self.ports["udp_dns"] = u.getsockname()[1]

        def udp_loop():
            while not self.stop_ev.is_set():
                try:
                    d, a = u.recvfrom(512)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if len(d) >= 12 and d[2] & 0x80 == 0 and d[4:6] == b"\x00\x01":
                    u.sendto(d[:2] + b"\x81\x80" + d[4:6] + b"\x00\x00\x00\x00\x00\x00" + d[12:], a)
            u.close()
        self._spawn(udp_loop)

        # 6. port knocking: protected port + knock ports
        probe = [_listener(None) for _ in range(3)]
        self.knock_ports = [x.getsockname()[1] for x in probe]
        self.knock_sequence = self.knock_ports[:]
        prot = socket.socket()
        prot.bind(("127.0.0.1", 0))
        self.ports["protected"] = prot.getsockname()[1]
        prot.close()   # free the port; it is (re)opened only after a valid knock
        for i, k in enumerate(probe):
            def knock_conn(c, _, i=i):
                c.close()
                if i == self.knock_progress:
                    self.knock_progress += 1
                    if self.knock_progress == len(self.knock_sequence):
                        self.knock_progress = 0
                        self._open_protected()
                else:
                    self.knock_progress = 1 if i == 0 else 0
            self._spawn(self._accept_loop, k, knock_conn)
        return self

    def _open_protected(self):
        s = _listener(None, port=self.ports["protected"])

        def conn(c, _):
            c.sendall(b"+OK protected-pop3 ready\r\n")
            c.close()

        def loop():
            end = time.time() + self.knock_open_seconds
            while time.time() < end and not self.stop_ev.is_set():
                try:
                    c, a = s.accept()
                except socket.timeout:
                    continue
                self._spawn(conn, c, a)
            s.close()
        self._spawn(loop)

    def stop(self):
        self.stop_ev.set()
        self._http.shutdown()
        time.sleep(0.3)
