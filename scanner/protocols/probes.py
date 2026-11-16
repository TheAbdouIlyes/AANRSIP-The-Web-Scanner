"""Protocol probes. All probes are read-only/benign (banner reads, HEAD/GET/OPTIONS, PING, DNS/NTP queries).
Every function returns plain dicts so results can be stored as evidence."""
import hashlib
import http.client
import re
import socket
import ssl

MAX_READ = 4096


def _family(addr):
    return socket.AF_INET6 if ":" in str(addr) else socket.AF_INET


def classify_bytes(data: bytes):
    """Map raw response bytes to a protocol name using signatures (not port numbers)."""
    if not data:
        return None
    if data.startswith(b"SSH-"):
        return "ssh"
    if data.startswith(b"HTTP/1.") or data.startswith(b"HTTP/2"):
        return "http"
    if data[:2] in (b"\x15\x03", b"\x16\x03"):
        return "tls"
    t = data[:200]
    if t.startswith((b"+PONG", b"-NOAUTH", b"-ERR", b"-DENIED", b"-WRONGPASS")) or b"redis_version" in data:
        return "redis"
    if t.startswith(b"220") and (b"FTP" in t.upper()):
        return "ftp"
    if t.startswith(b"220") and (b"SMTP" in t.upper()):
        return "smtp"
    if t.startswith(b"+OK"):
        return "pop3"
    if t.startswith(b"* OK"):
        return "imap"
    if t.startswith(b"RFB "):
        return "vnc"
    if len(data) > 6 and data[4] == 0x0A and re.match(rb"^[0-9][0-9.]+", data[5:12] or b""):
        return "mysql"
    if data[:2] == b"\x00\x00" and len(data) >= 4 and data[2] == 0 and False:
        return None
    return None


def digest(data: bytes):
    return hashlib.sha256(data).hexdigest()[:16] if data else ""


def preview(data: bytes, n=160):
    return data[:n].decode("latin-1").replace("\r", "\\r").replace("\n", "\\n") if data else ""


def _tcp(addr, port, timeout, payload=None, wrap_tls=False, read_wait=None):
    """Connect, optionally send payload, read up to MAX_READ. Returns (bytes, error)."""
    s = None
    try:
        s = socket.create_connection((str(addr), port), timeout=timeout)
        s.settimeout(read_wait or timeout)
        if wrap_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=None)
        if payload:
            s.sendall(payload)
        data = b""
        try:
            data = s.recv(MAX_READ)
        except socket.timeout:
            pass
        return data, None
    except socket.timeout:
        return b"", "timeout"
    except ConnectionResetError:
        return b"", "reset"
    except ConnectionRefusedError:
        return b"", "refused"
    except ssl.SSLError as e:
        return b"", f"tls-error:{e.reason}"
    except OSError as e:
        return b"", f"error:{e.errno}"
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


def _dialog(addr, port, timeout, payload, pre_wait=0.4):
    """Connect, read any server-first bytes, then send payload and read the reply.
    Returns (pre, reply, error). Separating the two is what exposes a banner that lies."""
    s = None
    try:
        s = socket.create_connection((str(addr), port), timeout=timeout)
        s.settimeout(pre_wait)
        pre = b""
        try:
            pre = s.recv(MAX_READ)
        except socket.timeout:
            pass
        reply = b""
        if payload:
            s.settimeout(timeout)
            s.sendall(payload)
            try:
                reply = s.recv(MAX_READ)
            except socket.timeout:
                pass
        return pre, reply, None
    except socket.timeout:
        return b"", b"", "timeout"
    except ConnectionResetError:
        return b"", b"", "reset"
    except ConnectionRefusedError:
        return b"", b"", "refused"
    except OSError as e:
        return b"", b"", f"error:{e.errno}"
    finally:
        if s:
            try:
                s.close()
            except OSError:
                pass


TCP_PROBES = [
    ("http_get", b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n"),
    ("redis_ping", b"PING\r\n"),
    ("crlf", b"\r\n\r\n"),
]


def _entry(data, err=None, extra=None):
    d = {"proto": classify_bytes(data), "len": len(data), "hash": digest(data), "preview": preview(data), "error": err}
    d.update(extra or {})
    return d


def identify_tcp(addr, port, timeout=3):
    """Probe ladder. 'banner' = what the server says first; every other probe records only the REPLY
    to our request, so a service that announces SSH but answers HTTP is visible. Never trusts one banner."""
    obs = {"probes": {}, "errors": []}
    pre, _, err = _dialog(addr, port, timeout, None, pre_wait=1.5)
    obs["probes"]["banner"] = _entry(pre, err)
    if err:
        obs["errors"].append(f"banner:{err}")
    for name, payload in TCP_PROBES:
        pre, reply, err = _dialog(addr, port, timeout, payload)
        obs["probes"][name] = _entry(reply, err, {"pre_len": len(pre)})
        if err:
            obs["errors"].append(f"{name}:{err}")
    tls_data, tls_err = _tcp(addr, port, timeout, None, wrap_tls=True)
    ok_tls = tls_err is None
    obs["probes"]["tls_handshake"] = {"proto": "tls" if ok_tls else None, "len": len(tls_data),
                                      "hash": digest(tls_data), "preview": preview(tls_data), "error": tls_err}
    if ok_tls:
        inner, _ = _tcp(addr, port, timeout, b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n", wrap_tls=True)
        obs["probes"]["https_get"] = _entry(inner)
    return obs


def http_investigate(addr, port, tls, paths=("/",), vhost="", timeout=4):
    """HEAD/GET/OPTIONS; headers, redirects, title, tech hints; vhost comparison."""
    out = {"tls": tls, "paths": {}, "methods": None, "tech": [], "vhost": None}

    def request(method, path, host_header=None):
        conn = None
        try:
            if tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(str(addr), port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(str(addr), port, timeout=timeout)
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host_header or f"{addr}:{port}")
            conn.putheader("User-Agent", "AANRSIP-lab-scanner/1.0")
            conn.putheader("Connection", "close")
            conn.endheaders()
            r = conn.getresponse()
            body = r.read(16384) if method != "HEAD" else b""
            return r, body
        except (OSError, http.client.HTTPException) as e:
            return None, str(e)
        finally:
            if conn:
                conn.close()

    for path in paths:
        r, body = request("GET", path)
        if r is None:
            out["paths"][path] = {"error": body}
            continue
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        m = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        out["paths"][path] = {
            "status": r.status, "reason": r.reason,
            "server": hdrs.get("server", ""), "location": hdrs.get("location", ""),
            "redirect": r.status in (301, 302, 303, 307, 308),
            "title": m.group(1).decode("latin-1").strip()[:120] if m else "",
            "headers": {k: v[:200] for k, v in hdrs.items()
                        if k in ("server", "x-powered-by", "content-type", "set-cookie", "www-authenticate",
                                 "strict-transport-security", "x-frame-options", "content-security-policy", "via")},
            "length": len(body),
        }
        h = out["paths"][path]["headers"]
        for key in ("server", "x-powered-by", "via"):
            if h.get(key):
                out["tech"].append(h[key])
        gen = re.search(rb'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        if gen:
            out["tech"].append("generator: " + gen.group(1).decode("latin-1"))
        if r.status in (401, 407):
            out["paths"][path]["auth_required"] = True
    r, _ = request("OPTIONS", "/")
    if r is not None:
        out["methods"] = {"status": r.status, "allow": r.getheader("Allow", "")}
    out["tech"] = sorted(set(out["tech"]))
    if vhost:
        base = out["paths"].get(paths[0], {})
        r2, body2 = request("GET", paths[0], host_header=vhost)
        if r2 is not None:
            m2 = re.search(rb"<title[^>]*>(.*?)</title>", body2, re.I | re.S)
            t2 = m2.group(1).decode("latin-1").strip()[:120] if m2 else ""
            out["vhost"] = {"host": vhost, "status": r2.status, "title": t2, "length": len(body2),
                            "differs_from_ip_default": (r2.status, t2, len(body2)) != (base.get("status"), base.get("title"), base.get("length"))}
    return out


def tls_inspect(addr, port, timeout=4):
    """TLS version/cipher/ALPN + certificate details (parsed when `cryptography` is installed)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((str(addr), port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as s:
                der = s.getpeercert(binary_form=True)
                info = {"version": s.version(), "cipher": s.cipher()[0] if s.cipher() else None,
                        "alpn": s.selected_alpn_protocol(), "cert_sha256": hashlib.sha256(der).hexdigest() if der else None}
    except (OSError, ssl.SSLError) as e:
        return {"error": str(e)[:200]}
    try:
        from cryptography import x509
        c = x509.load_der_x509_certificate(der)
        info.update({"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                     "not_before": c.not_valid_before_utc.isoformat() if hasattr(c, "not_valid_before_utc") else str(c.not_valid_before),
                     "not_after": c.not_valid_after_utc.isoformat() if hasattr(c, "not_valid_after_utc") else str(c.not_valid_after),
                     "self_signed": c.subject == c.issuer})
        try:
            info["san"] = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            info["san"] = []
    except ImportError:
        info["note"] = "install `cryptography` for full certificate parsing"
    return info


UDP_PROBE_SET = {
    "dns": bytes.fromhex("1a2b01000001000000000000076578616d706c6503636f6d0000010001"),
    "ntp": b"\x1b" + 47 * b"\x00",
    "empty": b"",
    "crlf": b"\r\n",
}


def classify_udp(name, data):
    if not data:
        return None
    if name == "dns" and len(data) >= 12 and data[:2] == b"\x1a\x2b" and data[2] & 0x80:
        return "dns"
    if name == "ntp" and len(data) >= 48 and (data[0] & 0x07) in (4, 5):
        return "ntp"
    return None   # a reply we cannot attribute to a protocol is evidence of activity, not a protocol


def identify_udp(addr, port, timeout=2):
    obs = {"probes": {}, "icmp_unreachable": False}
    for name, payload in UDP_PROBE_SET.items():
        s = socket.socket(_family(addr), socket.SOCK_DGRAM)
        s.settimeout(timeout)
        data, err = b"", None
        try:
            s.connect((str(addr), port))
            s.send(payload)
            data = s.recv(2048)
        except socket.timeout:
            err = "timeout"
        except ConnectionRefusedError:
            err = "icmp-unreachable"
            obs["icmp_unreachable"] = True
        except OSError as e:
            err = f"error:{e.errno}"
        finally:
            s.close()
        obs["probes"][name] = {"proto": classify_udp(name, data), "len": len(data), "hash": digest(data),
                               "preview": preview(data), "error": err}
    return obs
