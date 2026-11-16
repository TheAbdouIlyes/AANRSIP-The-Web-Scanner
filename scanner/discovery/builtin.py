"""Pure-Python port scanner. Used when nmap is absent, or for per-port outcome feedback
to the adaptive protection module. Outcomes: open / closed / filtered (TCP), open / closed / open|filtered (UDP)."""
import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor


def _family(addr):
    return socket.AF_INET6 if ":" in str(addr) else socket.AF_INET


def tcp_probe(addr, port, timeout, source_port=None):
    """Returns (state, reason, outcome) where outcome feeds adaptive protection."""
    s = socket.socket(_family(addr), socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if source_port:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", source_port))
        err = s.connect_ex((str(addr), port))
    except socket.timeout:
        return "filtered", "no-response", "timeout"
    except OSError as e:
        return "filtered", f"error:{e.errno}", "error"
    finally:
        s.close()
    if err == 0:
        return "open", "syn-ack", "ok"
    if err == errno.ECONNREFUSED:
        return "closed", "conn-refused", "refused"
    if err == errno.ECONNRESET:
        return "filtered", "reset", "reset"
    if err in (errno.EHOSTUNREACH, errno.ENETUNREACH):
        return "filtered", "unreachable", "error"
    if err in (errno.EAGAIN, errno.EINPROGRESS, errno.ETIMEDOUT):
        return "filtered", "no-response", "timeout"
    return "filtered", f"errno:{err}", "error"


UDP_PROBES = {53: bytes.fromhex("1a2b01000001000000000000076578616d706c6503636f6d0000010001"),
              123: b"\x1b" + 47 * b"\x00"}


def udp_probe(addr, port, timeout):
    s = socket.socket(_family(addr), socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((str(addr), port))
        s.send(UDP_PROBES.get(port, b"\r\n"))
        data = s.recv(2048)
        return ("open", "udp-response", "ok") if data else ("open|filtered", "empty", "timeout")
    except ConnectionRefusedError:
        return "closed", "icmp-port-unreachable", "refused"
    except socket.timeout:
        return "open|filtered", "no-response", "timeout"
    except OSError as e:
        return "open|filtered", f"error:{e.errno}", "error"
    finally:
        s.close()


def scan(addr, proto, ports, timeout, workers=64, delay_ms=0, on_outcome=None, should_stop=None, retries=0):
    """Scan ports; returns list of dicts for non-closed ports (closed are returned too, flagged)."""
    results = []
    fn = tcp_probe if proto == "tcp" else udp_probe

    def work(p):
        if should_stop and should_stop():
            return None
        if delay_ms:
            time.sleep(delay_ms / 1000)
        for _ in range(retries + 1):
            state, reason, outcome = fn(addr, p, timeout)
            if outcome != "timeout" or proto == "udp":
                break
        if on_outcome:
            on_outcome(str(addr), proto, p, outcome)
        return {"proto": proto, "port": p, "state": state, "reason": reason,
                "service": "", "product": "", "version": "", "outcome": outcome}

    with ThreadPoolExecutor(max_workers=1 if delay_ms else workers) as ex:
        for r in ex.map(work, ports):
            if r:
                results.append(r)
    return results
