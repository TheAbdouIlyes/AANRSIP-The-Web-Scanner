"""Adaptive investigation engine: a registry of investigators, each with an applicability rule and a
human-readable reason. The engine only runs what the previous results justify and logs why."""
from ..fingerprinting import validator
from ..protocols import probes


class Context:
    def __init__(self, cfg, host, svc):
        self.cfg, self.host, self.svc = cfg, host, svc
        self.obs = {}          # protocol ladder observation
        self.verdict = None
        self.http = None
        self.tls = None
        self.checks = {}


class Investigator:
    name = "base"

    def applies(self, ctx):   # -> reason string or None
        return None

    def run(self, ctx):       # -> dict (stored as evidence)
        raise NotImplementedError


class ProtocolIdentify(Investigator):
    name = "protocol_id"

    def applies(self, ctx):
        s = ctx.svc
        if s["state"] in ("open",) or (s["proto"] == "udp" and s["state"] == "open|filtered"):
            how = "port is open" if s["state"] == "open" else "UDP port is open|filtered (ambiguous), extra probes may elicit a reply"
            return f"{how}; identify the protocol from behaviour rather than the port number ({s['port']})"
        return None

    def run(self, ctx):
        s, timeout = ctx.svc, ctx.cfg["probe_timeout"]
        if s["proto"] == "tcp":
            ctx.obs = probes.identify_tcp(ctx.host, s["port"], timeout)
        else:
            ctx.obs = probes.identify_udp(ctx.host, s["port"], min(timeout, 2))
            if any(p.get("proto") for p in ctx.obs["probes"].values()):
                s["state"] = "open"
                s["reason"] = "udp-response"
        return {"observed": validator.observed_protocols(ctx.obs), "errors": ctx.obs.get("errors", [])}


class HttpInvestigator(Investigator):
    name = "http"

    def applies(self, ctx):
        seen = validator.observed_protocols(ctx.obs)
        if "http" in seen:
            how = "HTTPS" if "https_get" in seen.get("http", []) else "HTTP"
            return f"{how} behaviour observed on port {ctx.svc['port']}; fingerprint headers, redirects, methods and technology"
        return None

    def run(self, ctx):
        tls = "https_get" in validator.observed_protocols(ctx.obs).get("http", [])
        ctx.http = probes.http_investigate(ctx.host, ctx.svc["port"], tls, ctx.cfg["http_paths"], ctx.cfg.get("vhost", ""),
                                           ctx.cfg["probe_timeout"])
        first = next(iter(ctx.http["paths"].values()), {})
        if first.get("status"):
            ctx.checks["http"] = True
        return ctx.http


class TlsInvestigator(Investigator):
    name = "tls"

    def applies(self, ctx):
        if ctx.obs.get("probes", {}).get("tls_handshake", {}).get("proto") == "tls":
            return "TLS handshake succeeded; inspect protocol version, cipher and certificate"
        return None

    def run(self, ctx):
        ctx.tls = probes.tls_inspect(ctx.host, ctx.svc["port"], ctx.cfg["probe_timeout"])
        return ctx.tls


class ConsistencyValidator(Investigator):
    name = "consistency"

    def applies(self, ctx):
        if ctx.obs:
            return "compare the claimed service with observed protocol behaviour and grade confidence"
        return None

    def run(self, ctx):
        s = ctx.svc
        ctx.verdict = validator.validate(s.get("service", ""), s.get("method", ""), ctx.obs, ctx.checks)
        return ctx.verdict


class AuthBarrier(Investigator):
    name = "auth_barrier"

    def applies(self, ctx):
        if ctx.http and any(p.get("auth_required") for p in ctx.http["paths"].values()):
            return "HTTP 401/407 seen: service is available but protected; record as an authorization barrier (no credential guessing)"
        return None

    def run(self, ctx):
        return {"note": "service reachable; authentication required", "www_authenticate": [
            p["headers"].get("www-authenticate") for p in ctx.http["paths"].values() if p.get("headers")]}


REGISTRY = [ProtocolIdentify(), HttpInvestigator(), TlsInvestigator(), ConsistencyValidator(), AuthBarrier()]
ENABLED_BY = {"protocol_id": "protocol_id", "http": "http", "tls": "tls", "consistency": "consistency",
              "auth_barrier": "http", "udp_probes": "protocol_id"}


def investigate(cfg, host, svc, record):
    """record(investigator, reason, result) persists each step. Returns Context."""
    ctx = Context(cfg, host, svc)
    for inv in REGISTRY:
        module = ENABLED_BY.get(inv.name, inv.name)
        if module not in cfg["modules"] and not (inv.name == "protocol_id" and "udp_probes" in cfg["modules"] and svc["proto"] == "udp"):
            continue
        if svc["proto"] == "udp" and inv.name in ("http", "tls", "auth_barrier"):
            continue
        reason = inv.applies(ctx)
        if not reason:
            continue
        try:
            record(inv.name, reason, inv.run(ctx))
        except Exception as e:  # an investigator failing must never abort the scan
            record(inv.name, reason, {"error": f"{type(e).__name__}: {str(e)[:150]}"})
    return ctx
