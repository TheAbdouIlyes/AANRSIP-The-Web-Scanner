"""Compare *claimed* service with *observed* behaviour and grade the result with evidence.
Statuses: confirmed | probable | unknown | inconsistent | potential_decoy."""
from collections import Counter, defaultdict

WEAK_METHODS = {"table", ""}


def observed_protocols(obs):
    """Distinct protocols observed across probes, with the probes that showed them."""
    seen = defaultdict(list)
    for name, p in obs.get("probes", {}).items():
        if p.get("proto"):
            seen[p["proto"]].append(name)
    return dict(seen)


def validate(claim, claim_method, obs, protocol_checks=None):
    """claim: service name from nmap/banner (or ''). protocol_checks: extra confirmations
    e.g. {'http': True} when an HTTP parser accepted the response."""
    protocol_checks = protocol_checks or {}
    seen = observed_protocols(obs)
    evidence, issues = [], []
    claim = (claim or "").lower().replace("ssl/", "").replace("http-alt", "http").replace("https", "http")
    weak_claim = claim_method in WEAK_METHODS  # port-number table guess, not a measured fact
    tcp = "tls_handshake" in obs.get("probes", {})
    banner = obs.get("probes", {}).get("banner", {})
    if banner.get("proto"):
        evidence.append(f"server-first banner classified as {banner['proto']}: {banner['preview'][:60]!r}")
    for proto, names in seen.items():
        evidence.append(f"{proto} behaviour seen in probes: {', '.join(names)}")

    if not seen:
        errs = obs.get("errors", [])
        if tcp and all(p.get("error") == "refused" for p in obs["probes"].values()):
            return {"status": "unknown", "confidence": 0.1, "protocol": None, "evidence": ["connection refused during probing"], "issues": []}
        evidence.append("no probe produced a recognisable protocol response")
        if claim and not weak_claim:
            evidence.append(f"nmap version detection claims {claim!r}, not reproduced by our probes")
        return {"status": "unknown", "confidence": 0.2, "protocol": None, "evidence": evidence + errs[:3], "issues": []}

    primary = max(seen, key=lambda k: len(seen[k]))
    if banner.get("proto"):
        primary = banner["proto"]
    # Normalise tls-wrapped http
    if "tls" in seen and "http" in seen and "https_get" in seen.get("http", []):
        primary = "http"

    distinct = {p for p in seen if p != "tls"} or set(seen)
    if len(distinct) >= 2:
        issues.append(f"multiple incompatible protocols on one port: {sorted(distinct)}")
    if claim and claim not in seen and not (claim == "http" and "tls" in seen) and not weak_claim:
        issues.append(f"claimed service {claim!r} but observed {sorted(seen)}")
    if banner.get("proto") and banner["proto"] != primary:
        issues.append(f"banner says {banner['proto']} but behaviour is {primary}")
    # banner says X, but a different protocol answered a probe
    if banner.get("proto") and any(p not in (banner["proto"], "tls") for p in seen):
        other = sorted(p for p in seen if p not in (banner["proto"], "tls"))
        issues.append(f"banner claims {banner['proto']} yet port also answers as {other}")

    if issues:
        return {"status": "inconsistent", "confidence": 0.8, "protocol": primary,
                "evidence": evidence, "issues": issues}
    ok = protocol_checks.get(primary)
    if claim and (claim == primary or (claim == "http" and primary in ("http", "tls"))) and not weak_claim:
        return {"status": "confirmed", "confidence": 0.95 if ok else 0.85, "protocol": primary, "evidence": evidence, "issues": []}
    if ok or len(seen[primary]) >= 2:
        return {"status": "confirmed" if ok else "probable", "confidence": 0.85 if ok else 0.7,
                "protocol": primary, "evidence": evidence, "issues": []}
    return {"status": "probable", "confidence": 0.6, "protocol": primary, "evidence": evidence, "issues": []}


def decoy_indicators(per_service):
    """per_service: list of dict(host, proto, port, obs, verdict).
    Returns {(host,proto,port): {'indicators': [...], 'strength': n}}.
    A decoy is only *suggested*; we label it potential and keep the evidence."""
    out = defaultdict(lambda: {"indicators": [], "strength": 0})
    banner_hash = defaultdict(list)
    for s in per_service:
        key = (s["host"], s["proto"], s["port"])
        probes = s["obs"].get("probes", {})
        nonempty = [p for p in probes.values() if p.get("len")]
        # (a) identical bytes returned for different probe types
        hashes = Counter(p["hash"] for p in nonempty if p["hash"])
        if hashes and hashes.most_common(1)[0][1] >= 3:
            out[key]["indicators"].append(f"identical response bytes for {hashes.most_common(1)[0][1]} different probes")
            out[key]["strength"] += 1
        # (b) answers as several unrelated protocols
        protos = {p["proto"] for p in probes.values() if p.get("proto")} - {"tls"}
        if len(protos) >= 2:
            out[key]["indicators"].append(f"answers as multiple protocols: {sorted(protos)}")
            out[key]["strength"] += 1
        b = probes.get("banner", {})
        if b.get("hash"):
            banner_hash[b["hash"]].append(key)
    # (c) same banner reused on several ports/hosts
    for h, keys in banner_hash.items():
        if len(keys) >= 3:
            for k in keys:
                out[k]["indicators"].append(f"identical banner (sha256:{h}) on {len(keys)} services")
                out[k]["strength"] += 1
    return dict(out)
