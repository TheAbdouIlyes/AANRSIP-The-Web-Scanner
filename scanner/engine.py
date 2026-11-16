"""Scan orchestration. Independent of Flask. One ScanRunner thread per scan."""
import ipaddress
import threading
import time

from .adaptive.protection import ScanProtection, Throttle
from .discovery import builtin, nmap_runner
from .fingerprinting import validator
from .investigation import engine as inv_engine
from .protocols import probes

CHUNK = 1000
BUILTIN_CHUNK = 250   # finer checkpoints for the built-in scanner
MAX_STORED_FILTERED = 500
MAX_UDP_INVESTIGATE = 20


class Cancelled(Exception):
    pass


class ScanRunner(threading.Thread):
    def __init__(self, store, scan_id, cfg, hosts, target_spec, prior_open=None, prior_closed=None, clock=time.time):
        super().__init__(daemon=True, name=f"scan-{scan_id}")
        self.store, self.id, self.cfg, self.hosts, self.spec, self.clock = store, scan_id, cfg, hosts, target_spec, clock
        self.cancel_ev, self.run_ev, self.resume_ev = threading.Event(), threading.Event(), threading.Event()
        self.run_ev.set()
        self.protection = ScanProtection(known_open=prior_open, known_closed=prior_closed, clock=clock)
        self.throttle = Throttle(cfg["delay_ms"], cfg["max_delay_ms"])
        self.use_nmap = nmap_runner.available() and cfg["backend"] in ("auto", "nmap")
        self.checkpoint = (store.get_scan(scan_id) or {}).get("checkpoint") or {}
        self.checkpoint.setdefault("hosts", {})
        self.services = []   # collected for decoy comparison

    # ---- operator controls
    def pause(self):
        self.run_ev.clear()
        self.store.update_scan(self.id, status="paused")
        self.store.add_event(self.id, "info", "pause", "Scan paused by operator")

    def unpause(self):
        self.run_ev.set()
        self.store.update_scan(self.id, status="running")
        self.store.add_event(self.id, "info", "resume", "Scan resumed by operator")

    def release_block(self):
        self.resume_ev.set()

    def cancel(self):
        self.cancel_ev.set()
        self.run_ev.set()
        self.resume_ev.set()

    def _check(self):
        if self.cancel_ev.is_set():
            raise Cancelled()
        while not self.run_ev.wait(0.2):
            if self.cancel_ev.is_set():
                raise Cancelled()
        if self.cancel_ev.is_set():
            raise Cancelled()

    def _save_cp(self):
        self.store.update_scan(self.id, checkpoint=self.checkpoint)

    def _sleep(self):
        if self.throttle.delay_ms:
            time.sleep(self.throttle.delay_ms / 1000)

    # ---- main
    def run(self):
        s, sid = self.store, self.id
        try:
            s.update_scan(sid, status="running", stage="discovery", error=None)
            s.add_event(sid, "info", "start", f"Scan started on {self.spec} (backend={'nmap' if self.use_nmap else 'builtin'}, vantage={self.cfg['vantage']})")
            if not self.use_nmap and self.cfg["backend"] == "nmap":
                s.add_event(sid, "warning", "backend", "nmap requested but not installed; falling back to built-in scanner")
            up = self.discover()
            total = max(1, len(up))
            for i, h in enumerate(up):
                cp = self.checkpoint["hosts"].setdefault(h, {})
                if cp.get("done"):
                    continue
                self.scan_host(h, i, total)
                cp["done"] = True
                s.set_host_status(sid, h, "done")
                self._save_cp()
            s.update_scan(sid, stage="analysis", progress=0.97)
            self.cross_host_analysis()
            s.update_scan(sid, status="completed", stage="done", progress=1.0, finished=time.time())
            s.add_event(sid, "info", "complete", "Scan completed")
        except Cancelled:
            s.update_scan(sid, status="cancelled", stage="cancelled", finished=time.time())
            s.add_event(sid, "warning", "cancel", "Scan cancelled; partial results preserved")
        except Exception as e:
            s.update_scan(sid, status="failed", stage="failed", error=f"{type(e).__name__}: {e}"[:400], finished=time.time())
            s.add_event(sid, "error", "failure", f"Scan failed: {type(e).__name__}: {e}"[:300])

    # ---- discovery
    def discover(self):
        s, sid = self.store, self.id
        done = [h for h, v in self.checkpoint["hosts"].items()]
        if len(self.hosts) == 1:
            h = str(self.hosts[0])
            s.upsert_host(sid, h, ipaddress.ip_address(h).version, status="pending")
            return [h]
        up = set()
        if self.use_nmap:
            try:
                xml, _ = nmap_runner.run(nmap_runner.build_discovery_args(self.spec, self.cfg), 600)
                s.add_raw(sid, "*", "nmap host discovery (-sn)", xml)
                up = {h["address"] for h in nmap_runner.parse_xml(xml) if h["status"] == "up"}
            except nmap_runner.NmapError as e:
                s.add_event(sid, "warning", "discovery", f"nmap discovery failed ({e}); using TCP reachability checks")
        if not up:
            for h in self.hosts:
                self._check()
                if any(builtin.tcp_probe(h, p, 1)[2] in ("ok", "refused") for p in (80, 443, 22)):
                    up.add(str(h))
        for h in self.hosts:
            addr = str(h)
            if addr in up:
                s.upsert_host(sid, addr, h.version, status="pending")
            else:
                s.upsert_host(sid, addr, h.version, status="unreachable")
        s.add_event(sid, "info", "discovery", f"{len(up)} of {len(self.hosts)} addresses in scope responded; the rest are recorded as not reachable from vantage '{self.cfg['vantage']}'")
        return sorted(up, key=lambda a: ipaddress.ip_address(a))[: self.cfg["max_hosts"]]

    # ---- per-host
    def scan_host(self, host, idx, total):
        s, sid, cfg = self.store, self.id, self.cfg
        base = idx / total
        span = 0.95 / total
        cp = self.checkpoint["hosts"][host]
        self._save_cp()
        s.update_scan(sid, stage=f"scanning {host}", progress=base * 0.95)
        for proto, key in (("tcp", "tcp_ports"), ("udp", "udp_ports")):
            if not cfg[proto]:
                continue
            ports = cfg[key]
            size = CHUNK if self.use_nmap else BUILTIN_CHUNK
            chunks = [ports[i:i + size] for i in range(0, len(ports), size)]
            for ci in range(cp.get(f"{proto}_chunk", 0), len(chunks)):
                self._check()
                s.update_scan(sid, stage=f"{proto.upper()} port enumeration on {host} (chunk {ci + 1}/{len(chunks)})",
                              progress=(base + span * 0.5 * (ci / len(chunks))) * 0.95)
                self.scan_chunk(host, proto, chunks[ci], len(ports))
                cp[f"{proto}_chunk"] = ci + 1
                self._save_cp()
                self.guard(host)
        # service investigation
        s.update_scan(sid, stage=f"investigating services on {host}")
        rows = [p for p in s.ports(sid, host) if p["state"] == "open" or (p["proto"] == "udp" and p["state"] == "open|filtered")]
        rows = [p for p in rows if f"{p['proto']}/{p['port']}" not in cp.get("investigated", [])]
        udp_budget = MAX_UDP_INVESTIGATE
        for n, p in enumerate(rows):
            self._check()
            if p["proto"] == "udp":
                if udp_budget <= 0:
                    continue
                udp_budget -= 1
            self.investigate_one(host, p)
            cp.setdefault("investigated", []).append(f"{p['proto']}/{p['port']}")
            self._save_cp()
            s.update_scan(sid, progress=(base + span * (0.5 + 0.5 * (n + 1) / len(rows))) * 0.95)
            self._sleep()
            self.guard(host)
        if "knock" in cfg["modules"] and cfg.get("knock") and not cp.get("knock"):
            self.knock_experiment(host)
            cp["knock"] = True
        if "source_port" in cfg["modules"] and cfg.get("source_ports") and not cp.get("source"):
            self.source_port_experiment(host)
            cp["source"] = True
        self.host_findings(host)

    def scan_chunk(self, host, proto, ports, total_requested):
        s, sid, cfg = self.store, self.id, self.cfg
        results = []
        if self.use_nmap:
            try:
                xml, _ = nmap_runner.run(nmap_runner.build_port_args(host, proto, ports, cfg), cfg["host_timeout"] + 30)
                s.add_raw(sid, host, f"nmap {proto} ports {ports[0]}-{ports[-1]}", xml)
                for h in nmap_runner.parse_xml(xml):
                    if h.get("os"):
                        s.upsert_host(sid, host, h["family"], h["hostname"], h["os"])
                    elif h["hostname"]:
                        s.upsert_host(sid, host, h["family"], h["hostname"])
                    for p in h["ports"]:
                        p["outcome"] = {"open": "ok", "closed": "refused"}.get(p["state"], "timeout")
                        results.append(p)
            except nmap_runner.NmapError as e:
                s.add_event(sid, "warning", "nmap", f"nmap failed for {host} {proto}: {e}. Using built-in scanner for this chunk")
                self.use_nmap = False
        if not self.use_nmap and not results:
            results = builtin.scan(host, proto, ports, self.cfg["probe_timeout"], delay_ms=self.throttle.delay_ms,
                                   on_outcome=self.protection.record, should_stop=self.cancel_ev.is_set, retries=cfg["retries"])
        else:   # feed a bounded sample of outcomes to protection (nmap hides per-probe timing)
            for p in results[:25]:
                self.protection.record(host, proto, p["port"], p["outcome"])
        counts = {}
        for p in results:
            counts[p["state"]] = counts.get(p["state"], 0) + 1
        stored_f = 0
        for p in results:
            keep = p["state"] in ("open", "open|filtered")
            if p["state"] == "filtered" and stored_f < MAX_STORED_FILTERED:
                stored_f += 1
                keep = True
            if p["state"] == "closed" and total_requested <= 100:
                keep = True
            if keep:
                s.upsert_port(sid, host, proto, p["port"], p["state"], p["reason"],
                              p.get("service", ""), p.get("product", ""), p.get("version", ""))
                self.methods = getattr(self, "methods", {})
                self.methods[(host, proto, p["port"])] = p.get("method", "")
        s.add_event(sid, "info", "ports", f"{host} {proto.upper()} {ports[0]}-{ports[-1]}: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
        if counts.get("filtered", 0) > stored_f:
            s.add_event(sid, "info", "ports", f"{counts['filtered'] - stored_f} further filtered ports on {host} not stored individually (summary only)")
        if self.cancel_ev.is_set():
            raise Cancelled()   # partial chunk results were saved above; chunk stays un-checkpointed so resume redoes it

    def investigate_one(self, host, p):
        s, sid = self.store, self.id
        svc = {"proto": p["proto"], "port": p["port"], "state": p["state"], "reason": p["reason"],
               "service": p["service"] or "", "method": getattr(self, "methods", {}).get((host, p["proto"], p["port"]), "")}
        ctx = inv_engine.investigate(self.cfg, host, svc,
                                     lambda name, reason, res: s.add_investigation(sid, host, p["proto"], p["port"], name, reason, res))
        verdict = ctx.verdict or {"status": "unknown", "confidence": 0.1, "protocol": None, "evidence": ["no investigation ran"], "issues": []}
        fp = {"verdict": verdict, "observation": ctx.obs, "http": ctx.http, "tls": ctx.tls}
        banner = (ctx.obs.get("probes", {}).get("banner", {}) or {}).get("preview", "")
        s.update_port_fp(sid, host, p["proto"], p["port"], banner, verdict["status"], verdict["confidence"], fp)
        if svc["state"] != p["state"]:
            s.upsert_port(sid, host, p["proto"], p["port"], svc["state"], svc["reason"])
            s.add_event(sid, "info", "udp", f"{host} udp/{p['port']} upgraded open|filtered -> open after protocol-specific probe")
        seen = bool(validator.observed_protocols(ctx.obs))
        errs = ctx.obs.get("errors", [])
        outcome = "ok" if seen else ("reset" if any("reset" in e for e in errs) else "refused" if errs and all("refused" in e for e in errs) else "timeout" if errs else "ok")
        if p["proto"] == "tcp":
            self.protection.record(host, "tcp", p["port"], outcome)
        self.services.append({"host": host, "proto": p["proto"], "port": p["port"], "obs": ctx.obs, "verdict": verdict, "ctx": ctx})

    # ---- adaptive guard
    def guard(self, host):
        a = self.protection.assess(host)
        if a.level == "none":
            return
        s, sid = self.store, self.id
        if a.level == "rate_limit_suspected":
            if self.throttle.backoff():
                s.add_event(sid, "warning", "rate_limit", f"Possible rate limiting on {host}; slowing probes to {self.throttle.delay_ms} ms/probe", a.as_dict())
            return
        label = "confirmed (behavioural)" if a.level == "blocking_confirmed" else "SUSPECTED"
        until = self.clock() + self.cfg["cooldown_s"]
        s.update_scan(sid, status="paused_blocking", stage=f"paused: possible blocking by {host}", cooldown_until=until)
        s.add_event(sid, "warning", "blocking", f"Probing paused: temporary scan blocking {label} on {host}. "
                    f"Cooldown {self.cfg['cooldown_s']}s. No evasion is attempted; operator must resume.", a.as_dict())
        s.add_finding(sid, host, "", None, "blocking", "probable" if a.level == "blocking_confirmed" else "hypothesis", "medium",
                      f"Possible temporary blocking of scanner ({label})", a.as_dict())
        self.resume_ev.clear()
        while not self.resume_ev.wait(0.2):
            if self.cancel_ev.is_set():
                raise Cancelled()
        self._check()
        self.protection.history.pop(host, None)
        self.protection.suspected_since.pop(host, None)
        s.update_scan(sid, status="running", cooldown_until=None)
        s.add_event(sid, "info", "resume", "Operator released the cooldown pause; resuming")

    # ---- experiments (explicitly operator configured)
    def knock_experiment(self, host):
        k, s, sid = self.cfg["knock"], self.store, self.id
        t = self.cfg["probe_timeout"]
        before = builtin.tcp_probe(host, k["protected_port"], t)
        for kp in k["sequence"]:
            self._check()
            builtin.tcp_probe(host, kp, 1)
            time.sleep(k["delay_ms"] / 1000)
        time.sleep(0.3)
        after = builtin.tcp_probe(host, k["protected_port"], t)
        res = {"sequence": k["sequence"], "protected_port": k["protected_port"], "before": before[0], "after": after[0],
               "before_reason": before[1], "after_reason": after[1]}
        s.add_investigation(sid, host, "tcp", k["protected_port"], "knock", "operator supplied knock sequence: replay once and compare state", res)
        if before[0] != after[0]:
            s.upsert_port(sid, host, "tcp", k["protected_port"], after[0], after[1])
            s.add_finding(sid, host, "tcp", k["protected_port"], "port_knocking", "observed", "info",
                          f"Port {k['protected_port']} changed state {before[0]} -> {after[0]} after authorized knock sequence", res)
        else:
            s.add_finding(sid, host, "tcp", k["protected_port"], "port_knocking", "observed", "info",
                          f"No state change on port {k['protected_port']} after knock sequence (still {after[0]})", res)

    def source_port_experiment(self, host):
        s, sid = self.store, self.id
        targets = [p["port"] for p in s.ports(sid, host) if p["proto"] == "tcp" and p["state"] == "filtered"][:20]
        if self.cfg.get("knock"):
            targets.append(self.cfg["knock"]["protected_port"])
        rows = []
        for tp in sorted(set(targets)):
            base = builtin.tcp_probe(host, tp, self.cfg["probe_timeout"])[0]
            for sp in self.cfg["source_ports"]:
                self._check()
                st = builtin.tcp_probe(host, tp, self.cfg["probe_timeout"], source_port=sp)
                rows.append({"port": tp, "source_port": sp, "default_source": base, "with_source_port": st[0], "reason": st[1]})
                time.sleep(0.2)
        s.add_investigation(sid, host, "tcp", 0, "source_port", "authorized source-port experiment on filtered ports (no address spoofing)", rows)
        for r in rows:
            if r["default_source"] != r["with_source_port"]:
                s.add_finding(sid, host, "tcp", r["port"], "source_port", "observed", "medium",
                              f"Port {r['port']} is {r['default_source']} normally but {r['with_source_port']} from source port {r['source_port']}", r)

    # ---- findings
    def host_findings(self, host):
        s, sid = self.store, self.id
        fam = ipaddress.ip_address(host).version
        ports = s.ports(sid, host)
        opens = [p for p in ports if p["state"] == "open"]
        if fam == 6 and opens:
            s.add_finding(sid, host, "", None, "ipv6", "observed", "info", f"{len(opens)} open port(s) exposed over IPv6 ({host})", [f"{p['proto']}/{p['port']}" for p in opens])
        filt = [p for p in ports if p["state"] == "filtered"]
        if filt:
            s.add_finding(sid, host, "", None, "filtered", "observed", "info",
                          f"{len(filt)} filtered port(s): no response, NOT proven closed. A filter (firewall/ACL) is the probable explanation; a service may sit behind it.",
                          {"sample": [f"{p['proto']}/{p['port']}" for p in filt[:20]], "reasons": sorted({p['reason'] for p in filt})})
        mine = [x for x in self.services if x["host"] == host]
        deco = validator.decoy_indicators(mine)
        for x in mine:
            v = x["verdict"]
            key = (host, x["proto"], x["port"])
            d = deco.get(key, {"indicators": [], "strength": 0})
            if v["status"] == "inconsistent":
                s.add_finding(sid, host, x["proto"], x["port"], "inconsistent_fingerprint", "observed", "medium",
                              f"Inconsistent fingerprint on {x['proto']}/{x['port']}", v["issues"] + v["evidence"])
            if d["strength"] >= 1:
                cat = "probable" if d["strength"] >= 2 else "hypothesis"
                s.add_finding(sid, host, x["proto"], x["port"], "potential_decoy", cat, "medium",
                              f"Potential decoy/deceptive service on {x['proto']}/{x['port']} ({d['strength']} indicator(s))", d["indicators"])
                s.update_port_fp(sid, host, x["proto"], x["port"], (x["obs"]["probes"].get("banner") or {}).get("preview", ""),
                                 "potential_decoy", min(0.6 + 0.1 * d["strength"], 0.85), {"verdict": v, "observation": x["obs"], "http": x["ctx"].http, "tls": x["ctx"].tls, "decoy": d})
            if v["status"] == "unknown" and x["proto"] == "tcp":
                s.add_finding(sid, host, x["proto"], x["port"], "unknown_service", "observed", "low",
                              f"Open port tcp/{x['port']} with unidentified service (not ignored: no probe in the ladder got a recognisable reply)", v["evidence"])
            if x["ctx"].http and any(p.get("auth_required") for p in x["ctx"].http["paths"].values()):
                s.add_finding(sid, host, x["proto"], x["port"], "auth_required", "observed", "info",
                              f"{x['proto']}/{x['port']} is available but requires authentication", x["ctx"].http["paths"])

    def cross_host_analysis(self):
        """Same banner on >=3 services across hosts is a decoy indicator."""
        deco = validator.decoy_indicators(self.services)
        hosts_with = {}
        for key, d in deco.items():
            if any("identical banner" in i for i in d["indicators"]) and len({k[0] for k in deco if any('identical banner' in i for i in deco[k]['indicators'])}) >= 2:
                hosts_with[key] = d
        for (h, proto, port), d in hosts_with.items():
            self.store.add_finding(self.id, h, proto, port, "cross_host_fingerprint", "hypothesis", "low",
                                   f"Identical banner shared across hosts/services ({proto}/{port})", d["indicators"])
