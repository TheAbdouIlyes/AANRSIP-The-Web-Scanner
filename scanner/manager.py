"""Owns running scans. Flask talks only to this class."""
import json
import threading
import time

from .engine import ScanRunner
from .validation import load_allowlist, parse_target, validate_config, ValidationError


class ScanManager:
    def __init__(self, store, allowlist=None, max_concurrent=2, max_hosts=256):
        self.store, self.allowlist, self.max_concurrent, self.max_hosts = store, load_allowlist(allowlist), max_concurrent, max_hosts
        self.runners = {}
        self.lock = threading.Lock()
        # Mark unfinished scans so their saved results can be resumed.
        for s in self.store.query("SELECT id FROM scans WHERE status IN ('running','paused','paused_blocking','queued')"):
            self.store.update_scan(s["id"], status="interrupted", stage="interrupted")
            self.store.add_event(s["id"], "warning", "interrupt", "Application restarted while scan was active; partial results preserved, resume is possible")

    def _active(self):
        return [r for r in self.runners.values() if r.is_alive()]

    def _prior(self, target, vantage, exclude_id=None):
        prev = self.store.one("SELECT id FROM scans WHERE target=? AND vantage=? AND status='completed' AND id!=? ORDER BY id DESC LIMIT 1",
                              (target, vantage, exclude_id or -1))
        openp, closedp = {}, {}
        if prev:
            for p in self.store.ports(prev["id"]):
                if p["state"] == "open":
                    openp.setdefault(p["host"], set()).add((p["proto"], p["port"]))
                elif p["state"] == "closed":
                    closedp.setdefault(p["host"], set()).add((p["proto"], p["port"]))
        return openp, closedp

    def start(self, target, raw_cfg):
        with self.lock:
            if len(self._active()) >= self.max_concurrent:
                raise ValidationError(f"at most {self.max_concurrent} concurrent scans")
                
            # Validate everything before saving or starting network activity.
            cfg = validate_config(raw_cfg)
            hosts = parse_target(target, self.allowlist, self.max_hosts)
            sid = self.store.create_scan(cfg["name"], target.strip(), cfg)
            return self._launch(sid, cfg, hosts, target.strip())

    def _launch(self, sid, cfg, hosts, target):
        # Show the queued state before the worker thread starts.
        self.store.update_scan(sid, status="queued", stage="queued", finished=None)
        po, pc = self._prior(target, cfg["vantage"], sid)
        r = ScanRunner(self.store, sid, cfg, hosts, target, po, pc)
        self.runners[sid] = r
        r.start()
        return sid

    def resume(self, sid):
        with self.lock:
            s = self.store.get_scan(sid)
            if not s or s["status"] not in ("cancelled", "interrupted", "failed"):
                raise ValidationError("only cancelled, interrupted or failed scans can be resumed from checkpoint")
            if len(self._active()) >= self.max_concurrent:
                raise ValidationError("too many concurrent scans")
            # Check the target again because the allowlist may have changed.
            hosts = parse_target(s["target"], self.allowlist, self.max_hosts)
            self.store.add_event(sid, "info", "resume", "Resuming from checkpoint; completed hosts/chunks are skipped")
            return self._launch(sid, s["config"], hosts, s["target"])

    def control(self, sid, action, force=False):
        r = self.runners.get(sid)
        if not r or not r.is_alive():
            raise ValidationError("scan is not running")
        if action == "pause":
            r.pause()
        elif action == "unpause":
            r.unpause()
        elif action == "cancel":
            r.cancel()
        elif action == "release":
            s = self.store.get_scan(sid)
            until = s.get("cooldown_until") or 0
            if s["status"] != "paused_blocking":
                raise ValidationError("scan is not paused for suspected blocking")
            if time.time() < until and not force:
                raise ValidationError(f"cooldown active for another {int(until - time.time())}s; pass force=true to override as operator")
            r.release_block()
        else:
            raise ValidationError("unknown action")
