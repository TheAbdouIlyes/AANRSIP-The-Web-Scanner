"""Adaptive scan protection: decide whether failures look like rate limiting or a block, with evidence.
A timeout alone is never treated as a defence. Levels:
  none -> rate_limit_suspected -> blocking_suspected -> blocking_confirmed
'confirmed' is behavioural: it needs persistence over time AND a strong indicator. A vantage point
can never *prove* a block (host down / routing change look the same), and the report says so."""
import time
from collections import deque


class Assessment:
    def __init__(self, level="none", confidence=0.0, indicators=None, recommended_delay_ms=None):
        self.level, self.confidence = level, confidence
        self.indicators = indicators or []
        self.recommended_delay_ms = recommended_delay_ms

    def as_dict(self):
        return {"level": self.level, "confidence": round(self.confidence, 2), "indicators": self.indicators,
                "recommended_delay_ms": self.recommended_delay_ms}


class ScanProtection:
    def __init__(self, window=15, confirm_after_s=60, clock=time.time, known_open=None, known_closed=None):
        self.window, self.confirm_after_s, self.clock = window, confirm_after_s, clock
        self.history = {}                      # host -> recent probe outcomes
        self.baseline = {}                     # first non-timeout result per port
        self.known_open = {h: set(v) for h, v in (known_open or {}).items()}   # results from earlier scans
        self.known_closed = {h: set(v) for h, v in (known_closed or {}).items()}
        self.suspected_since = {}

    def record(self, host, proto, port, outcome):
        dq = self.history.setdefault(host, deque(maxlen=self.window * 4))
        dq.append((self.clock(), proto, port, outcome))
        key = (host, proto, port)
        if outcome == "ok":
            self.known_open.setdefault(host, set()).add((proto, port))
            self.baseline.setdefault(key, "ok")
        elif outcome == "refused":
            self.known_closed.setdefault(host, set()).add((proto, port))
            self.baseline.setdefault(key, "refused")

    @staticmethod
    def _rate(items, *outcomes):
        return sum(1 for i in items if i[3] in outcomes) / len(items) if items else 0.0

    def assess(self, host):
        dq = list(self.history.get(host, []))
        if len(dq) < 8:
            return Assessment()
        recent, earlier = dq[-self.window:], dq[:-self.window]
        ind, rate_ind, block_ind = [], [], []
        t_recent, t_early = self._rate(recent, "timeout"), self._rate(earlier, "timeout")
        r_recent = self._rate(recent, "reset")
        if earlier and t_recent >= 0.5 and t_early <= 0.25 and len(recent) >= 10:
            rate_ind.append(f"timeout rate rose from {t_early:.0%} to {t_recent:.0%} over the last {len(recent)} probes")
        if r_recent >= 0.3:
            rate_ind.append(f"{r_recent:.0%} of recent probes were reset")
        # Check whether previously open ports have become unreachable.
        last = {}
        for _, proto, port, outcome in dq:
            last[(proto, port)] = outcome
        canaries = [(p, last.get(p)) for p in self.known_open.get(host, set()) if p in last]
        dead = [p for p, o in canaries if o in ("timeout", "reset", "refused", "error") and
                dq and any(x[1:3] == p and x[3] == "ok" for x in dq)]
        strong = False
        if len(dead) >= 2 or (len(dead) >= 1 and len(self.known_open.get(host, ())) == 1):
            block_ind.append(f"{len(dead)} previously-open service(s) now unreachable: " + ", ".join(f"{a}/{b}" for a, b in sorted(dead)[:6]))
        # A refused port that now times out may have gained a filter.
        flipped = [p for p, o in last.items() if self.baseline.get((host, *p)) == "refused" and o == "timeout"]
        if flipped:
            block_ind.append(f"{len(flipped)} port(s) that previously refused now time out (filter inserted?)")
            strong = True
        if t_recent >= 0.9 and len(recent) >= 10 and any(x[3] == "ok" for x in earlier):
            block_ind.append("host went completely silent after earlier successful responses")
        ind = rate_ind + block_ind
        if block_ind and (len(block_ind) >= 2 or len(rate_ind) >= 1):
            since = self.suspected_since.setdefault(host, self.clock())
            persisted = self.clock() - since >= self.confirm_after_s
            if persisted and (strong or len(dead) >= 3):
                return Assessment("blocking_confirmed", 0.9, ind + [f"persisted for {int(self.clock() - since)}s"])
            return Assessment("blocking_suspected", 0.55 + 0.1 * len(ind), ind)
        self.suspected_since.pop(host, None)
        if rate_ind:
            return Assessment("rate_limit_suspected", 0.5 + 0.1 * len(rate_ind), ind, None)
        return Assessment()


class Throttle:
    """Delay controller. Only ever slows down, bounded by the operator's max_delay."""
    def __init__(self, delay_ms, max_delay_ms):
        self.delay_ms, self.max_delay_ms = delay_ms, max_delay_ms

    def backoff(self):
        new = min(self.max_delay_ms, max(100, self.delay_ms * 2))
        changed = new != self.delay_ms
        self.delay_ms = new
        return changed
