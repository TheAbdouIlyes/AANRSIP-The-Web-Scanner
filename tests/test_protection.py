from scanner.adaptive.protection import ScanProtection, Throttle


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def feed(p, outcomes, host="h", ports=(80, 81, 82, 83)):
    for i, o in enumerate(outcomes):
        p.record(host, "tcp", ports[i % len(ports)], o)


def test_isolated_timeouts_are_not_a_defence():
    p = ScanProtection()
    feed(p, ["ok"] * 10 + ["timeout", "ok", "timeout", "ok", "ok", "ok"])
    assert p.assess("h").level == "none"


def test_too_little_data():
    p = ScanProtection()
    feed(p, ["timeout"] * 5)
    assert p.assess("h").level == "none"


def test_rate_limit_from_resets():
    p = ScanProtection()
    feed(p, ["ok"] * 12 + ["reset", "ok", "reset", "reset", "ok", "reset", "ok", "ok", "reset", "ok", "ok", "ok"])
    a = p.assess("h")
    assert a.level == "rate_limit_suspected" and a.indicators


def test_blocking_suspected_then_confirmed_after_persistence():
    c = Clock()
    p = ScanProtection(clock=c, confirm_after_s=60)
    p.record("h", "tcp", 9999, "refused")             # closed port that used to RST
    feed(p, ["ok"] * 12)
    for _ in range(4):
        feed(p, ["timeout"] * 4)
    p.record("h", "tcp", 9999, "timeout")             # now silent
    a = p.assess("h")
    assert a.level == "blocking_suspected" and any("previously-open" in i for i in a.indicators)
    c.t += 61
    for port in (80, 81, 82, 83, 9999):
        p.record("h", "tcp", port, "timeout")
    b = p.assess("h")
    assert b.level == "blocking_confirmed" and any("persisted" in i for i in b.indicators)


def test_throttle_only_slows_down_and_is_bounded():
    t = Throttle(0, 1000)
    seen = []
    while t.backoff():
        seen.append(t.delay_ms)
    assert seen == sorted(seen) and seen[-1] == 1000
