import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.manager import ScanManager  # noqa: E402
from scanner.storage import Storage  # noqa: E402
from tests.mock_lab import MockLab  # noqa: E402


@pytest.fixture()
def lab():
    l = MockLab().start()
    yield l
    l.stop()


@pytest.fixture()
def store(tmp_path):
    return Storage(str(tmp_path / "t.db"))


@pytest.fixture()
def manager(store):
    return ScanManager(store)


def wait_done(store, sid, timeout=120, states=("queued", "running")):
    end = time.time() + timeout
    while time.time() < end:
        if store.get_scan(sid)["status"] not in states:
            return store.get_scan(sid)
        time.sleep(0.2)
    raise AssertionError("scan did not finish")
