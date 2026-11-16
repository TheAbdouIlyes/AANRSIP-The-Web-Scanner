"""Start the simulated defender network on 127.0.0.1 and print its ports. Ctrl-C to stop.
Then scan 127.0.0.1 from the dashboard with TCP ports 'all' to see the scanner find them."""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.mock_lab import MockLab

lab = MockLab().start()
print("Mock lab running on 127.0.0.1")
for k, v in lab.ports.items():
    print(f"  {k:12s} {v}")
print("  knock ports  ", lab.knock_sequence, "(in order) -> opens 'protected' for 8 s")
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    lab.stop()
