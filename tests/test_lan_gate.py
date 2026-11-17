"""LAN gate: nobody outside OMANET_ALLOW gets in, and no password is needed inside.

Run: python3 -m unittest discover -s tests -v
"""
import importlib
import os
import sys
import unittest

os.environ.setdefault("DB_PATH", "/tmp/omanet-test.db")
os.environ["OMANET_ALLOW"] = "192.168.5.0/24"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
app = importlib.import_module("app")


def allowed(ip):
    h = object.__new__(app.Handler)          # no socket needed for this check
    h.client_address = (ip, 4242)
    return h.client_allowed()


class LanGate(unittest.TestCase):
    def test_lan_addresses_pass(self):
        for ip in ("192.168.5.245", "192.168.5.114", "192.168.5.1"):
            self.assertTrue(allowed(ip), ip)

    def test_loopback_passes(self):
        for ip in ("127.0.0.1", "::1"):
            self.assertTrue(allowed(ip), ip)

    def test_outside_is_refused(self):
        for ip in ("10.0.0.5", "8.8.8.8", "192.168.6.10", "172.16.4.4", "::ffff:8.8.8.8"):
            self.assertFalse(allowed(ip), ip)

    def test_no_token_means_no_password(self):
        self.assertFalse(app.TOKEN, "OMANET_TOKEN must stay empty: LAN-only, no password")
        self.assertTrue(app.NETS, "OMANET_ALLOW must be set when the app listens off-loopback")


if __name__ == "__main__":
    unittest.main()
