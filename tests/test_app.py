import hashlib
import os
import sys
import unittest
from unittest import mock


os.environ.setdefault("PANEL_PASSWORD_SALT", "test-salt")
os.environ.setdefault(
    "PANEL_PASSWORD_HASH",
    hashlib.sha256(b"test-salttest-password").hexdigest(),
)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app  # noqa: E402


class ValidationTests(unittest.TestCase):
    def test_instance_names(self):
        self.assertIsNotNone(app.NAME_RE.fullmatch("web-01"))
        self.assertIsNone(app.NAME_RE.fullmatch("-bad"))
        self.assertIsNone(app.NAME_RE.fullmatch("bad name"))
        self.assertIsNone(app.NAME_RE.fullmatch("a" * 64))

    def test_resource_sizes(self):
        self.assertIsNotNone(app.SIZE_RE.fullmatch("512MiB"))
        self.assertIsNotNone(app.SIZE_RE.fullmatch("2GiB"))
        self.assertIsNone(app.SIZE_RE.fullmatch("0GiB"))
        self.assertIsNone(app.SIZE_RE.fullmatch("2GB"))

    def test_password_hash(self):
        self.assertTrue(app.password_matches("test-password"))
        self.assertFalse(app.password_matches("wrong-password"))

    def test_pbkdf2_password_hash(self):
        old_values = (app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS)
        try:
            app.PASSWORD_SALT = "00112233445566778899aabbccddeeff"
            app.PASSWORD_ITERATIONS = 1000
            app.PASSWORD_HASH = hashlib.pbkdf2_hmac(
                "sha256",
                b"strong-password",
                bytes.fromhex(app.PASSWORD_SALT),
                app.PASSWORD_ITERATIONS,
            ).hex()
            self.assertTrue(app.password_matches("strong-password"))
            self.assertFalse(app.password_matches("wrong-password"))
        finally:
            app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS = old_values

    def test_chinese_ui_and_relative_api_base(self):
        self.assertIn("Incus 中文集群面板", app.HTML)
        self.assertIn("location.pathname", app.HTML)
        self.assertIn("apiBase + path", app.HTML)

    def test_normalize_node_address(self):
        self.assertEqual(
            app.normalize_address("203.0.113.10"),
            "https://203.0.113.10:8443",
        )
        self.assertEqual(
            app.normalize_address("https://node.example.com:9443/"),
            "https://node.example.com:9443",
        )
        self.assertEqual(
            app.normalize_address("2001:db8::10"),
            "https://[2001:db8::10]:8443",
        )
        for invalid in ("http://node.example.com", "https://user@node.example.com", "https://node.example.com/path"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                app.normalize_address(invalid)

    @mock.patch("app.run_incus")
    def test_registered_remotes_only_returns_private_incus_nodes(self, run_incus):
        run_incus.return_value = '''{
            "local": {"Protocol": "incus", "Public": false},
            "images": {"Protocol": "simplestreams", "Public": true},
            "node-hk-01": {"Protocol": "incus", "Public": false}
        }'''
        self.assertEqual(
            app.registered_remotes(),
            {"node-hk-01": {"Protocol": "incus", "Public": False}},
        )

    @mock.patch("app.registered_remotes", return_value={})
    @mock.patch("app.run_incus")
    def test_add_remote_uses_token_before_setting_explicit_url(self, run_incus, _):
        app.add_remote(
            "node-hk-01",
            "https://203.0.113.10:8443",
            "one-time-trust-token",
        )
        self.assertEqual(
            run_incus.call_args_list,
            [
                mock.call("remote", "add", "node-hk-01", "one-time-trust-token", timeout=90),
                mock.call("remote", "set-url", "node-hk-01", "https://203.0.113.10:8443", timeout=20),
                mock.call("query", "node-hk-01:/1.0", timeout=20),
            ],
        )

    @mock.patch("app.registered_remotes", return_value={})
    @mock.patch("app.run_incus")
    def test_add_remote_rolls_back_failed_health_check(self, run_incus, _):
        run_incus.side_effect = [None, None, RuntimeError("offline"), None]
        with self.assertRaisesRegex(RuntimeError, "offline"):
            app.add_remote(
                "node-hk-01",
                "https://203.0.113.10:8443",
                "one-time-trust-token",
            )
        self.assertEqual(
            run_incus.call_args_list[-1],
            mock.call("remote", "remove", "node-hk-01", timeout=20),
        )


if __name__ == "__main__":
    unittest.main()
