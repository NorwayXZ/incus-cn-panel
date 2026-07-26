import hashlib
import json
import os
import sys
import tempfile
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
        self.assertIn("Incus Control", app.HTML)
        self.assertIn("切割实例", app.HTML)
        self.assertIn("添加宿主机", app.HTML)
        self.assertIn('data-view="operations"', app.HTML)
        self.assertIn("location.pathname", app.HTML)
        self.assertIn("apiBase+path", app.HTML)
        self.assertIn("const iconSvg=", app.HTML)
        self.assertNotIn("lucide.createIcons", app.HTML)

    def test_csp_allows_same_origin_scripts(self):
        with open(app.__file__, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertEqual(source.count("script-src 'self' 'unsafe-inline'"), 2)

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

    def test_parse_instances_includes_resource_and_access_metadata(self):
        instances = app.parse_instances("node-hk-01", [{
            "name": "web-01",
            "type": "container",
            "status": "Running",
            "expanded_config": {
                "limits.cpu": "1",
                "limits.cpu.allowance": "50%",
                "limits.memory": "256MiB",
                "user.incus-cn-panel.image": "images:alpine/edge",
                "user.incus-cn-panel.ssh-port": "22001",
            },
            "expanded_devices": {
                "root": {"type": "disk", "path": "/", "size": "2GiB"},
            },
            "state": {"network": {}},
        }])
        self.assertEqual(instances[0]["disk"], "2GiB")
        self.assertEqual(instances[0]["cpu_allowance"], "50%")
        self.assertEqual(instances[0]["ssh_port"], "22001")
        self.assertEqual(instances[0]["image"], "images:alpine/edge")

    def test_operation_log_is_persistent_and_newest_first(self):
        old_values = (app.DATA_DIR, app.OPERATIONS_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.OPERATIONS_FILE = os.path.join(directory, "operations.jsonl")
                app.record_operation("node_add", "node-a", "node-a")
                app.record_operation("instance_create", "web-01", "node-a")
                operations = app.recent_operations()
                self.assertEqual(operations[0]["target"], "web-01")
                self.assertEqual(operations[1]["target"], "node-a")
        finally:
            app.DATA_DIR, app.OPERATIONS_FILE = old_values

    def test_instance_credentials_are_private_and_removable(self):
        old_values = (app.DATA_DIR, app.CREDENTIALS_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.CREDENTIALS_FILE = os.path.join(directory, "credentials.json")
                access = {
                    "host": "203.0.113.10",
                    "host_port": 22001,
                    "guest_port": 22,
                    "username": "root",
                    "password": "strong-password",
                }
                app.save_instance_credentials("node-a", "web-01", access)
                self.assertEqual(app.instance_credentials("node-a", "web-01"), access)
                self.assertEqual(os.stat(app.CREDENTIALS_FILE).st_mode & 0o777, 0o600)
                app.delete_credentials("node-a", "web-01")
                with self.assertRaisesRegex(ValueError, "没有由面板生成"):
                    app.instance_credentials("node-a", "web-01")
        finally:
            app.DATA_DIR, app.CREDENTIALS_FILE = old_values

    @mock.patch("app.run_incus")
    def test_allocate_ssh_port_skips_existing_assignments(self, run_incus):
        run_incus.return_value = json.dumps([
            {"config": {"user.incus-cn-panel.ssh-port": "22000"}},
            {"config": {"user.incus-cn-panel.ssh-port": "22002"}},
        ])
        self.assertEqual(app.allocate_ssh_port("node-a"), "22001")

    def test_create_instance_applies_limits_and_provisions_ssh(self):
        access = {
            "host": "203.0.113.10",
            "host_port": 22001,
            "guest_port": 22,
            "username": "root",
            "password": "generated-password",
        }
        with (
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.require_node", return_value="node-hk-01"),
            mock.patch("app.port_is_used", return_value=False) as port_is_used,
            mock.patch("app.generate_ssh_password", return_value="generated-password"),
            mock.patch("app.provision_ssh") as provision_ssh,
            mock.patch("app.node_host", return_value="203.0.113.10"),
            mock.patch("app.save_instance_credentials") as save_credentials,
        ):
            result = app.create_instance({
                "node": "node-hk-01",
                "name": "web-01",
                "type": "container",
                "image": "images:alpine/edge",
                "cpu": "1",
                "cpu_allowance": "50",
                "memory": "256MiB",
                "disk": "2GiB",
                "ingress": "100Mbit",
                "egress": "50Mbit",
                "read_iops": "100",
                "write_iops": "80",
                "ssh_port": "22001",
            })
        self.assertEqual(result, ("node-hk-01", "web-01", access))
        port_is_used.assert_called_once_with("node-hk-01", "22001")
        provision_ssh.assert_called_once_with("node-hk-01:web-01", "generated-password")
        save_credentials.assert_called_once_with("node-hk-01", "web-01", access)
        self.assertIn(
            mock.call(
                "config", "device", "add", "node-hk-01:web-01", "ssh", "proxy",
                "listen=tcp:0.0.0.0:22001", "connect=tcp:127.0.0.1:22",
            ),
            run_incus.call_args_list,
        )
        self.assertIn(
            mock.call(
                "config", "device", "override", "node-hk-01:web-01", "root",
                "size=2GiB", "limits.read=100iops", "limits.write=80iops",
            ),
            run_incus.call_args_list,
        )

    def test_existing_instance_can_be_given_ssh_access(self):
        instance = {
            "name": "legacy-01",
            "status": "Stopped",
            "config": {},
            "expanded_devices": {},
        }
        access = {
            "host": "203.0.113.10",
            "host_port": 22000,
            "guest_port": 22,
            "username": "root",
            "password": "generated-password",
        }
        with (
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.instance_credentials", side_effect=ValueError("missing")),
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.allocate_ssh_port", return_value="22000"),
            mock.patch("app.generate_ssh_password", return_value="generated-password"),
            mock.patch("app.provision_ssh") as provision_ssh,
            mock.patch("app.node_host", return_value="203.0.113.10"),
            mock.patch("app.save_instance_credentials") as save_credentials,
        ):
            run_incus.return_value = json.dumps(instance)
            result = app.configure_instance_access("node-a", "legacy-01")
        self.assertEqual(result, access)
        self.assertIn(
            mock.call("config", "set", "node-a:legacy-01", "user.incus-cn-panel.ssh-port", "22000"),
            run_incus.call_args_list,
        )
        self.assertIn(mock.call("start", "node-a:legacy-01", timeout=180), run_incus.call_args_list)
        provision_ssh.assert_called_once_with("node-a:legacy-01", "generated-password")
        save_credentials.assert_called_once_with("node-a", "legacy-01", access)


if __name__ == "__main__":
    unittest.main()
