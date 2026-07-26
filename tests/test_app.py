import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


os.environ.setdefault("PANEL_PASSWORD_SALT", "test-salt")
os.environ.setdefault(
    "PANEL_PASSWORD_HASH",
    hashlib.sha256(b"test-salttest-password").hexdigest(),
)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import app  # noqa: E402


class ValidationTests(unittest.TestCase):
    def test_panel_version_and_remote_update_check(self):
        self.assertEqual(app.APP_VERSION, "1.4.1")
        self.assertLess(app.version_tuple("1.4.1"), app.version_tuple("1.5.0"))
        response = mock.MagicMock()
        response.read.return_value = b"1.5.0\n"
        response.__enter__.return_value = response
        with mock.patch("app.urlopen", return_value=response) as urlopen:
            self.assertEqual(app.fetch_latest_version(), "1.5.0")
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 10)
        self.assertEqual(urlopen.call_args.args[0].full_url, app.UPDATE_VERSION_URL)

        response.read.return_value = b"not-a-version\n"
        with mock.patch("app.urlopen", return_value=response), self.assertRaises(RuntimeError):
            app.fetch_latest_version()

        with mock.patch("app.read_update_status", return_value={
            "status": "running", "target_version": "1.5.0",
        }):
            payload = app.panel_version_payload(refresh=False)
        self.assertEqual(payload["latest_version"], "1.5.0")
        self.assertTrue(payload["update_available"])

    def test_panel_update_starts_fixed_systemd_updater(self):
        old_values = (app.DATA_DIR, app.UPDATE_STATUS_FILE, app.UPDATER_PATH)
        try:
            with tempfile.TemporaryDirectory() as directory:
                updater = os.path.join(directory, "incus-cn-panel-update")
                with open(updater, "w", encoding="utf-8") as handle:
                    handle.write("#!/bin/sh\nexit 0\n")
                os.chmod(updater, 0o700)
                app.DATA_DIR = directory
                app.UPDATE_STATUS_FILE = os.path.join(directory, "update-status.json")
                app.UPDATER_PATH = updater
                completed = mock.Mock(returncode=0, stdout="", stderr="")
                with mock.patch("app.subprocess.run", return_value=completed) as run:
                    status = app.start_panel_update("1.5.0")
                self.assertEqual(status["status"], "queued")
                command = run.call_args.args[0]
                self.assertEqual(command[0:3], ["systemd-run", "--quiet", "--collect"])
                self.assertEqual(command[-1], updater)
                self.assertRegex(command[3], r"^--unit=incus-cn-panel-update-[0-9]+$")
                with open(app.UPDATE_STATUS_FILE, encoding="utf-8") as handle:
                    saved = json.load(handle)
                self.assertEqual(saved["target_version"], "1.5.0")
        finally:
            app.DATA_DIR, app.UPDATE_STATUS_FILE, app.UPDATER_PATH = old_values

    def test_admin_can_check_and_start_panel_update(self):
        app.SESSIONS["admin-token"] = {
            "username": "admin", "role": "admin", "csrf": "csrf-token",
            "expires": 9999999999,
        }
        server = app.PanelServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def request(method, path, payload=None):
            connection = http.client.HTTPConnection(
                "127.0.0.1", server.server_address[1], timeout=5,
            )
            headers = {
                "Cookie": "incus_cn_session=admin-token",
                "X-CSRF-Token": "csrf-token",
            }
            body = None
            if payload is not None:
                body = json.dumps(payload)
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            data = json.loads(response.read())
            connection.close()
            return response.status, data

        try:
            version_payload = {
                "current_version": "1.4.1", "latest_version": "1.5.0",
                "update_available": True, "update": {"status": "idle"},
            }
            queued = {"status": "queued", "target_version": "1.5.0"}
            live_payload = {
                "nodes": [{"name": "node-a", "sample_ready": True}],
                "interval_seconds": 5,
            }
            with mock.patch.object(app.Handler, "log_message", return_value=None), \
                 mock.patch("app.panel_version_payload", return_value=version_payload), \
                 mock.patch("app.node_live_payload", return_value=live_payload), \
                 mock.patch("app.fetch_latest_version", return_value="1.5.0"), \
                 mock.patch("app.start_panel_update", return_value=queued), \
                 mock.patch("app.record_operation") as record_operation:
                status, data = request("GET", "/api/system/version?refresh=1")
                self.assertEqual(status, 200)
                self.assertTrue(data["update_available"])
                status, data = request("GET", "/api/nodes/live")
                self.assertEqual(status, 200)
                self.assertEqual(data, live_payload)
                status, data = request("POST", "/api/system/update", {})
                self.assertEqual(status, 202)
                self.assertEqual(data["update"], queued)
                record_operation.assert_called_once()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            app.SESSIONS.clear()

    def test_run_incus_uses_writable_panel_cache(self):
        old_data_dir = app.DATA_DIR
        try:
            with tempfile.TemporaryDirectory() as directory, \
                 mock.patch.dict(os.environ, {"XDG_CACHE_HOME": ""}), \
                 mock.patch("app.subprocess.run") as run:
                app.DATA_DIR = directory
                run.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
                self.assertEqual(app.run_incus("version"), "ok")
                cache_dir = os.path.join(directory, "cache")
                self.assertTrue(os.path.isdir(cache_dir))
                self.assertEqual(os.stat(cache_dir).st_mode & 0o777, 0o700)
                self.assertEqual(run.call_args.kwargs["env"]["XDG_CACHE_HOME"], cache_dir)
        finally:
            app.DATA_DIR = old_data_dir

    def test_node_installer_requires_incus_server_package(self):
        installer = os.path.join(os.path.dirname(app.__file__), "install-node.sh")
        with open(installer, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertIn("dpkg-query -W -f='${Status}' incus", source)
        self.assertNotIn("if ! command -v incus", source)
        self.assertLess(
            source.index("/usr/local/sbin/incus-cn-node-uninstall"),
            source.index("apt-get update"),
        )

    def test_control_installer_includes_version_updater(self):
        root = os.path.dirname(app.__file__)
        with open(os.path.join(root, "install.sh"), encoding="utf-8") as source_file:
            installer = source_file.read()
        with open(os.path.join(root, "uninstall.sh"), encoding="utf-8") as source_file:
            uninstaller = source_file.read()
        for value in ("VERSION", "incus-cn-panel-bootstrap", "incus-cn-panel-update"):
            self.assertIn(value, installer)
        self.assertIn("static/login-datacenter.webp", installer)
        for value in ("password.env", "password_config_rewrite=false", "chmod 0600"):
            self.assertIn(value, installer)
        self.assertIn("incus-cn-panel-update", uninstaller)

    def test_login_preview_asset_is_served(self):
        server = app.PanelServer(("127.0.0.1", 0), app.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.object(app.Handler, "log_message", return_value=None):
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=5,
                )
                connection.request("GET", "/assets/login-datacenter.webp")
                response = connection.getresponse()
                body = response.read()
                connection.close()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.getheader("Content-Type"), "image/webp")
            self.assertTrue(body.startswith(b"RIFF"))
            self.assertIn(b"WEBP", body[:16])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_node_uninstaller_checks_and_removes_known_residuals(self):
        uninstaller = os.path.join(os.path.dirname(app.__file__), "uninstall-node.sh")
        with open(uninstaller, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertIn("apt-get purge -y", source)
        self.assertNotIn("apt-get purge -y incus incus-base incus-client 2>/dev/null || true", source)
        for value in ("/root/.cache/incus", "incusbr0", "Incus controller", "residuals=()"):
            self.assertIn(value, source)

    @mock.patch("app.run_incus")
    def test_ssh_provisioning_reloads_password_authentication(self, run_incus):
        app.provision_ssh("node-a:web-01", "generated-password")
        args = run_incus.call_args.args
        script = args[-1]
        self.assertIn("00-incus-cn-panel.conf", script)
        self.assertIn("/usr/sbin/sshd -t", script)
        self.assertIn('systemctl restart "$service_name"', script)
        self.assertNotIn('systemctl enable --now "$service_name"', script)

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

    def test_size_conversion_and_allocation_summary(self):
        self.assertEqual(app.parse_size_bytes("512MiB"), 512 * 1024**2)
        self.assertEqual(app.parse_size_bytes("2GB"), 2 * 1000**3)
        self.assertEqual(app.parse_size_bytes("不限"), 0)
        summary = app.allocation_summary([
            {"cpu": "2", "memory": "512MiB", "disk": "5GiB", "ssh_port": "22000"},
            {"cpu": "不限", "memory": "25%", "disk": "10GiB", "ssh_port": ""},
        ], 4 * 1024**3)
        self.assertEqual(summary["cpu"], 2)
        self.assertEqual(summary["memory"], 1536 * 1024**2)
        self.assertEqual(summary["disk"], 15 * 1024**3)
        self.assertEqual(summary["unlimited_instances"], 1)
        self.assertEqual(summary["ssh_ports"], 1)

    def test_capacity_treats_cpu_as_shared_and_uses_hard_resources(self):
        maximum, limits = app.maximum_instances({
            "status": "online",
            "cpu": 8,
            "available_cpu": 8,
            "available_memory": 3 * 1024**3,
            "available_disk": 50 * 1024**3,
            "available_ssh_ports": 100,
        }, {"cpu": "2", "memory": "512MiB", "disk": "5GiB"})
        self.assertEqual(limits, {"cpu": "共享", "memory": 6, "disk": 10, "ssh_ports": 100})
        self.assertEqual(maximum, 6)

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

    def test_admin_password_change_is_atomic_and_invalidates_admin_sessions(self):
        old_values = (
            app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS,
            app.PANEL_CONFIG_FILE,
        )
        app.SESSIONS.clear()
        try:
            with tempfile.TemporaryDirectory() as directory:
                config_file = os.path.join(directory, "config.env")
                original = (
                    "# panel settings\n"
                    "PANEL_USER=admin\n"
                    "PANEL_PASSWORD_SALT=old-salt\n"
                    "PANEL_PASSWORD_HASH=old-hash\n"
                    "PANEL_PASSWORD_ITERATIONS=0\n"
                    "PANEL_HOST=0.0.0.0\n"
                    "TLS_CERT=/etc/incus-cn-panel/panel.crt\n"
                )
                with open(config_file, "w", encoding="utf-8") as handle:
                    handle.write(original)
                os.chmod(config_file, 0o644)
                app.PANEL_CONFIG_FILE = config_file
                app.PASSWORD_SALT = "test-salt"
                app.PASSWORD_HASH = hashlib.sha256(b"test-saltcurrent-password").hexdigest()
                app.PASSWORD_ITERATIONS = 0
                app.SESSIONS.update({
                    "admin-one": {"username": "admin", "role": "admin"},
                    "admin-two": {"username": "admin", "role": "admin"},
                    "user-one": {"username": "customer", "role": "user"},
                })

                with self.assertRaisesRegex(ValueError, "当前密码错误"):
                    app.change_admin_password("wrong-password", "new-strong-password")
                with self.assertRaisesRegex(ValueError, "10 到 128"):
                    app.change_admin_password("current-password", "short")
                with open(config_file, encoding="utf-8") as handle:
                    self.assertEqual(handle.read(), original)

                app.change_admin_password("current-password", "new-strong-password")

                with open(config_file, encoding="utf-8") as handle:
                    updated = handle.read()
                self.assertIn("# panel settings\n", updated)
                self.assertIn("PANEL_USER=admin\n", updated)
                self.assertIn("PANEL_HOST=0.0.0.0\n", updated)
                self.assertIn("TLS_CERT=/etc/incus-cn-panel/panel.crt\n", updated)
                self.assertEqual(updated.count("PANEL_PASSWORD_SALT="), 1)
                self.assertEqual(updated.count("PANEL_PASSWORD_HASH="), 1)
                self.assertIn("PANEL_PASSWORD_ITERATIONS=260000\n", updated)
                self.assertEqual(os.stat(config_file).st_mode & 0o777, 0o600)
                self.assertTrue(app.password_matches("new-strong-password"))
                self.assertFalse(app.password_matches("current-password"))
                self.assertNotIn("admin-one", app.SESSIONS)
                self.assertNotIn("admin-two", app.SESSIONS)
                self.assertIn("user-one", app.SESSIONS)
        finally:
            app.SESSIONS.clear()
            (
                app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS,
                app.PANEL_CONFIG_FILE,
            ) = old_values

    def test_admin_password_http_route_requires_admin_and_logs_out(self):
        old_values = (
            app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS,
            app.PANEL_CONFIG_FILE,
        )
        app.SESSIONS.clear()
        server = None
        thread = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                config_file = os.path.join(directory, "config.env")
                with open(config_file, "w", encoding="utf-8") as handle:
                    handle.write("PANEL_USER=admin\nPANEL_HOST=127.0.0.1\n")
                app.PANEL_CONFIG_FILE = config_file
                app.PASSWORD_SALT = "test-salt"
                app.PASSWORD_HASH = hashlib.sha256(b"test-saltcurrent-password").hexdigest()
                app.PASSWORD_ITERATIONS = 0
                app.SESSIONS["admin-token"] = {
                    "username": "admin", "role": "admin", "csrf": "csrf-token",
                    "expires": 9999999999,
                }

                server = app.PanelServer(("127.0.0.1", 0), app.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=5,
                )
                payload = json.dumps({
                    "current_password": "current-password",
                    "new_password": "new-strong-password",
                    "confirm_password": "new-strong-password",
                })
                with mock.patch.object(app.Handler, "log_message", return_value=None), \
                     mock.patch("app.record_operation") as record_operation:
                    connection.request("POST", "/api/account/password", body=payload, headers={
                        "Content-Type": "application/json",
                        "Cookie": "incus_cn_session=admin-token",
                        "X-CSRF-Token": "csrf-token",
                    })
                    response = connection.getresponse()
                    data = json.loads(response.read())
                    headers = dict(response.getheaders())
                connection.close()

                self.assertEqual(response.status, 200)
                self.assertTrue(data["ok"])
                self.assertIn("Max-Age=0", headers["Set-Cookie"])
                self.assertTrue(app.password_matches("new-strong-password"))
                self.assertFalse(app.password_matches("current-password"))
                self.assertNotIn("admin-token", app.SESSIONS)
                record_operation.assert_called_once_with(
                    "admin_password_change", app.PANEL_USER, message="管理员密码已修改",
                )
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=5)
            app.SESSIONS.clear()
            (
                app.PASSWORD_SALT, app.PASSWORD_HASH, app.PASSWORD_ITERATIONS,
                app.PANEL_CONFIG_FILE,
            ) = old_values

    def test_user_accounts_are_private_authenticatable_and_disable_sessions(self):
        old_values = (app.DATA_DIR, app.USERS_FILE)
        app.SESSIONS.clear()
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.USERS_FILE = os.path.join(directory, "users.json")
                user = app.create_user_account("customer-01", "strong-password")
                self.assertEqual(user["username"], "customer-01")
                self.assertEqual(os.stat(app.USERS_FILE).st_mode & 0o777, 0o600)
                self.assertEqual(
                    app.authenticate_account("customer-01", "strong-password"),
                    {"username": "customer-01", "role": "user"},
                )
                self.assertIsNone(app.authenticate_account("customer-01", "wrong-password"))
                app.SESSIONS["customer-session"] = {
                    "username": "customer-01", "role": "user",
                    "csrf": "token", "expires": 9999999999,
                }
                app.update_user_account("customer-01", enabled=False)
                self.assertNotIn("customer-session", app.SESSIONS)
                self.assertIsNone(app.authenticate_account("customer-01", "strong-password"))
        finally:
            app.SESSIONS.clear()
            app.DATA_DIR, app.USERS_FILE = old_values

    def test_expiring_assignments_filter_user_overview_and_access(self):
        old_values = (app.DATA_DIR, app.USERS_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.USERS_FILE = os.path.join(directory, "users.json")
                app.create_user_account("customer-02", "strong-password")
                future = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
                past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                app.update_user_account("customer-02", assignments=[
                    {"instance": "node-a/web-01", "expires_at": future},
                    {"instance": "node-a/old-01", "expires_at": past},
                ])
                session = {"username": "customer-02", "role": "user"}
                self.assertTrue(app.session_can_access_instance(session, "node-a", "web-01"))
                self.assertFalse(app.session_can_access_instance(session, "node-a", "old-01"))
                self.assertFalse(app.session_can_access_instance(session, "node-a", "other-01"))
                nodes = [{
                    "name": "node-a", "address": "https://203.0.113.10:8443",
                    "status": "online", "memory": 1024, "private": "not-returned",
                }]
                instances = [
                    {"node": "node-a", "name": "web-01"},
                    {"node": "node-a", "name": "old-01"},
                    {"node": "node-a", "name": "other-01"},
                ]
                with mock.patch("app.overview", return_value=(nodes, instances)):
                    payload = app.overview_for_session(session)
                self.assertEqual(payload["instances"], [{
                    "node": "node-a",
                    "name": "web-01",
                    "authorization_expires_at": app.parse_assignment_expiry(future),
                }])
                self.assertEqual(payload["nodes"], [{
                    "name": "node-a", "address": "https://203.0.113.10:8443",
                    "status": "online",
                }])
                self.assertEqual(payload["operations"], [])
                self.assertEqual(payload["public_images"], [])
                app.remove_instance_assignments("node-a", "web-01")
                self.assertFalse(app.session_can_access_instance(session, "node-a", "web-01"))
        finally:
            app.DATA_DIR, app.USERS_FILE = old_values

    def test_assignment_expiry_requires_timezone(self):
        with self.assertRaisesRegex(ValueError, "必须包含时区"):
            app.parse_assignment_expiry("2026-08-01T00:00:00")

    def test_notification_config_is_private_and_hides_bot_token(self):
        old_values = (
            app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.NOTIFICATION_CONFIG_FILE = os.path.join(directory, "notification-config.json")
                app.NOTIFICATIONS_FILE = os.path.join(directory, "notifications.json")
                public = app.update_notification_config({
                    "interval_seconds": 120,
                    "thresholds": {"memory_percent": 85},
                    "rules": {"node_offline": "panel_telegram"},
                    "telegram": {
                        "enabled": True,
                        "bot_token": "123456789:abcdefghijklmnopqrstuvwxyz_123456",
                        "chat_id": "-1001234567890",
                        "send_recovery": False,
                    },
                })
                self.assertEqual(os.stat(app.NOTIFICATION_CONFIG_FILE).st_mode & 0o777, 0o600)
                self.assertTrue(public["telegram"]["token_configured"])
                self.assertNotIn("bot_token", public["telegram"])
                self.assertEqual(public["thresholds"]["memory_percent"], 85)
                stored = app.read_notification_config()
                self.assertEqual(
                    stored["telegram"]["bot_token"],
                    "123456789:abcdefghijklmnopqrstuvwxyz_123456",
                )
                self.assertFalse(stored["telegram"]["send_recovery"])
        finally:
            app.MONITOR_WAKE_EVENT.clear()
            (
                app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
            ) = old_values

    def test_detect_anomalies_covers_nodes_instances_and_missing_state(self):
        config = app.default_notification_config()
        config["rules"] = {key: "panel" for key in app.ALERT_RULES}
        config["thresholds"] = {
            "memory_percent": 80,
            "disk_percent": 80,
            "load_percent": 100,
            "instance_memory_percent": 90,
            "instance_cpu_percent": 90,
        }
        nodes = [
            {
                "name": "node-offline", "status": "offline", "error": "timeout",
                "memory": 0, "memory_used": 0, "disk": 0, "disk_used": 0,
                "load": 0, "cpu": 0, "image_error": "",
            },
            {
                "name": "node-a", "status": "online", "error": "",
                "memory": 1000, "memory_used": 900, "disk": 1000, "disk_used": 850,
                "load": 3, "cpu": 2, "image_error": "catalog failed",
            },
        ]
        instances = [
            {"node": "node-a", "name": "stopped", "status": "Stopped", "ipv4": ""},
            {
                "node": "node-a", "name": "no-ip", "status": "Running", "ipv4": "",
                "memory_used_bytes": 95, "memory_total_bytes": 100,
                "cpu_usage_ns": 61_000_000_000, "cpu_allocated_ns": 1_000_000_000,
                "traffic_exceeded": True, "traffic_action": "stop",
                "traffic_used_bytes": 600 * 1024**3,
                "traffic_limit_bytes": 500 * 1024**3,
            },
        ]
        previous = {
            "initialized": True,
            "captured_at": (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat(),
            "nodes": {"node-a": "online"},
            "instances": {
                "node-a/missing": "Running",
                "node-a/no-ip": {"status": "Running", "cpu_usage_ns": 1_000_000_000},
            },
        }
        anomalies, snapshot = app.detect_anomalies(nodes, instances, config, previous)
        self.assertEqual(set(anomalies), {
            "node_offline:node-offline",
            "node_memory_high:node-a",
            "node_disk_high:node-a",
            "node_load_high:node-a",
            "node_image_error:node-a",
            "instance_memory_high:node-a/no-ip",
            "instance_cpu_high:node-a/no-ip",
            "instance_not_running:node-a/stopped",
            "instance_no_ipv4:node-a/no-ip",
            "instance_missing:node-a/missing",
            "instance_traffic_exceeded:node-a/no-ip",
        })
        self.assertTrue(snapshot["initialized"])
        first_scan, _ = app.detect_anomalies(nodes, instances, config, {})
        self.assertNotIn("instance_missing:node-a/missing", first_scan)

    def test_traffic_usage_accumulates_and_stops_exceeded_instance(self):
        old_values = (app.DATA_DIR, app.TRAFFIC_FILE, app.OPERATIONS_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.TRAFFIC_FILE = os.path.join(directory, "traffic-usage.json")
                app.OPERATIONS_FILE = os.path.join(directory, "operations.jsonl")
                limit = 1024**3
                app.initialize_traffic_usage(
                    "node-a", "web-01", limit, "stop",
                    rx_bytes=100 * 1024**2, tx_bytes=50 * 1024**2,
                )
                instances = [{
                    "node": "node-a", "name": "web-01", "status": "Running",
                    "traffic_limit_bytes": limit, "traffic_action": "stop",
                    "network_rx_bytes": 700 * 1024**2,
                    "network_tx_bytes": 650 * 1024**2,
                }]
                with mock.patch("app.run_incus") as run_incus:
                    app.update_traffic_usage(instances)
                run_incus.assert_called_once_with(
                    "stop", "node-a:web-01", "--force", timeout=180,
                )
                self.assertTrue(instances[0]["traffic_exceeded"])
                self.assertGreater(instances[0]["traffic_used_bytes"], limit)
                data = app.read_traffic_data()
                record = data["instances"]["node-a/web-01"]
                self.assertTrue(record["enforced_at"])
                self.assertEqual(os.stat(app.TRAFFIC_FILE).st_mode & 0o777, 0o600)
        finally:
            app.DATA_DIR, app.TRAFFIC_FILE, app.OPERATIONS_FILE = old_values

    def test_traffic_new_month_resets_usage_without_replaying_counters(self):
        old_values = (app.DATA_DIR, app.TRAFFIC_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.TRAFFIC_FILE = os.path.join(directory, "traffic-usage.json")
                app.initialize_traffic_usage("node-a", "web-01", 1024**3, "stop")
                data = app.read_traffic_data()
                data["instances"]["node-a/web-01"].update({
                    "period": "2000-01", "used_bytes": 2 * 1024**3,
                    "last_rx_bytes": 5000, "last_tx_bytes": 5000,
                })
                with app.TRAFFIC_LOCK:
                    app._write_traffic_data(data)
                instances = [{
                    "node": "node-a", "name": "web-01", "status": "Stopped",
                    "traffic_limit_bytes": 1024**3, "traffic_action": "stop",
                    "network_rx_bytes": 9000, "network_tx_bytes": 9000,
                }]
                app.update_traffic_usage(instances)
                self.assertEqual(instances[0]["traffic_used_bytes"], 0)
                self.assertFalse(instances[0]["traffic_exceeded"])
                record = app.read_traffic_data()["instances"]["node-a/web-01"]
                self.assertEqual(record["last_rx_bytes"], 9000)
                self.assertEqual(record["last_tx_bytes"], 9000)
        finally:
            app.DATA_DIR, app.TRAFFIC_FILE = old_values

    def test_traffic_quota_validation(self):
        self.assertEqual(
            app.validate_traffic_quota(500 * 1024**3, "stop"),
            (500 * 1024**3, "stop"),
        )
        self.assertEqual(app.validate_traffic_quota(0, "notify"), (0, "notify"))
        with self.assertRaisesRegex(ValueError, "1 GiB"):
            app.validate_traffic_quota(1024**2, "stop")
        with self.assertRaisesRegex(ValueError, "处理方式"):
            app.validate_traffic_quota(1024**3, "delete")

    def test_update_instance_traffic_quota_sets_metadata_and_baseline(self):
        old_values = (app.DATA_DIR, app.TRAFFIC_FILE)
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.TRAFFIC_FILE = os.path.join(directory, "traffic-usage.json")
                instance = {
                    "name": "web-01", "type": "container", "status": "Running",
                    "config": {}, "expanded_devices": {},
                }
                state = {"network": {"eth0": {
                    "type": "broadcast",
                    "counters": {"bytes_received": 1234, "bytes_sent": 5678},
                }}}
                with (
                    mock.patch("app.require_node", return_value="node-a"),
                    mock.patch("app.run_incus", side_effect=[
                        json.dumps(instance), None, None, json.dumps(state),
                    ]) as run_incus,
                ):
                    result = app.update_instance_traffic_quota(
                        "node-a", "web-01", 500 * 1024**3, "notify", True,
                    )
                self.assertEqual(result["limit_bytes"], 500 * 1024**3)
                self.assertEqual(result["action"], "notify")
                self.assertEqual(run_incus.call_args_list[1:3], [
                    mock.call(
                        "config", "set", "node-a:web-01",
                        "user.incus-cn-panel.traffic-limit-bytes", str(500 * 1024**3),
                    ),
                    mock.call(
                        "config", "set", "node-a:web-01",
                        "user.incus-cn-panel.traffic-action", "notify",
                    ),
                ])
                record = app.read_traffic_data()["instances"]["node-a/web-01"]
                self.assertEqual(record["last_rx_bytes"], 1234)
                self.assertEqual(record["last_tx_bytes"], 5678)
                self.assertEqual(record["used_bytes"], 0)
        finally:
            app.DATA_DIR, app.TRAFFIC_FILE = old_values

    def test_notification_events_are_deduplicated_and_resolved(self):
        old_values = (
            app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.NOTIFICATION_CONFIG_FILE = os.path.join(directory, "notification-config.json")
                app.NOTIFICATIONS_FILE = os.path.join(directory, "notifications.json")
                config = app.default_notification_config()
                config["telegram"].update({
                    "enabled": True,
                    "bot_token": "123456789:abcdefghijklmnopqrstuvwxyz_123456",
                    "chat_id": "-1001234567890",
                })
                anomaly = app._anomaly(
                    "node_offline:node-a", "node_offline", "node-a", "node-a",
                    "宿主机 node-a 离线", "timeout",
                )
                snapshot = {"initialized": True, "nodes": {"node-a": "offline"}, "instances": {}}
                with mock.patch("app.send_telegram_message") as send_telegram:
                    app._persist_anomalies(config, {anomaly["key"]: anomaly}, snapshot)
                    app._persist_anomalies(config, {anomaly["key"]: anomaly}, snapshot)
                    self.assertEqual(send_telegram.call_count, 1)
                    app._persist_anomalies(config, {}, snapshot)
                    self.assertEqual(send_telegram.call_count, 2)
                data = app.read_notification_data()
                self.assertEqual(len(data["active"]), 0)
                self.assertEqual(len(data["events"]), 2)
                payload = app.notification_payload()
                self.assertEqual(payload["active_count"], 0)
                self.assertEqual(len(payload["events"]), 2)
                self.assertEqual(payload["events"][0]["kind"], "recovery")
                self.assertEqual(os.stat(app.NOTIFICATIONS_FILE).st_mode & 0o777, 0o600)
                read_payload = app.mark_notifications_read()
                self.assertEqual(read_payload["unread_count"], 0)
        finally:
            (
                app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
            ) = old_values

    def test_telegram_delivery_errors_redact_bot_token(self):
        old_values = (
            app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
        )
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.NOTIFICATION_CONFIG_FILE = os.path.join(directory, "notification-config.json")
                app.NOTIFICATIONS_FILE = os.path.join(directory, "notifications.json")
                config = app.default_notification_config()
                token = "123456789:abcdefghijklmnopqrstuvwxyz_123456"
                config["telegram"].update({
                    "enabled": True,
                    "bot_token": token,
                    "chat_id": "-1001234567890",
                })
                anomaly = app._anomaly(
                    "node_offline:node-a", "node_offline", "node-a", "node-a",
                    "宿主机 node-a 离线", "timeout",
                )
                snapshot = {"initialized": True, "nodes": {}, "instances": {}}
                error = f"request failed at https://api.telegram.org/bot{token}/sendMessage"
                with mock.patch("app.send_telegram_message", side_effect=RuntimeError(error)):
                    app._persist_anomalies(config, {anomaly["key"]: anomaly}, snapshot)
                data = app.read_notification_data()
                self.assertNotIn(token, json.dumps(data))
                self.assertIn("bot***/sendMessage", data["telegram_last_error"])
        finally:
            (
                app.DATA_DIR, app.NOTIFICATION_CONFIG_FILE, app.NOTIFICATIONS_FILE,
            ) = old_values

    def test_telegram_sender_posts_structured_message(self):
        config = app.default_notification_config()
        config["telegram"].update({
            "bot_token": "123456789:abcdefghijklmnopqrstuvwxyz_123456",
            "chat_id": "-1001234567890",
        })
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"ok":true}'
        with mock.patch("app.urlopen", return_value=response) as urlopen:
            self.assertTrue(app.send_telegram_message(config, "test message"))
        request = urlopen.call_args.args[0]
        self.assertIn(config["telegram"]["bot_token"], request.full_url)
        self.assertEqual(json.loads(request.data)["chat_id"], "-1001234567890")
        self.assertEqual(json.loads(request.data)["text"], "test message")
        self.assertEqual(
            app.redact_telegram_token(
                f"https://api.telegram.org/bot{config['telegram']['bot_token']}/sendMessage",
                config["telegram"]["bot_token"],
            ),
            "https://api.telegram.org/bot***/sendMessage",
        )

    def test_http_permissions_enforce_active_instance_assignments(self):
        old_values = (app.DATA_DIR, app.USERS_FILE)
        app.SESSIONS.clear()
        server = None
        thread = None
        try:
            with tempfile.TemporaryDirectory() as directory:
                app.DATA_DIR = directory
                app.USERS_FILE = os.path.join(directory, "users.json")
                app.create_user_account("customer-03", "strong-password")
                future = (datetime.now(timezone.utc) + timedelta(days=31)).isoformat()
                app.update_user_account("customer-03", assignments=[
                    {"instance": "node-a/web-01", "expires_at": future},
                ])
                app.SESSIONS["customer-token"] = {
                    "username": "customer-03",
                    "role": "user",
                    "csrf": "csrf-token",
                    "expires": 9999999999,
                }

                server = app.PanelServer(("127.0.0.1", 0), app.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()

                def request(method, path, payload=None):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", server.server_address[1], timeout=5
                    )
                    headers = {
                        "Cookie": "incus_cn_session=customer-token",
                        "X-CSRF-Token": "csrf-token",
                    }
                    body = None
                    if payload is not None:
                        body = json.dumps(payload)
                        headers["Content-Type"] = "application/json"
                    connection.request(method, path, body=body, headers=headers)
                    response = connection.getresponse()
                    data = json.loads(response.read())
                    connection.close()
                    return response.status, data

                with mock.patch.object(app.Handler, "log_message", return_value=None), \
                     mock.patch("app.require_node", return_value="node-a"), \
                     mock.patch("app.instance_credentials", return_value={"username": "root"}), \
                     mock.patch("app.record_operation"), \
                     mock.patch("app.run_incus") as run_incus:
                    run_incus.side_effect = [json.dumps({"config": {}}), None]
                    self.assertEqual(request("GET", "/api/users")[0], 403)
                    self.assertEqual(request("GET", "/api/notifications")[0], 403)
                    self.assertEqual(request("GET", "/api/system/version?refresh=1")[0], 403)
                    self.assertEqual(request("GET", "/api/nodes/live")[0], 403)
                    self.assertEqual(request("POST", "/api/instances", {})[0], 403)
                    self.assertEqual(request("POST", "/api/system/update", {})[0], 403)
                    self.assertEqual(request("POST", "/api/account/password", {})[0], 403)
                    self.assertEqual(request("POST", "/api/notifications/scan", {})[0], 403)
                    self.assertEqual(request(
                        "POST", "/api/nodes/node-a/instances/web-01/traffic", {},
                    )[0], 403)
                    self.assertEqual(request("DELETE", "/api/users/customer-03")[0], 403)
                    status, data = request(
                        "GET", "/api/nodes/node-a/instances/web-01/access"
                    )
                    self.assertEqual(status, 200)
                    self.assertEqual(data["access"], {"username": "root"})
                    self.assertEqual(
                        request("GET", "/api/nodes/node-a/instances/other-01/access")[0],
                        403,
                    )
                    self.assertEqual(request(
                        "POST",
                        "/api/nodes/node-a/instances/web-01/action",
                        {"action": "restart"},
                    )[0], 200)
                    self.assertEqual(run_incus.call_args_list, [
                        mock.call(
                            "query", "node-a:/1.0/instances/web-01?recursion=1", timeout=20,
                        ),
                        mock.call("restart", "node-a:web-01", "--force", timeout=180),
                    ])

                    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                    app.update_user_account("customer-03", assignments=[
                        {"instance": "node-a/web-01", "expires_at": past},
                    ])
                    self.assertEqual(request(
                        "GET", "/api/nodes/node-a/instances/web-01/access"
                    )[0], 403)
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=5)
            app.SESSIONS.clear()
            app.DATA_DIR, app.USERS_FILE = old_values

    def test_chinese_ui_and_relative_api_base(self):
        self.assertIn("Incus Control", app.HTML)
        self.assertIn('id="toggleLoginPassword"', app.HTML)
        self.assertIn('id="loginSubmit"', app.HTML)
        self.assertIn('id="loginErrorText"', app.HTML)
        self.assertIn("assets/login-datacenter.webp", app.HTML)
        self.assertIn("function setLoginError", app.HTML)
        self.assertIn("正在登录", app.HTML)
        self.assertIn("切割实例", app.HTML)
        self.assertIn("添加宿主机", app.HTML)
        self.assertIn("月流量配额", app.HTML)
        self.assertIn('id="trafficDialog"', app.HTML)
        self.assertIn('id="managedTrafficValue" type="number" min="1" max="1048576" step="any"', app.HTML)
        self.assertIn("String(Math.round(Number($('managedTrafficValue').value)*multiplier))", app.HTML)
        self.assertIn('data-traffic-instance=', app.HTML)
        self.assertIn('data-view="operations"', app.HTML)
        self.assertIn('data-view="updates"', app.HTML)
        self.assertIn('id="checkUpdate"', app.HTML)
        self.assertIn('id="startUpdate"', app.HTML)
        self.assertIn("/api/system/version", app.HTML)
        self.assertIn("/api/system/update", app.HTML)
        self.assertIn('id="openAdminAccount"', app.HTML)
        self.assertIn('id="adminAccountDialog"', app.HTML)
        self.assertIn("/api/account/password", app.HTML)
        self.assertIn("/api/nodes/live", app.HTML)
        for label in ("实例 CPU", "宿主机内存", "实例下载", "实例上传"):
            self.assertIn(label, app.HTML)
        self.assertIn("startNodeLivePolling", app.HTML)
        self.assertIn("location.pathname", app.HTML)
        self.assertIn("apiBase+path", app.HTML)
        self.assertIn("const iconSvg=", app.HTML)
        self.assertNotIn("lucide.createIcons", app.HTML)

    def test_instance_actions_are_labeled_and_show_pending_state(self):
        for label in (">SSH</span>", ">流量</span>", "'开机中'", "'关机中'", "'重启中'"):
            self.assertIn(label, app.HTML)
        self.assertIn("pendingInstanceActions", app.HTML)
        self.assertIn("instance-action-spin", app.HTML)
        self.assertIn("prefers-reduced-motion:reduce", app.HTML)

    def test_csp_allows_same_origin_scripts(self):
        with open(app.__file__, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertEqual(source.count("script-src 'self' 'unsafe-inline'"), 2)

    def test_service_can_only_write_required_password_config(self):
        service_file = os.path.join(os.path.dirname(app.__file__), "incus-cn-panel.service")
        with open(service_file, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("EnvironmentFile=-/var/lib/incus-cn-panel/password.env", source)
        self.assertIn(
            "ReadWritePaths=/etc/incus-cn-panel/incus-client /var/lib/incus-cn-panel",
            source,
        )
        self.assertNotIn("ReadWritePaths=/etc/incus-cn-panel/config.env", source)

    def test_tls_handshake_cannot_block_the_accept_loop(self):
        with open(app.__file__, encoding="utf-8") as source_file:
            source = source_file.read()
        self.assertIn("do_handshake_on_connect=False", source)
        self.assertGreaterEqual(app.PanelServer.request_queue_size, 128)
        self.assertTrue(app.PanelServer.daemon_threads)

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
                "user.incus-cn-panel.port-start": "10000",
                "user.incus-cn-panel.port-end": "10010",
                "user.incus-cn-panel.traffic-limit-bytes": str(500 * 1024**3),
                "user.incus-cn-panel.traffic-action": "stop",
            },
            "expanded_devices": {
                "root": {"type": "disk", "path": "/", "size": "2GiB"},
            },
            "state": {"network": {
                "eth0": {
                    "type": "broadcast",
                    "counters": {"bytes_received": 1200, "bytes_sent": 300},
                },
                "lo": {
                    "type": "loopback",
                    "counters": {"bytes_received": 9999, "bytes_sent": 9999},
                },
                "eth1": {
                    "type": "broadcast",
                    "counters": {"bytes_received": 800, "bytes_sent": 700},
                },
            }},
        }])
        self.assertEqual(instances[0]["disk"], "2GiB")
        self.assertEqual(instances[0]["cpu_allowance"], "50%")
        self.assertEqual(instances[0]["ssh_port"], "22001")
        self.assertEqual(instances[0]["image"], "images:alpine/edge")
        self.assertEqual(instances[0]["port_start"], "10000")
        self.assertEqual(instances[0]["port_end"], "10010")
        self.assertEqual(instances[0]["memory_used_bytes"], 0)
        self.assertEqual(instances[0]["cpu_usage_ns"], 0)
        self.assertEqual(instances[0]["traffic_limit_bytes"], 500 * 1024**3)
        self.assertEqual(instances[0]["traffic_action"], "stop")
        self.assertEqual(instances[0]["network_rx_bytes"], 2000)
        self.assertEqual(instances[0]["network_tx_bytes"], 1000)

    @mock.patch("app.run_incus")
    def test_live_node_snapshot_aggregates_instance_counters(self, run_incus):
        resources = {
            "cpu": {"total": 2},
            "memory": {"total": 2 * 1024**3, "used": 768 * 1024**2},
            "load": {"Average1Min": 0.75},
            "storage": {"disks": [{"size": 20 * 1024**3}]},
        }
        instances = [{
            "name": "vps-01", "status": "Running",
            "state": {
                "cpu": {"usage": 4_000_000_000},
                "network": {"eth0": {
                    "type": "broadcast",
                    "counters": {"bytes_received": 8_000_000, "bytes_sent": 3_000_000},
                }},
            },
        }]
        pool = {"space": {"total": 15 * 1024**3, "used": 5 * 1024**3}}
        run_incus.side_effect = [json.dumps(resources), json.dumps(instances), json.dumps(pool)]

        sample = app.inspect_node_live("node-a", {})

        self.assertEqual(sample["status"], "online")
        self.assertEqual(sample["cpu"], 2)
        self.assertEqual(sample["load"], 0.75)
        self.assertEqual(sample["memory_used"], 768 * 1024**2)
        self.assertEqual(sample["disk"], 15 * 1024**3)
        self.assertEqual(sample["disk_used"], 5 * 1024**3)
        self.assertEqual(sample["instance_cpu_usage_ns"], 4_000_000_000)
        self.assertEqual(sample["instance_network_rx_bytes"], 8_000_000)
        self.assertEqual(sample["instance_network_tx_bytes"], 3_000_000)

    def test_live_node_rates_use_counter_deltas_and_handle_resets(self):
        previous = {
            "status": "online", "instance_cpu_usage_ns": 10_000_000_000,
            "instance_network_rx_bytes": 5_000_000,
            "instance_network_tx_bytes": 2_000_000,
        }
        sample = {
            "name": "node-a", "status": "online", "cpu": 2,
            "instance_cpu_usage_ns": 11_000_000_000,
            "instance_network_rx_bytes": 10_000_000,
            "instance_network_tx_bytes": 4_500_000,
        }
        rates = app.node_live_rates(sample, previous, 5)
        self.assertTrue(rates["sample_ready"])
        self.assertAlmostEqual(rates["instance_cpu_percent"], 10.0)
        self.assertAlmostEqual(rates["network_rx_bytes_per_second"], 1_000_000)
        self.assertAlmostEqual(rates["network_tx_bytes_per_second"], 500_000)

        reset = app.node_live_rates({**sample, "instance_network_rx_bytes": 1}, previous, 5)
        self.assertFalse(reset["sample_ready"])

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

    @mock.patch("app.run_incus")
    def test_allocate_ssh_port_also_skips_business_range(self, run_incus):
        run_incus.return_value = json.dumps([
            {"config": {
                "user.incus-cn-panel.port-start": "22000",
                "user.incus-cn-panel.port-end": "22002",
            }},
            {"config": {"user.incus-cn-panel.ssh-port": "22004"}},
        ])
        self.assertEqual(app.allocate_ssh_port("node-a"), "22003")

    def test_port_range_validation_and_conflict_aware_blocks(self):
        self.assertEqual(app.validate_port_range("10000", "10010"), (10000, 10010))
        with self.assertRaisesRegex(ValueError, "最多分配 1000"):
            app.validate_port_range("10000", "11000")
        blocks = app.available_port_blocks([
            {"port_start": "10003", "port_end": "10005", "ssh_port": "10009"},
        ], 10000, 10014, 3)
        self.assertEqual(blocks, [(10000, 10002), (10006, 10008), (10010, 10012)])

    def test_public_catalog_includes_profiles_for_lxc_and_kvm(self):
        catalog = app.public_image_catalog()
        ubuntu = next(image for image in catalog if image["id"] == "images:ubuntu/24.04")
        self.assertEqual(ubuntu["source"], "public")
        self.assertEqual(ubuntu["profiles"]["container"]["minimum_memory"], "512MiB")
        self.assertEqual(ubuntu["profiles"]["virtual-machine"]["recommended_disk"], "12GiB")

    def test_parse_node_images_exposes_local_fingerprint_and_profile(self):
        images = app.parse_node_images("node-a", [{
            "fingerprint": "a" * 64,
            "aliases": [{"name": "custom/debian-12"}],
            "properties": {"os": "Debian", "release": "12", "description": "Debian 12"},
            "type": "container",
            "architecture": "x86_64",
            "size": 123456,
        }])
        self.assertEqual(images[0]["id"], f"local:{'a' * 64}")
        self.assertEqual(images[0]["family"], "debian")
        self.assertEqual(images[0]["profiles"]["container"]["minimum_disk"], "3GiB")

    def test_resolve_local_image_is_node_scoped_and_type_checked(self):
        local = {
            "id": f"local:{'b' * 64}", "fingerprint": "b" * 64,
            "kind": "container", "family": "alpine",
        }
        with mock.patch("app.list_node_images", return_value=[local]) as list_images:
            resolved = app.resolve_image("node-a", f"local:{'b' * 12}", "container")
            self.assertEqual(resolved["reference"], f"node-a:{'b' * 64}")
            list_images.assert_called_once_with("node-a")
            with self.assertRaisesRegex(ValueError, "仅支持 LXC"):
                app.resolve_image("node-a", f"local:{'b' * 12}", "virtual-machine")

    def test_image_management_builds_incus_commands(self):
        with (
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.list_node_images", return_value=[]) as list_images,
        ):
            app.copy_public_image("node-a", "images:alpine/3.22", "cached/alpine")
            app.import_local_image("node-a", "/private/image.tar", "custom/alpine")
            app.delete_local_image("node-a", "c" * 64)
        self.assertIn(
            mock.call("image", "copy", "images:alpine/3.22", "node-a:", "--alias", "cached/alpine", timeout=1800),
            run_incus.call_args_list,
        )
        self.assertIn(
            mock.call("image", "import", "/private/image.tar", "node-a:", "--alias", "custom/alpine", timeout=1800),
            run_incus.call_args_list,
        )
        self.assertIn(
            mock.call("image", "delete", f"node-a:{'c' * 64}", timeout=180),
            run_incus.call_args_list,
        )
        self.assertEqual(list_images.call_count, 2)

    def test_create_rejects_resources_below_image_minimum(self):
        with mock.patch("app.require_node", return_value="node-a"):
            with self.assertRaisesRegex(ValueError, "最低需要 512MiB 内存"):
                app.create_instance({
                    "node": "node-a", "name": "too-small", "type": "container",
                    "image": "images:ubuntu/24.04", "cpu": "1", "cpu_allowance": "100",
                    "memory": "256MiB", "disk": "8GiB", "read_iops": "0",
                    "write_iops": "0",
                })

    def test_create_instance_applies_limits_and_provisions_ssh(self):
        access = {
            "host": "203.0.113.10",
            "host_port": 22001,
            "guest_port": 22,
            "username": "root",
            "password": "generated-password",
            "port_start": 10000,
            "port_end": 10010,
            "port_count": 11,
        }
        with (
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.require_node", return_value="node-hk-01"),
            mock.patch("app.port_is_used", return_value=False) as port_is_used,
            mock.patch("app.generate_ssh_password", return_value="generated-password"),
            mock.patch("app.provision_ssh") as provision_ssh,
            mock.patch("app.node_host", return_value="203.0.113.10"),
            mock.patch("app.save_instance_credentials") as save_credentials,
            mock.patch("app.initialize_traffic_usage") as initialize_traffic,
        ):
            run_incus.return_value = "[]"
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
                "port_start": "10000",
                "port_end": "10010",
                "traffic_limit_bytes": str(500 * 1024**3),
                "traffic_action": "stop",
            })
        self.assertEqual(result, ("node-hk-01", "web-01", access))
        port_is_used.assert_called_once_with("node-hk-01", "22001")
        provision_ssh.assert_called_once_with("node-hk-01:web-01", "generated-password")
        save_credentials.assert_called_once_with("node-hk-01", "web-01", access)
        initialize_traffic.assert_called_once_with(
            "node-hk-01", "web-01", 500 * 1024**3, "stop", reset=True,
        )
        init_call = next(call for call in run_incus.call_args_list if call.args[0] == "init")
        self.assertIn(f"user.incus-cn-panel.traffic-limit-bytes={500 * 1024**3}", init_call.args)
        self.assertIn("user.incus-cn-panel.traffic-action=stop", init_call.args)
        self.assertIn(
            mock.call(
                "config", "device", "add", "node-hk-01:web-01", "ssh", "proxy",
                "listen=tcp:0.0.0.0:22001", "connect=tcp:127.0.0.1:22",
            ),
            run_incus.call_args_list,
        )
        self.assertIn(
            mock.call(
                "config", "device", "add", "node-hk-01:web-01", "ports", "proxy",
                "listen=tcp:0.0.0.0:10000-10010",
                "connect=tcp:127.0.0.1:10000-10010",
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

    def test_create_instance_skips_unlimited_iops_and_network_limits(self):
        with (
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.allocate_ssh_port", return_value="22000"),
            mock.patch("app.generate_ssh_password", return_value="generated-password"),
            mock.patch("app.provision_ssh"),
            mock.patch("app.node_host", return_value="203.0.113.10"),
            mock.patch("app.save_instance_credentials"),
        ):
            app.create_instance({
                "node": "node-a", "name": "free-io", "type": "container",
                "image": "images:alpine/edge", "cpu": "1", "cpu_allowance": "100",
                "memory": "256MiB", "disk": "2GiB", "ingress": "", "egress": "",
                "read_iops": "0", "write_iops": "0", "ssh_port": "",
            })
        calls = run_incus.call_args_list
        self.assertIn(
            mock.call("config", "device", "override", "node-a:free-io", "root", "size=2GiB"),
            calls,
        )
        self.assertFalse(any(
            call.args[:5] == ("config", "device", "override", "node-a:free-io", "eth0")
            for call in calls
        ))

    def test_batch_creation_uses_padded_names_and_capacity_limit(self):
        node_info = {
            "status": "online", "cpu": 4, "available_cpu": 4,
            "available_memory": 2 * 1024**3, "available_disk": 8 * 1024**3,
            "available_ssh_ports": 100, "instances": [],
        }

        def create(data):
            access = {"host": "203.0.113.10", "host_port": 22000, "guest_port": 22,
                      "username": "root", "password": "password"}
            return "node-a", data["name"], access

        with (
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.live_node_info", return_value=node_info),
            mock.patch("app.create_instance", side_effect=create) as create_mock,
        ):
            node, created = app.create_batch_instances({
                "node": "node-a", "name_prefix": "vps-", "start_index": 7,
                "padding": 3, "count": 2, "cpu": "1", "memory": "256MiB",
                "disk": "2GiB", "port_pool_start": "10000",
                "port_pool_end": "10009", "port_count": "3",
                "traffic_allocation": "batch_total",
                "traffic_total_bytes": str(500 * 1024**3),
                "traffic_action": "stop",
            })
        self.assertEqual(node, "node-a")
        self.assertEqual([item["name"] for item in created], ["vps-007", "vps-008"])
        self.assertEqual(
            [call.args[0]["name"] for call in create_mock.call_args_list],
            ["vps-007", "vps-008"],
        )
        self.assertEqual(
            [(call.args[0]["port_start"], call.args[0]["port_end"]) for call in create_mock.call_args_list],
            [(10000, 10002), (10003, 10005)],
        )
        self.assertEqual(
            [call.args[0]["traffic_limit_bytes"] for call in create_mock.call_args_list],
            [str(250 * 1024**3), str(250 * 1024**3)],
        )

        with (
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.live_node_info", return_value=node_info),
        ):
            with self.assertRaisesRegex(ValueError, "最多还能创建 4 台"):
                app.create_batch_instances({
                    "node": "node-a", "name_prefix": "vps-", "count": 5,
                    "cpu": "1", "memory": "256MiB", "disk": "2GiB",
                })

    def test_batch_failure_rolls_back_completed_instances(self):
        node_info = {
            "status": "online", "cpu": 2, "available_cpu": 2,
            "available_memory": 2 * 1024**3, "available_disk": 20 * 1024**3,
            "available_ssh_ports": 100, "instances": [],
        }
        access = {"host": "203.0.113.10", "host_port": 22000, "guest_port": 22,
                  "username": "root", "password": "password"}
        with (
            mock.patch("app.require_node", return_value="node-a"),
            mock.patch("app.live_node_info", return_value=node_info),
            mock.patch("app.create_instance", side_effect=[
                ("node-a", "vps-001", access), RuntimeError("provision failed"),
            ]),
            mock.patch("app.run_incus") as run_incus,
            mock.patch("app.delete_credentials") as delete_credentials,
        ):
            with self.assertRaisesRegex(RuntimeError, "provision failed"):
                app.create_batch_instances({
                    "node": "node-a", "name_prefix": "vps-", "count": 2,
                    "cpu": "1", "memory": "256MiB", "disk": "2GiB",
                })
        run_incus.assert_called_once_with(
            "delete", "node-a:vps-001", "--force", timeout=180,
        )
        delete_credentials.assert_called_once_with("node-a", "vps-001")

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
