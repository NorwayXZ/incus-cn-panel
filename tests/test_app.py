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
                    self.assertEqual(request("GET", "/api/users")[0], 403)
                    self.assertEqual(request("POST", "/api/instances", {})[0], 403)
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
                    run_incus.assert_called_once_with(
                        "restart", "node-a:web-01", "--force", timeout=180
                    )

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
        self.assertEqual(instances[0]["port_start"], "10000")
        self.assertEqual(instances[0]["port_end"], "10010")

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
