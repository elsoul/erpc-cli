# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


POSTURE = runpy.run_path(Path(__file__).with_name("node-security-posture.py"))


class PostureTests(unittest.TestCase):
    def test_all_scopes_and_bound_udp_use_process_names_not_port_guesses(self):
        source = (
            b'tcp LISTEN 0 0 0.0.0.0:16379 0.0.0.0:* users:(("redis-server",pid=11,fd=4))\n'
            b'tcp LISTEN 0 0 [::ffff:127.0.0.1]:6379 [::]:*\n'
            b'tcp ESTAB 0 0 198.51.100.2:2222 198.51.100.1:80 users:(("client",pid=22,fd=5))\n'
            b'udp ESTAB 0 0 [fe80::1%eth0]:40535 [fe80::2]:53 users:(("test-daemon",pid=31,fd=9))\n'
            b'udp UNCONN 0 0 *:41195 *:*\n'
            b'udp UNCONN 0 0 *:0 *:*\n'
        )
        report, pids = POSTURE["socket_report"](source, False)
        self.assertEqual(report["tcp"]["wildcard"], [{"port": 16379, "services": ["redis"]}])
        self.assertEqual(report["tcp"]["loopback"], [{"port": 6379, "services": ["unknown"]}])
        self.assertEqual(report["udp"]["interface"], [{"port": 40535, "services": ["unclassified"]}])
        self.assertEqual(report["udp"]["wildcard"], [{"port": 41195, "services": ["unknown"]}])
        self.assertEqual(pids, {11, 31})
        rendered = json.dumps(report)
        for raw in ("198.51.100", "fe80", "test-daemon", "pid=", "2222"):
            self.assertNotIn(raw, rendered)

    def test_reports_cap_and_malformed_rows_without_clean_bill_of_health(self):
        rows = [f"tcp LISTEN 0 0 *:{port} *:*\n".encode() for port in range(1, 151)]
        view, _ = POSTURE["socket_report"](b"".join(rows), False)
        self.assertTrue(view["truncated"])
        self.assertEqual(len(view["tcp"]["wildcard"]), 128)
        partial, _ = POSTURE["socket_report"](rows[0] + b"unreadable row\ntruncated", True)
        self.assertTrue(partial["truncated"])
        self.assertEqual(partial["tcp"]["coverage"], "partial")
        self.assertEqual(POSTURE["socket_report"](None, False)[0]["udp"]["coverage"], "unknown")

    def test_nft_requires_a_packet_family_input_hook_for_evidence(self):
        chain = {"family": "ip", "table": "private-table", "name": "filter-input",
                 "type": "filter", "hook": "input", "policy": "accept"}
        rule = {"family": "ip", "table": "private-table", "chain": "filter-input",
                "expr": [{"match": {"left": "192.0.2.3"}}, {"drop": None}]}
        raw = {"nftables": [{"table": {"name": "private-table"}}, {"chain": chain}, {"rule": rule}]}
        legacy, evidence = POSTURE["filter_evidence"](json.dumps(raw).encode(), False)
        self.assertEqual(legacy, "tables_present")
        self.assertEqual(evidence["ipv4"], "configured_drop_or_reject_rule")
        self.assertEqual(evidence["ipv6"], "no_input_filter_hook")
        chain.update(family="inet", policy="drop")
        _, evidence = POSTURE["filter_evidence"](json.dumps(raw).encode(), False)
        self.assertEqual((evidence["ipv4"], evidence["ipv6"]), ("input_default_drop", "input_default_drop"))
        self.assertNotIn("private-table", json.dumps(evidence))
        self.assertEqual(POSTURE["filter_evidence"](b'{}', True)[1]["ipv4"], "unknown")

    def test_config_dump_and_fail2ban_project_only_closed_results(self):
        settings = b"usedns no\npasswordauthentication no\nkbdinteractiveauthentication yes\n"
        with patch.dict("os.environ", {"USER": "ubuntu", "SSH_CONNECTION": "192.0.2.4 54321 192.0.2.8 22"}):
            capture = POSTURE["effective_ssh_settings"].__globals__
            with patch.dict(capture, capture=lambda args, **_: (settings, False)):
                result = POSTURE["effective_ssh_settings"]()
            self.assertEqual(result, {"password": "disabled", "keyboard_interactive": "enabled"})
            with patch.dict(capture, capture=lambda args, **_: (settings, True)):
                self.assertEqual(POSTURE["effective_ssh_settings"]()["password"], "unknown")
        capture = POSTURE["sshd_jail"].__globals__
        with patch.dict(capture, capture=lambda args, **_: (b"Status for the jail: sshd\n", False)):
            self.assertEqual(POSTURE["sshd_jail"](), "sshd_jail_observed")
        with patch.dict(capture, capture=lambda args, **_: (b"|- Number of jail: 1\nJail list: custom\n", False)):
            self.assertEqual(POSTURE["sshd_jail"](), "sshd_jail_not_listed")

    def test_control_read_only_uses_fixed_noninteractive_fallback_on_permission_denial(self):
        fallback = POSTURE["control_read"]
        globals_ = fallback.__globals__
        denied = globals_["DENIED"]
        sudo = ["/usr/bin/sudo", "-n", "--"]
        commands = {
            "ruleset": ["/usr/sbin/nft", "-j", "list", "ruleset"],
            "sshd_jail": ["/usr/bin/fail2ban-client", "status", "sshd"],
            "jail_list": ["/usr/bin/fail2ban-client", "status"],
        }
        for operation, command in commands.items():
            calls = []

            def capture(argv, **kwargs):
                calls.append(argv)
                return (denied, False) if kwargs.get("denial_markers") else (b"bounded", False)

            with patch.dict(globals_, capture=capture):
                self.assertEqual(fallback(operation), (b"bounded", False))
            self.assertEqual(calls, [command, sudo + command])

        for outcome in [(b"data", False), (b"partial", True), (None, False)]:
            calls = []

            def capture(argv, **kwargs):
                calls.append(argv)
                return outcome

            with patch.dict(globals_, capture=capture):
                self.assertEqual(fallback("ruleset"), outcome)
            self.assertEqual(calls, [commands["ruleset"]])

        with patch.dict(globals_, capture=lambda argv, **kwargs: (
            (denied, False) if kwargs.get("denial_markers") else (None, False)
        )):
            self.assertEqual(POSTURE["sshd_jail"](), "unknown")
            self.assertEqual(POSTURE["filter_evidence"](*fallback("ruleset"))[1]["ipv4"], "unknown")

    def test_permission_detection_keeps_command_diagnostics_private(self):
        output = POSTURE["capture"](
            [sys.executable, "-c", "import sys; sys.stderr.write('Permission denied to socket: fixture'); sys.exit(1)"],
            denial_markers=(b"Permission denied to socket:",),
        )
        self.assertIs(output[0], POSTURE["DENIED"])
        self.assertFalse(output[1])
        self.assertEqual(
            POSTURE["capture"]([sys.executable, "-c", "print('fixture partial data')"], limit=3),
            (b"fix", True),
        )

    def test_metadata_reads_only_modes_of_explicitly_referenced_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = root / ".env"
            env.write_text("outline fixture data")
            env.chmod(0o600)
            secret_dir = root / "private-source"
            secret_dir.mkdir(mode=0o755)
            symlink = root / "pointer"
            symlink.symlink_to(env)
            raw = (
                f'a(sb) 2 "{env}" false "/etc/default/not-an-env" true\n'
                f'a(ss) 2 "source" "{secret_dir}" "link" "{symlink}"\n'
                'a(ss) 1 "identifier" "credential-store-alias"\n'
            )
            paths = POSTURE["parse_properties"](raw.encode())
            self.assertEqual(paths["service_env"], {str(env)})
            self.assertEqual(paths["environment_files"], {str(env), "/etc/default/not-an-env"})
            self.assertEqual(POSTURE["file_modes"](paths["service_env"]),
                             {"owner_only": 1, "group_or_other_access": 0, "unknown": 0})
            self.assertEqual(paths["as_is_credentials"], {str(secret_dir), str(symlink)})
            self.assertEqual(paths["encrypted_credentials"], {"credential-store-alias"})
            self.assertEqual(POSTURE["file_modes"](paths["as_is_credentials"] | paths["encrypted_credentials"]),
                             {"owner_only": 0, "group_or_other_access": 1, "unknown": 2})

    def test_credential_declarations_are_counted_without_new_metadata_reads(self):
        metadata = POSTURE["metadata_policy"]
        observed_calls = []

        def capture(args, **options):
            if "GetUnit" in args and args[-1] == "ssh.service":
                return (b'o "/org/freedesktop/systemd1/unit/ssh_2eservice"\n', False)
            if "get-property" in args:
                return (b'a(sb) 0\na(ss) 2 "left" "/fixture/dual" "right" "/fixture/raw"\n'
                        b'a(ss) 2 "third" "/fixture/dual" "fourth" "/fixture/encrypted"\n', False)
            return None, False

        def modes(paths):
            observed_calls.append(tuple(paths))
            return {"owner_only": len(paths), "group_or_other_access": 0, "unknown": 0}

        with patch.dict(metadata.__globals__, capture=capture, file_modes=modes):
            report = metadata(set())
        self.assertEqual(report["credential_declarations"], {"as_is": 2, "encrypted": 2})
        self.assertEqual(observed_calls, [(), (), ("/fixture/dual", "/fixture/encrypted", "/fixture/raw")])
        self.assertNotIn("/fixture", json.dumps(report))
        with patch.dict(metadata.__globals__, capture=lambda *args, **kw: (None, False)):
            unavailable = metadata(set())
        self.assertEqual(unavailable["credential_declarations"], {"as_is": None, "encrypted": None})


if __name__ == "__main__":
    unittest.main()
