# SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
# SPDX-License-Identifier: Apache-2.0

import json
import io
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
        report, pids, attribution_incomplete = POSTURE["socket_report"](source, False)
        self.assertEqual(report["tcp"]["wildcard"], [{"port": 16379, "services": ["redis"]}])
        self.assertEqual(report["tcp"]["loopback"], [{"port": 6379, "services": ["unknown"]}])
        self.assertEqual(report["udp"]["interface"], [{"port": 40535, "services": ["unclassified"]}])
        self.assertEqual(report["udp"]["wildcard"], [{"port": 41195, "services": ["unknown"]}])
        self.assertEqual(pids, {11, 31})
        self.assertTrue(attribution_incomplete)
        rendered = json.dumps(report)
        for raw in ("198.51.100", "fe80", "test-daemon", "pid=", "2222"):
            self.assertNotIn(raw, rendered)

    def test_reports_cap_and_malformed_rows_without_clean_bill_of_health(self):
        rows = [f"tcp LISTEN 0 0 *:{port} *:*\n".encode() for port in range(1, 151)]
        view, _, incomplete = POSTURE["socket_report"](b"".join(rows), False)
        self.assertTrue(incomplete)
        self.assertTrue(view["truncated"])
        self.assertEqual(len(view["tcp"]["wildcard"]), 128)
        partial, _, incomplete = POSTURE["socket_report"](rows[0] + b"unreadable row\ntruncated", True)
        self.assertTrue(incomplete)
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
            capture = POSTURE["ssh_default_config"].__globals__
            with patch.dict(capture, capture=lambda args, **_: (settings, False)):
                result = POSTURE["ssh_default_config"]()
            self.assertEqual(result, {"password": "disabled", "keyboard_interactive": "enabled"})
            with patch.dict(capture, capture=lambda args, **_: (settings, True)):
                self.assertEqual(POSTURE["ssh_default_config"]()["password"], "unknown")
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
                return (b'a(sb) 0\na(ss) 3 "left" "/fixture/dual" "right" "/fixture/raw" "extra" "/fixture/raw"\n'
                        b'a(ss) 2 "third" "/fixture/dual" "fourth" "/fixture/encrypted"\n', False)
            return POSTURE["NOT_LOADED"], False

        def modes(paths):
            observed_calls.append(tuple(paths))
            return {"owner_only": len(paths), "group_or_other_access": 0, "unknown": 0}

        with patch.dict(metadata.__globals__, capture=capture, file_modes=modes):
            report = metadata(set(), False)
        self.assertEqual(report["distinct_credential_sources"], {"as_is": 2, "encrypted": 2})
        self.assertEqual(observed_calls, [(), (), ("/fixture/dual", "/fixture/encrypted", "/fixture/raw")])
        self.assertNotIn("/fixture", json.dumps(report))
        with patch.dict(metadata.__globals__, capture=lambda *args, **kw: (None, False)):
            unavailable = metadata(set(), False)
        self.assertEqual(unavailable["distinct_credential_sources"], {"as_is": None, "encrypted": None})

    def test_metadata_distinguishes_missing_units_from_failed_reads(self):
        metadata = POSTURE["metadata_policy"]
        names = ("ssh.service", "redis-server.service")
        empty = b"a(sb) 0\na(ss) 0\na(ss) 0\n"
        positive = b'a(sb) 1 "/fixture/.env" false\na(ss) 0\na(ss) 0\n'
        unit_path = "/org/freedesktop/systemd1/unit/"
        absent = b"Call failed: Unit redis-server.service not loaded."
        missing = POSTURE["capture"](
            [sys.executable, "-c", "import sys; print(sys.argv[1], file=sys.stderr); sys.exit(1)",
             absent.decode("ascii")],
            absent_line=absent,
        )
        self.assertEqual(missing, (POSTURE["NOT_LOADED"], False))

        def modes(paths):
            return {"owner_only": 0, "group_or_other_access": len(paths), "unknown": 0}

        for second, expected in [
            (missing, "observed"),
            ((None, False), "partial"),
            ((b"unreadable", False), "partial"),
            ((b"truncated", True), "partial"),
        ]:
            for first in (empty, positive):
                def capture(args, **options):
                    if "GetUnit" in args:
                        if args[-1] == names[1] and second[0] is POSTURE["NOT_LOADED"]:
                            return second
                        unit = "ssh" if args[-1] == names[0] else "redis"
                        return f'o "{unit_path}{unit}"\n'.encode("ascii"), False
                    return (first, False) if unit_path + "ssh" in args else second

                with patch.dict(metadata.__globals__, capture=capture, file_modes=modes,
                                unit_names=lambda _: (names, set(), False, False)):
                    report = metadata(set(), False)
                self.assertEqual(report["coverage"], expected, report)
                self.assertEqual(report["units_with_evidence"], 1)
                self.assertEqual(report["environment_files"]["group_or_other_access"], int(first == positive))
                self.assertNotIn("/fixture", json.dumps(report))

    def test_sampled_fixed_unit_disappearance_or_unreadable_properties_downgrade_coverage(self):
        report_linux = POSTURE["report_linux"]
        target = "redis-server.service"
        fixed = b"0::/system.slice/redis-server.service"
        obj = b'o "/org/freedesktop/systemd1/unit/redis"\n'
        missing = (POSTURE["NOT_LOADED"], False)
        empty = b"a(sb) 0\na(ss) 0\na(ss) 0\n"
        for cgroup, lookup, properties, other_positive, expected, capped in (
            (fixed, missing, None, False, "partial", False),
            (fixed + b"/child", missing, None, True, "partial", False),
            (fixed + b"/child", (None, False), None, True, "partial", False),
            (fixed, (None, True), None, True, "partial", True),
            (fixed + b"/child", (obj, False), (None, False), True, "partial", False),
            (fixed + b"/child", (obj, False), (None, True), True, "partial", True),
            (fixed + b"/child", (obj, False), (empty, False), False, "observed", False),
            (b"0::/system.slice/cron.service/child", missing, None, False, "observed", False),
        ):
            with self.subTest(cgroup=cgroup, lookup=lookup, properties=properties):
                def capture(args, **_):
                    if args[0] == "/usr/bin/ss":
                        return b'tcp LISTEN 0 0 *:6379 *:* users:(("redis",pid=27,fd=4))\n', False
                    if "GetUnit" in args:
                        if args[-1] == target:
                            return lookup
                        if args[-1] == "ssh.service":
                            return b'o "/org/freedesktop/systemd1/unit/ssh"\n', False
                    if "/org/freedesktop/systemd1/unit/redis" in args:
                        self.assertIsNotNone(properties)
                        return properties
                    if "/org/freedesktop/systemd1/unit/ssh" in args:
                        return (b'a(sb) 1 "/fixture/.env" false\na(ss) 0\na(ss) 0\n'
                                if other_positive else empty), False
                    return missing

                def open_cgroup(path, mode):
                    self.assertEqual((path, mode), ("/proc/27/cgroup", "rb"))
                    return io.BytesIO(cgroup + b"\n")

                with patch.dict(report_linux.__globals__, capture=capture, open=open_cgroup,
                                listeners=lambda: "no_listener", ssh_default_config=lambda: {},
                                control_read=lambda _: (b'{"nftables":[]}', False),
                                sshd_jail=lambda: "unknown",
                                file_modes=lambda paths: {"owner_only": len(paths),
                                                          "group_or_other_access": 0, "unknown": 0}):
                    report = report_linux()["metadata"]
                self.assertEqual(report["coverage"], expected, report)
                self.assertEqual(report["truncated"], capped, report)
                self.assertEqual(report["environment_files"]["owner_only"], int(other_positive))

    def test_report_metadata_carries_socket_and_cgroup_uncertainty(self):
        report_linux = POSTURE["report_linux"]
        socket = b'tcp LISTEN 0 0 *:80 *:* users:(("nginx",pid=27,fd=4))\n'
        mixed = b'tcp LISTEN 0 0 *:80 *:* users:(("nginx",pid=27,fd=4),unknown)\n'
        cgroup = b"0::/system.slice/erpc-worker-example.service\n"
        for data, capped, proc, expected, truncated in (
            (socket, False, cgroup, "observed", False),
            (b"", False, cgroup, "observed", False),
            (None, False, cgroup, "partial", False),
            (socket, True, cgroup, "partial", False),
            (socket + b"invalid\n", False, cgroup, "partial", False),
            (mixed, False, cgroup, "partial", False),
            (socket + b"udp UNCONN 0 0 *:53 *:*\n", False, cgroup, "partial", False),
            (socket, False, None, "partial", False),
            (socket, False, b"x" * 4097, "partial", True),
            (socket, False, cgroup + b"\xff\n", "partial", False),
            (socket, False, b"", "partial", False),
            (socket, False, b"invalid\n", "partial", False),
        ):
            def capture(args, **_):
                if args[0] == "/usr/bin/ss":
                    return data, capped
                if "GetUnit" in args and args[-1] == "ssh.service":
                    return b'o "/org/freedesktop/systemd1/unit/ssh"\n', False
                if "GetUnit" in args and args[-1] == "erpc-worker-example.service":
                    return b'o "/org/freedesktop/systemd1/unit/worker"\n', False
                if "/org/freedesktop/systemd1/unit/ssh" in args:
                    return b'a(sb) 1 "/fixture/.env" false\na(ss) 0\na(ss) 0\n', False
                if "/org/freedesktop/systemd1/unit/worker" in args:
                    return b"a(sb) 0\na(ss) 0\na(ss) 0\n", False
                return POSTURE["NOT_LOADED"], False

            def open_cgroup(path, mode):
                self.assertEqual((path, mode), ("/proc/27/cgroup", "rb"))
                if proc is None:
                    raise PermissionError
                return io.BytesIO(proc)

            with patch.dict(report_linux.__globals__, capture=capture, open=open_cgroup,
                            listeners=lambda: "no_listener", ssh_default_config=lambda: {},
                            control_read=lambda _: (b'{"nftables":[]}', False),
                            sshd_jail=lambda: "unknown",
                            file_modes=lambda paths: {
                                "owner_only": len(paths), "group_or_other_access": 0, "unknown": 0,
                            }):
                result = report_linux()["metadata"]
            self.assertEqual(result["coverage"], expected, (data, proc, result))
            self.assertEqual(result["truncated"], truncated)
            self.assertEqual(result["environment_files"]["owner_only"], 1)

    def test_discovered_unit_owns_its_nested_cgroup_without_losing_known_findings(self):
        report_linux = POSTURE["report_linux"]
        direct = b"0::/system.slice/erpc-worker-example.service"
        nested = direct + b"/.control/child"
        for proc, loaded, queried, coverage, capped in (
            (direct + b"\n", True, True, "observed", False),
            (nested + b"\n", True, True, "observed", False),
            (b"9:cpu:/other\n4:name=systemd:/erpc.slice/erpc-worker-example.service/child\n",
             True, True, "observed", False),
            (nested + b"\n" + b"1:name=systemd:/system.slice/ssh.service\n",
             True, True, "partial", False),
            (nested + b"\n" + b"0::/unexpected\n", True, True, "partial", False),
            (nested + b"\n" + b"0::/bad\xff\n", True, True, "partial", False),
            (nested + b"\xff\n", True, True, "partial", False),
            (nested + b"\n" + b"z" * 4096, True, True, "partial", True),
            (nested + b"\n", False, True, "partial", False),
            (b"0::/system.slice/cron.service/child\n", True, False, "observed", False),
            (b"0::/system.slice/docker.service/erpc-worker-example.service\n",
             True, False, "partial", False),
            (b"0::/system.slice/erpc-worker-example.service/../sibling\n",
             True, False, "partial", False),
            (b"0::/../system.slice/erpc-worker-example.service\n", True, False, "partial", False),
            (b"0::/system.slice//erpc-worker-example.service\n", True, False, "partial", False),
            (b"9:cpu:/system.slice/erpc-worker-example.service\n", True, False, "partial", False),
            (None, True, False, "partial", False),
        ):
            with self.subTest(cgroup=proc[:150] if proc else None, loaded=loaded):
                discovered = "erpc-worker-example.service"
                calls = []
                examined = set()

                def capture(args, **_):
                    if args[0] == "/usr/bin/ss":
                        return b'tcp LISTEN 0 0 *:80 *:* users:(("nginx",pid=27,fd=4))\n', False
                    if "GetUnit" in args:
                        calls.append(args[-1])
                        if args[-1] == "ssh.service":
                            return b'o "/org/freedesktop/systemd1/unit/ssh"\n', False
                        if args[-1] == discovered and loaded:
                            return b'o "/org/freedesktop/systemd1/unit/worker"\n', False
                    if "/org/freedesktop/systemd1/unit/worker" in args:
                        return b'a(sb) 1 "/fixture/.env" false\na(ss) 0\na(ss) 0\n', False
                    if "/org/freedesktop/systemd1/unit/ssh" in args:
                        return b"a(sb) 0\na(ss) 0\na(ss) 0\n", False
                    return POSTURE["NOT_LOADED"], False

                def open_cgroup(path, mode):
                    self.assertEqual((path, mode), ("/proc/27/cgroup", "rb"))
                    if proc is None:
                        raise PermissionError
                    return io.BytesIO(proc)

                def modes(paths):
                    examined.update(paths)
                    return {"owner_only": len(paths), "group_or_other_access": 0, "unknown": 0}

                with patch.dict(report_linux.__globals__, capture=capture, open=open_cgroup,
                                listeners=lambda: "no_listener", ssh_default_config=lambda: {},
                                control_read=lambda _: (b'{"nftables":[]}', False),
                                sshd_jail=lambda: "unknown", file_modes=modes):
                    report = report_linux()["metadata"]
                positive = queried and loaded
                self.assertEqual(calls.count(discovered), int(queried))
                self.assertLessEqual(len(calls), POSTURE["UNIT_LIMIT"])
                self.assertEqual(examined, {"/fixture/.env"} if positive else set())
                self.assertEqual(report["coverage"], coverage)
                self.assertEqual(report["truncated"], capped)
                self.assertEqual(report["environment_files"]["owner_only"], int(positive))
                self.assertEqual(report["service_env"]["owner_only"], int(positive))
                self.assertNotIn("/fixture", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
