"""Unit tests for tools/doctor.py. Standard library only, no network, no Docker, no Ollama needed.

Run:  python3 -m unittest discover -s tools/tests -v     (or: make test-setup)
"""
import io
import json
import os
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import doctor  # noqa: E402

OK, WARN, FAIL, SKIP = doctor.OK, doctor.WARN, doctor.FAIL, doctor.SKIP


def fake_runner(table):
    """table maps a command prefix (tuple) to (exit_code, output); unknown commands are 'not found'."""
    def run(cmd, timeout=30):
        for prefix, result in table.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                return result
        return 127, ""
    return run


class VenvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.py = doctor.venv_python(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def make_venv(self):
        os.makedirs(os.path.dirname(self.py))
        open(self.py, "w").close()

    def test_missing_venv_fails_with_setup_advice(self):
        r = doctor.check_venv(self.root, runner=fake_runner({}))
        self.assertEqual(r.status, FAIL)
        self.assertIn("setup", r.advice)

    def test_good_version(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (0, "3.13.16\n"), (self.py, "-m"): (0, "pip 25")}))
        self.assertEqual(r.status, OK)
        self.assertIn("3.13.16", r.detail)

    def test_311_warns_about_m9_only(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (0, "3.11.0rc1\n"), (self.py, "-m"): (0, "pip")}))
        self.assertEqual(r.status, WARN)
        self.assertIn("M9", r.advice)

    def test_too_old_fails(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (0, "3.10.12\n")}))
        self.assertEqual(r.status, FAIL)
        self.assertIn("3.10.12", r.detail)

    def test_newer_than_tested_warns(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (0, "3.14.1\n"), (self.py, "-m"): (0, "pip")}))
        self.assertEqual(r.status, WARN)
        self.assertIn("3.13", r.advice)

    def test_broken_venv_fails(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (1, "error while loading")}))
        self.assertEqual(r.status, FAIL)
        self.assertIn("Delete", r.advice)

    def test_missing_pip_fails(self):
        self.make_venv()
        r = doctor.check_venv(self.root, runner=fake_runner({(self.py, "-c"): (0, "3.12.3"), (self.py, "-m"): (1, "No module named pip")}))
        self.assertEqual(r.status, FAIL)
        self.assertIn("pip", r.detail)


class DockerTests(unittest.TestCase):
    which_yes = staticmethod(lambda name: "/usr/bin/" + name)
    which_no = staticmethod(lambda name: None)

    def statuses(self, results):
        return [r.status for r in results]

    def test_not_installed(self):
        res = doctor.check_docker(runner=fake_runner({}), which=self.which_no)
        self.assertEqual(self.statuses(res), [FAIL, SKIP, SKIP])

    def test_daemon_down(self):
        run = fake_runner({("docker", "info"): (1, "Cannot connect to the Docker daemon. Is the docker daemon running?")})
        res = doctor.check_docker(runner=run, which=self.which_yes)
        self.assertEqual(self.statuses(res), [OK, FAIL, SKIP])
        self.assertTrue(res[1].advice)

    def test_permission_denied_is_a_warning_with_group_advice(self):
        run = fake_runner({("docker", "info"): (1, "permission denied while trying to connect to the Docker daemon socket")})
        res = doctor.check_docker(runner=run, which=self.which_yes)
        self.assertEqual(self.statuses(res), [OK, WARN, SKIP])
        self.assertIn("docker group", res[1].advice)

    def test_all_good(self):
        run = fake_runner({("docker", "info"): (0, "29.8.2\n"),
                           ("docker", "run"): (0, "\nHello from Docker!\nThis message shows...")})
        res = doctor.check_docker(runner=run, which=self.which_yes)
        self.assertEqual(self.statuses(res), [OK, OK, OK])

    def test_no_hello_skips_container(self):
        run = fake_runner({("docker", "info"): (0, "29.8.2\n")})
        res = doctor.check_docker(runner=run, which=self.which_yes, hello=False)
        self.assertEqual(self.statuses(res), [OK, OK, SKIP])

    def test_registry_blocked_names_the_proxy(self):
        out = ('docker: Error response from daemon: failed to resolve reference "docker.io/library/hello-world:latest": '
               'Head "https://registry-1.docker.io/v2/...": Forbidden\n\nRun \'docker run --help\' for more information\n')
        run = fake_runner({("docker", "info"): (0, "29.8.2"), ("docker", "run"): (125, out)})
        res = doctor.check_docker(runner=run, which=self.which_yes)
        self.assertEqual(res[2].status, FAIL)
        self.assertIn("Docker Hub", res[2].detail)
        self.assertIn("proxy", res[2].advice.lower())

    def test_tls_inspection(self):
        detail, advice = doctor.docker_run_failure(125, "Error: x509: certificate signed by unknown authority")
        self.assertIn("certificate", detail)
        self.assertIn("root", advice)


class ListeningTests(unittest.TestCase):
    """/proc/net/tcp parsing: the exact local address Ollama is bound to."""

    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def proc(self, tcp_rows, tcp6_rows=()):
        tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(tmp, "net"))
        with open(os.path.join(tmp, "net", "tcp"), "w") as f:
            f.write(self.HEADER + "".join(tcp_rows))
        with open(os.path.join(tmp, "net", "tcp6"), "w") as f:
            f.write(self.HEADER + "".join(tcp6_rows))
        return tmp

    @staticmethod
    def row(addr, port, state="0A"):
        return "   0: %s:%04X 00000000:0000 %s 00000000:00000000 00:00000000 00000000  1000 0 1 1\n" % (addr, port, state)

    def test_loopback(self):
        root = self.proc([self.row("0100007F", 11434)])
        self.assertEqual(doctor.listening_addresses_linux(11434, root), ["127.0.0.1"])

    def test_all_interfaces(self):
        root = self.proc([self.row("00000000", 11434)])
        self.assertEqual(doctor.listening_addresses_linux(11434, root), ["0.0.0.0"])

    def test_ipv6_any_and_loopback(self):
        any6 = "0" * 32
        lo6 = "00000000000000000000000001000000"
        root = self.proc([], [self.row(any6, 11434), self.row(lo6, 11434)])
        self.assertEqual(doctor.listening_addresses_linux(11434, root), ["::", "::1"])

    def test_ignores_other_ports_and_non_listening(self):
        root = self.proc([self.row("00000000", 8080), self.row("00000000", 11434, state="01")])
        self.assertEqual(doctor.listening_addresses_linux(11434, root), [])

    def test_unreadable_returns_none(self):
        self.assertIsNone(doctor.listening_addresses_linux(11434, "/nonexistent-proc"))


class ExposureTests(unittest.TestCase):
    def check(self, env=None, addrs=None, platform_name="linux", lan="192.168.1.20", open_port=False):
        return doctor.check_ollama_exposure(env=env or {}, listen_reader=lambda port: addrs, lan=lambda: lan,
                                            probe=lambda h, p: open_port, platform_name=platform_name)

    def test_env_var_all_interfaces_fails(self):
        for value in ("0.0.0.0", "0.0.0.0:11434", "http://0.0.0.0:11434", "192.168.1.20"):
            self.assertEqual(self.check(env={"OLLAMA_HOST": value}).status, FAIL, value)

    def test_env_var_loopback_is_fine(self):
        for value in ("127.0.0.1", "127.0.0.1:11434", "localhost:11434", "http://127.0.0.1:11434"):
            self.assertEqual(self.check(env={"OLLAMA_HOST": value}, addrs=["127.0.0.1"]).status, OK, value)

    def test_linux_bound_everywhere_fails(self):
        self.assertEqual(self.check(addrs=["0.0.0.0"]).status, FAIL)
        self.assertEqual(self.check(addrs=["::"]).status, FAIL)

    def test_linux_loopback_ok(self):
        self.assertEqual(self.check(addrs=["127.0.0.1", "::1"]).status, OK)

    def test_mac_or_windows_probe_answers_fails(self):
        self.assertEqual(self.check(platform_name="darwin", open_port=True).status, FAIL)

    def test_mac_or_windows_probe_refused_ok(self):
        self.assertEqual(self.check(platform_name="win32", open_port=False).status, OK)


class OllamaTests(unittest.TestCase):
    def getter(self, tags=None, up=True):
        def get(url):
            if not up:
                return None, "connection refused"
            if url.endswith("/api/version"):
                return 200, json.dumps({"version": "0.12.0"})
            if url.endswith("/api/tags"):
                return 200, json.dumps({"models": [{"name": n} for n in (tags or [])]})
            return 404, ""
        return get

    def ok_exposure(self, env=None):
        return doctor.Result("Ollama listens on 127.0.0.1 only", OK)

    def test_not_running(self):
        res = doctor.check_ollama(get=self.getter(up=False), exposure=self.ok_exposure)
        self.assertEqual([r.status for r in res], [FAIL, SKIP, SKIP])

    def test_models_present_with_latest_tag(self):
        res = doctor.check_ollama(get=self.getter(["gemma3:1b", "embeddinggemma:latest"]), exposure=self.ok_exposure)
        self.assertEqual([r.status for r in res], [OK, OK, OK])
        self.assertIn("0.12.0", res[0].detail)

    def test_missing_model_gives_pull_command(self):
        res = doctor.check_ollama(get=self.getter(["gemma3:1b"]), exposure=self.ok_exposure)
        self.assertEqual(res[2].status, FAIL)
        self.assertIn("ollama pull embeddinggemma", res[2].advice)
        self.assertNotIn("gemma3:1b", res[2].advice)

    def test_models_can_be_skipped(self):
        res = doctor.check_ollama(get=self.getter([]), exposure=self.ok_exposure, models=False)
        self.assertEqual([r.status for r in res], [OK, OK, SKIP])

    def test_other_size_does_not_count(self):
        res = doctor.check_ollama(get=self.getter(["gemma3:4b", "embeddinggemma:latest"]), exposure=self.ok_exposure)
        self.assertEqual(res[2].status, FAIL)


class ResourceTests(unittest.TestCase):
    def statuses(self, ram, disk):
        return [r.status for r in doctor.check_resources(".", ram_gb=ram, free_gb=disk)]

    def test_plenty(self):
        self.assertEqual(self.statuses(16, 100), [OK, OK])

    def test_8gb_laptop_reporting_a_bit_less_is_ok(self):
        self.assertEqual(self.statuses(7.7, 100)[0], OK)

    def test_low_ram_warns(self):
        self.assertEqual(self.statuses(4, 100)[0], WARN)

    def test_low_disk_warns_and_tiny_disk_fails(self):
        self.assertEqual(self.statuses(16, 10)[1], WARN)
        self.assertEqual(self.statuses(16, 1)[1], FAIL)


class ReportTests(unittest.TestCase):
    def test_ascii_fallback_for_old_consoles(self):
        class Stream:
            encoding = "cp1252"
        self.assertIs(doctor.marks_for(Stream()), doctor.MARKS_ASCII)

    def test_unicode_when_possible(self):
        class Stream:
            encoding = "utf-8"
        self.assertIs(doctor.marks_for(Stream()), doctor.MARKS_UNICODE)

    def run_main(self, results):
        original = doctor.collect
        doctor.collect = lambda args: results
        out = io.StringIO()
        old_stdout, sys.stdout = sys.stdout, out
        try:
            code = doctor.main([])
        finally:
            sys.stdout = old_stdout
            doctor.collect = original
        return code, out.getvalue()

    def test_exit_code_and_advice(self):
        code, text = self.run_main([doctor.Result("A", OK, "fine"), doctor.Result("B", FAIL, "broken", "do this")])
        self.assertEqual(code, 1)
        self.assertIn("next step: do this", text)

    def test_warnings_do_not_fail(self):
        code, text = self.run_main([doctor.Result("A", OK), doctor.Result("B", WARN, "meh", "maybe")])
        self.assertEqual(code, 0)
        self.assertIn("Ready", text)

    def test_json_output(self):
        original = doctor.collect
        doctor.collect = lambda args: [doctor.Result("A", FAIL, "x", "y")]
        out = io.StringIO()
        old_stdout, sys.stdout = sys.stdout, out
        try:
            code = doctor.main(["--json"])
        finally:
            sys.stdout = old_stdout
            doctor.collect = original
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())[0]["status"], "fail")


class NetworkSafetyTests(unittest.TestCase):
    def test_lan_address_sends_nothing_and_is_not_loopback(self):
        ip = doctor.lan_address()
        if ip is not None:
            socket.inet_aton(ip)
            self.assertFalse(ip.startswith("127."))

    def test_doctor_only_talks_to_loopback_ollama(self):
        self.assertTrue(doctor.OLLAMA_URL.startswith("http://127.0.0.1:"))


if __name__ == "__main__":
    unittest.main()
