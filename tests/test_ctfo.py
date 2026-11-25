import json
import os
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import CTFO  # noqa: E402

CTFO.C.disable()


def banner_server(payload, reply_to_request=False):
    """Start a one-shot local TCP server; returns its port."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]

    def serve():
        srv.settimeout(5)
        try:
            while True:
                conn, _ = srv.accept()
                with conn:
                    if reply_to_request:
                        conn.recv(1024)
                    conn.sendall(payload)
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return port, srv


class ParsePortsTest(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(CTFO.parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_reversed_range_and_dupes(self):
        self.assertEqual(CTFO.parse_ports("5-3,4"), [3, 4, 5])

    def test_keywords(self):
        self.assertEqual(len(CTFO.parse_ports("all")), 65535)
        self.assertEqual(CTFO.parse_ports("top"), CTFO.TOP_PORTS)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            CTFO.parse_ports("0,70000")
        with self.assertRaises(ValueError):
            CTFO.parse_ports("abc")


class ResolveTargetsTest(unittest.TestCase):
    def test_ip_and_cidr(self):
        self.assertEqual(CTFO.resolve_targets(["127.0.0.1"]), [("127.0.0.1", "127.0.0.1")])
        self.assertEqual(len(CTFO.resolve_targets(["10.0.0.0/30"])), 2)

    def test_cidr_limit(self):
        with self.assertRaises(ValueError):
            CTFO.resolve_targets(["10.0.0.0/16"], max_hosts=100)


class ProductTest(unittest.TestCase):
    def check(self, banner, name, version):
        p = CTFO.extract_product(banner)
        self.assertIsNotNone(p, banner)
        self.assertEqual(p["name"], name)
        self.assertEqual(p["version"], version)

    def test_known_products(self):
        self.check("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", "OpenSSH", "8.2p1")
        self.check("220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3")
        self.check("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n", "Apache HTTP Server", "2.4.41")
        self.check("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n", "nginx", "1.18.0")
        self.check("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "Microsoft IIS", "10.0")
        self.check("MySQL 10.6.12-MariaDB-0ubuntu0.22.04.1", "MariaDB", "10.6.12")

    def test_generic(self):
        self.check("HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.11.4\r\n", "SimpleHTTP", "0.6")

    def test_nothing(self):
        self.assertIsNone(CTFO.extract_product(""))
        self.assertIsNone(CTFO.extract_product("HTTP/1.1 200 OK"))

    def test_keyword(self):
        r = CTFO.build_result(22, "SSH-2.0-OpenSSH_9.6")
        self.assertEqual(CTFO.cve_keyword(r), "OpenSSH 9.6")
        self.assertIsNone(CTFO.cve_keyword(CTFO.build_result(80, "HTTP/1.1 200 OK")))


class GuessOSTest(unittest.TestCase):
    def test_distros(self):
        self.assertEqual(CTFO.guess_os(["SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"]), "Linux (Ubuntu)")
        self.assertEqual(CTFO.guess_os(["Server: Microsoft-IIS/10.0"]), "Windows Server")
        self.assertEqual(CTFO.guess_os(["nginx/1.18.0"]), "Linux/Unix")
        self.assertEqual(CTFO.guess_os([""], [135, 445, 3389]), "Windows Server")
        self.assertEqual(CTFO.guess_os([]), "Unknown")


class NVDParseTest(unittest.TestCase):
    def test_parse_sorted(self):
        data = {"vulnerabilities": [
            {"cve": {"id": "CVE-1", "published": "2020-01-01T00:00",
                     "descriptions": [{"lang": "en", "value": "low one"}],
                     "metrics": {"cvssMetricV2": [{"baseSeverity": "LOW",
                                                   "cvssData": {"baseScore": 2.1, "version": "2.0"}}]}}},
            {"cve": {"id": "CVE-2", "metrics": {"cvssMetricV31": [
                {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "version": "3.1"}}]}}},
            {"cve": {"id": "CVE-3", "metrics": {}}},
        ]}
        res = CTFO.NVDClient.parse(data)
        self.assertEqual([r["id"] for r in res], ["CVE-2", "CVE-1", "CVE-3"])
        self.assertEqual(res[1]["severity"], "LOW")
        self.assertEqual(res[2]["severity"], "N/A")

    def test_cache(self):
        client = CTFO.NVDClient()
        calls = []
        client._get = lambda params: calls.append(params) or {"vulnerabilities": []}
        client.search("nginx 1.18.0")
        client.search("nginx 1.18.0")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["keywordSearch"], "nginx 1.18.0")


class ScanTest(unittest.TestCase):
    def test_ssh_banner(self):
        port, srv = banner_server(b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n")
        try:
            r = CTFO.scan_port("127.0.0.1", port, timeout=1.0)
        finally:
            srv.close()
        self.assertEqual(r["port"], port)
        self.assertEqual(r["product"], {"name": "OpenSSH", "version": "9.6p1"})

    def test_mysql_greeting(self):
        payload = b"\x4a\x00\x00\x00\x0a8.0.36\x00" + b"\x01\x02\x03\x04" * 4
        port, srv = banner_server(payload)
        try:
            r = CTFO.scan_port("127.0.0.1", port, timeout=1.0)
        finally:
            srv.close()
        self.assertEqual(r["banner"], "MySQL 8.0.36")

    def test_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertIsNone(CTFO.scan_port("127.0.0.1", port, timeout=0.5))


class ReportTest(unittest.TestCase):
    def sample(self):
        r = CTFO.build_result(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")
        r["cves"] = [{"id": "CVE-2021-23017", "score": 7.7, "severity": "HIGH",
                      "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"}]
        return [{"target": "t<x>", "ip": "1.2.3.4", "duration": 1.0, "os": "Linux/Unix", "ports": [r]}]

    def test_formats(self):
        with tempfile.TemporaryDirectory() as d:
            for ext in ("json", "csv", "html"):
                path = os.path.join(d, f"r.{ext}")
                CTFO.write_report(self.sample(), path)
                with open(path, encoding="utf-8") as f:
                    content = f.read()
                self.assertIn("CVE-2021-23017", content)
            with open(os.path.join(d, "r.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["version"], CTFO.__version__)
            with open(os.path.join(d, "r.html"), encoding="utf-8") as f:
                self.assertIn("t&lt;x&gt;", f.read())
            with self.assertRaises(ValueError):
                CTFO.write_report(self.sample(), os.path.join(d, "r.txt"))


if __name__ == "__main__":
    unittest.main()
