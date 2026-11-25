#!/usr/bin/env python3
"""CTFO - Network Recon & CVE Lookup Tool.

Multi-threaded TCP port scanner with banner grabbing, service/version
detection, OS fingerprinting and live CVE lookup (NIST NVD API 2.0).

For authorized security testing and educational use only.
"""

import argparse
import csv
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

__version__ = "2.0.0"
__author__ = "Ordukhan Ordukhanli"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Most commonly open TCP ports (used by --ports top).
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 161, 389, 443,
    445, 465, 514, 587, 631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723,
    1883, 2049, 2082, 2083, 2181, 2375, 2376, 3000, 3128, 3306, 3389, 3690,
    4443, 4444, 5000, 5060, 5432, 5601, 5672, 5900, 5984, 6000, 6379, 6443,
    7001, 8000, 8008, 8080, 8081, 8086, 8088, 8443, 8888, 9000, 9042, 9090,
    9092, 9200, 9300, 9418, 10000, 11211, 15672, 27017, 50000,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 514: "shell", 587: "submission",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3128: "squid",
    3306: "mysql", 3389: "rdp", 3690: "svn", 4443: "https-alt",
    5000: "http-alt", 5060: "sip", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6000: "x11", 6379: "redis",
    6443: "kubernetes", 7001: "weblogic", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8086: "influxdb", 8088: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt", 9042: "cassandra",
    9090: "http-alt", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch",
    9418: "git", 10000: "webmin", 11211: "memcached", 15672: "rabbitmq",
    27017: "mongodb", 50000: "http-alt",
}

HTTP_PORTS = {80, 81, 3000, 5000, 5601, 5984, 7001, 8000, 8008, 8080, 8081,
              8086, 8088, 8888, 9000, 9090, 9200, 10000, 15672, 50000}
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 6443, 8443}
TLS_HTTP_PORTS = {443, 4443, 6443, 8443}


# --------------------------------------------------------------------------
# Terminal colors
# --------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"

    @classmethod
    def disable(cls):
        for name in ("RESET", "BOLD", "RED", "GREEN", "YELLOW", "BLUE",
                     "MAGENTA", "CYAN", "GREY"):
            setattr(cls, name, "")


def setup_colors(no_color=False):
    if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        C.disable()
    elif os.name == "nt":
        os.system("")  # enables ANSI escape processing on Windows 10+


SEVERITY_COLORS = {
    "CRITICAL": lambda: C.RED + C.BOLD,
    "HIGH": lambda: C.RED,
    "MEDIUM": lambda: C.YELLOW,
    "LOW": lambda: C.GREEN,
}


def color_severity(severity):
    col = SEVERITY_COLORS.get(str(severity).upper())
    return f"{col()}{severity}{C.RESET}" if col else str(severity)


def interface():
    print(f"""{C.CYAN}
    {"=" * 60}
    ║ [►] STATUS: INITIALIZING SYSTEM...                       ║
    ║ [►] MODULE: VULNERABILITY_SCAN_V{__version__:<25}║
    ╠{"═" * 58}╣
    ║          ██████╗ ████████╗███████╗ ██████╗               ║
    ║         ██╔════╝ ╚══██╔══╝██╔════╝██╔═══██╗              ║
    ║         ██║         ██║   █████╗  ██║   ██║              ║
    ║         ██║         ██║   ██╔══╝  ██║   ██║              ║
    ║         ╚██████╗    ██║   ██║     ╚██████╔╝              ║
    ║          ╚═════╝    ╚═╝   ╚═╝      ╚═════╝               ║
    ╠{"═" * 58}╣
    ║ >> CREATED BY: ORDUKHAN ORDUKHANLI [SECURED ACCESS]      ║
    ║ >> TARGETING: RECON & CVE LOOKUP                         ║
    {"=" * 60}{C.RESET}
""")


# --------------------------------------------------------------------------
# Target / port parsing
# --------------------------------------------------------------------------
def parse_ports(spec):
    """Parse a port spec like '22,80,8000-8100', 'top' or 'all'."""
    spec = str(spec).strip().lower()
    if spec in ("all", "-", "1-65535"):
        return list(range(1, 65536))
    if spec == "top":
        return list(TOP_PORTS)
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {sorted(bad)[:5]}")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def resolve_targets(targets, max_hosts=1024):
    """Expand hostnames, single IPs and CIDR ranges into (label, ip) pairs."""
    resolved = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            if len(hosts) > max_hosts:
                raise ValueError(f"{t} has {len(hosts)} hosts (limit {max_hosts})")
            resolved.extend((str(h), str(h)) for h in hosts)
            continue
        try:
            ip = socket.gethostbyname(t)
        except socket.gaierror as e:
            raise ValueError(f"cannot resolve '{t}': {e}") from e
        resolved.append((t, ip))
    return resolved


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def _recv(sock, size=4096):
    try:
        return sock.recv(size)
    except (socket.timeout, OSError):
        return b""


def _clean_banner(raw):
    text = raw.decode("utf-8", errors="ignore")
    # Keep printable characters only (binary greetings such as MySQL).
    text = "".join(ch if ch.isprintable() or ch in "\r\n" else " " for ch in text)
    return text.strip()


def _mysql_version(raw):
    # MySQL/MariaDB handshake: 3-byte len, 1-byte seq, protocol 0x0a, version\0
    if len(raw) > 5 and raw[4] == 0x0A:
        end = raw.find(b"\x00", 5)
        if end > 5:
            return raw[5:end].decode(errors="ignore")
    return None


def grab_banner(sock, host, port, timeout):
    """Read a banner from an already connected socket."""
    sock.settimeout(timeout)
    hostname = host
    tls_info = None

    if port in TLS_PORTS:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = ctx.wrap_socket(sock, server_hostname=hostname)
            tls_info = sock.version()
        except (ssl.SSLError, OSError):
            return "", None, sock

    req = (f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\n"
           f"User-Agent: CTFO/{__version__}\r\n\r\n").encode()
    if port in HTTP_PORTS or port in TLS_HTTP_PORTS:
        try:
            sock.sendall(req)
        except OSError:
            return "", tls_info, sock
        raw = _recv(sock)
    else:
        # Many services (SSH, FTP, SMTP, MySQL...) speak first.
        sock.settimeout(min(timeout, 1.5))
        raw = _recv(sock)
        sock.settimeout(timeout)
        if not raw:
            # Silent service: try an HTTP probe (web servers on odd ports
            # answer it, most other protocols reply with an error/banner).
            try:
                sock.sendall(req)
            except OSError:
                return "", tls_info, sock
            raw = _recv(sock)

    mysql = _mysql_version(raw) if raw else None
    if mysql:
        return f"MySQL {mysql}", tls_info, sock
    return _clean_banner(raw), tls_info, sock


def scan_port(host, port, timeout=1.0, grab=True):
    """Return a result dict for an open port, otherwise None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((host, port)) != 0:
            return None
        banner, tls_info = "", None
        if grab:
            banner, tls_info, sock = grab_banner(sock, host, port, max(timeout, 2.0))
        return build_result(port, banner, tls_info)
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def build_result(port, banner, tls_info=None):
    first_line = banner.splitlines()[0].strip() if banner else ""
    server = http_header(banner, "Server")
    product = extract_product(banner)
    service = service_name(port)
    if service == "unknown" and first_line.startswith("HTTP/"):
        service = "https" if tls_info else "http"
    elif service == "unknown" and first_line.startswith("SSH-"):
        service = "ssh"
    return {
        "port": port,
        "service": service,
        "banner": first_line,
        "server": server,
        "product": product,
        "tls": tls_info,
        "raw_banner": banner[:1024],
        "cves": [],
    }


def http_header(banner, name):
    m = re.search(rf"^{re.escape(name)}:\s*(.+)$", banner or "", re.I | re.M)
    return m.group(1).strip() if m else None


# Known product signatures -> (regex, canonical product name).
PRODUCT_PATTERNS = [
    (r"OpenSSH[_ -]([\w.]+)", "OpenSSH"),
    (r"dropbear[_ -]([\w.]+)", "Dropbear SSH"),
    (r"vsFTPd ([\d.]+)", "vsftpd"),
    (r"ProFTPD ([\d.]+\w*)", "ProFTPD"),
    (r"Pure-FTPd(?: ([\d.]+))?", "Pure-FTPd"),
    (r"FileZilla Server(?: version)? ([\d.]+\w*)", "FileZilla Server"),
    (r"Microsoft-IIS/([\d.]+)", "Microsoft IIS"),
    (r"Apache/([\d.]+)", "Apache HTTP Server"),
    (r"nginx/([\d.]+)", "nginx"),
    (r"lighttpd/([\d.]+)", "lighttpd"),
    (r"LiteSpeed(?:/([\d.]+))?", "LiteSpeed"),
    (r"Apache-Coyote/([\d.]+)", "Apache Tomcat"),
    (r"Jetty\(([\d.]+)", "Jetty"),
    (r"Werkzeug/([\d.]+)", "Werkzeug"),
    (r"gunicorn/([\d.]+)", "gunicorn"),
    (r"Exim ([\d.]+)", "Exim"),
    (r"Postfix", "Postfix"),
    (r"Sendmail ([\d.]+)", "Sendmail"),
    (r"Dovecot", "Dovecot"),
    (r"MySQL ([\d.]+)(?:-MariaDB)?", "MySQL"),
    (r"([\d.]+)-MariaDB", "MariaDB"),
    (r"redis_version:([\d.]+)", "Redis"),
    (r"Samba ([\d.]+)", "Samba"),
]

GENERIC_PRODUCT = re.compile(r"\b([A-Za-z][A-Za-z0-9\-]{2,})[/_ ]v?(\d+\.\d+(?:\.\d+)*[a-z0-9]*)\b")
GENERIC_SKIP = {"http", "https", "ssh", "smtp", "esmtp", "ftp", "tls", "ssl"}


def extract_product(banner):
    """Return {'name', 'version'} parsed from a banner, or None."""
    if not banner:
        return None
    # MariaDB reports itself as "MySQL 10.x.y-MariaDB" - prefer MariaDB.
    if "MariaDB" in banner:
        m = re.search(r"([\d.]+)-MariaDB", banner)
        return {"name": "MariaDB", "version": m.group(1) if m else None}
    for pattern, name in PRODUCT_PATTERNS:
        m = re.search(pattern, banner, re.I)
        if m:
            version = m.group(1) if m.groups() and m.group(1) else None
            return {"name": name, "version": version}
    server = http_header(banner, "Server") or banner.splitlines()[0]
    for m in GENERIC_PRODUCT.finditer(server):
        if m.group(1).lower() not in GENERIC_SKIP:
            return {"name": m.group(1), "version": m.group(2)}
    return None


def cve_keyword(result):
    """Best keyword for an NVD search, or None if nothing meaningful."""
    product = result.get("product")
    if product:
        if product.get("version"):
            return f"{product['name']} {product['version']}"
        return product["name"]
    return None


def scan_host(ip, ports, threads=200, timeout=1.0, grab=True, progress=True):
    open_ports = []
    total = len(ports)
    done = 0
    lock = threading.Lock()
    show = progress and sys.stderr.isatty()
    start = time.time()

    with ThreadPoolExecutor(max_workers=max(1, min(threads, total))) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout, grab) for p in ports]
        try:
            for fut in as_completed(futures):
                res = fut.result()
                with lock:
                    done += 1
                    if res:
                        open_ports.append(res)
                        if show:
                            sys.stderr.write("\r" + " " * 70 + "\r")
                        print(f"  {C.GREEN}[+]{C.RESET} {res['port']}/tcp open "
                              f"{C.GREY}{res['service']}{C.RESET}", flush=True)
                    if show and (done % 250 == 0 or done == total):
                        pct = done * 100 // total
                        sys.stderr.write(f"\r  {C.GREY}scanning {done}/{total} "
                                         f"({pct}%) {time.time() - start:.1f}s{C.RESET}")
                        sys.stderr.flush()
        except KeyboardInterrupt:
            for f in futures:
                f.cancel()
            if show:
                sys.stderr.write("\n")
            print(f"{C.YELLOW}[!] scan interrupted - showing partial results{C.RESET}")
    if show:
        sys.stderr.write("\r" + " " * 70 + "\r")
    return sorted(open_ports, key=lambda r: r["port"])


# --------------------------------------------------------------------------
# OS fingerprinting
# --------------------------------------------------------------------------
OS_RULES = [
    ("Linux (Ubuntu)", ["ubuntu"], 3),
    ("Linux (Debian)", ["debian", "deb10", "deb11", "deb12", "+deb"], 3),
    ("Linux (CentOS/RHEL)", ["centos", "red hat", "rhel", "el7", "el8", "el9"], 3),
    ("Linux (Fedora)", ["fedora"], 3),
    ("Linux (Alpine)", ["alpine"], 3),
    ("Windows Server", ["windows", "microsoft-iis", "microsoft", "win32", "win64"], 3),
    ("FreeBSD", ["freebsd"], 3),
    ("OpenBSD", ["openbsd"], 3),
    ("Linux/Unix", ["openssh", "apache", "nginx", "postfix", "exim", "vsftpd",
                    "proftpd", "dovecot", "lighttpd"], 1),
]
WINDOWS_PORTS = {135, 139, 445, 3389, 5985, 5986}


def guess_os(banners, ports=()):
    combined = " ".join(b for b in banners if b).lower()
    scores = {}
    for name, keys, weight in OS_RULES:
        hits = sum(1 for k in keys if k in combined)
        if hits:
            scores[name] = scores.get(name, 0) + hits * weight
    win_hits = len(WINDOWS_PORTS.intersection(ports))
    if win_hits:
        scores["Windows Server"] = scores.get("Windows Server", 0) + win_hits * 2
    if not scores:
        return "Unknown"
    best = max(scores.items(), key=lambda kv: kv[1])
    # Prefer specific distro over generic Linux/Unix when it also scored.
    specific = {k: v for k, v in scores.items() if k != "Linux/Unix"}
    if best[0] == "Linux/Unix" and specific:
        best = max(specific.items(), key=lambda kv: kv[1])
    return best[0]


# --------------------------------------------------------------------------
# CVE lookup (NIST NVD API 2.0)
# --------------------------------------------------------------------------
class NVDClient:
    """Small NVD client with rate limiting, retries and an in-memory cache."""

    def __init__(self, api_key=None, limit=5, timeout=15):
        self.api_key = api_key
        self.limit = limit
        self.timeout = timeout
        self.cache = {}
        self._lock = threading.Lock()
        self._calls = []
        # Public limits: 5 req / 30 s without key, 50 req / 30 s with key.
        self.window, self.max_calls = 30.0, (50 if api_key else 5)

    def _wait_for_slot(self):
        with self._lock:
            now = time.time()
            self._calls = [t for t in self._calls if now - t < self.window]
            if len(self._calls) >= self.max_calls:
                sleep_for = self.window - (now - self._calls[0]) + 0.1
                time.sleep(max(0, sleep_for))
            self._calls.append(time.time())

    def _get(self, params):
        url = f"{NVD_URL}?{urllib.parse.urlencode(params)}"
        headers = {"User-Agent": f"CTFO/{__version__}"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        for attempt in range(3):
            self._wait_for_slot()
            req = urllib.request.Request(url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                if e.code in (403, 429, 503) and attempt < 2:
                    time.sleep(6 * (attempt + 1))
                    continue
                raise
            except urllib.error.URLError:
                if attempt < 2:
                    time.sleep(2)
                    continue
                raise
        return {}

    @staticmethod
    def parse(data):
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            metrics = cve.get("metrics", {})
            score, severity, version = None, "N/A", None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    m = metrics[key][0]
                    cvss = m.get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or m.get("baseSeverity", "N/A")
                    version = cvss.get("version")
                    break
            desc = next((d.get("value", "") for d in cve.get("descriptions", [])
                         if d.get("lang") == "en"), "")
            results.append({
                "id": cve.get("id"),
                "score": score,
                "severity": severity,
                "cvss_version": version,
                "published": (cve.get("published") or "")[:10],
                "description": desc,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id')}",
            })
        results.sort(key=lambda r: (r["score"] or 0), reverse=True)
        return results

    def search(self, keyword):
        keyword = keyword.strip()
        if keyword in self.cache:
            return self.cache[keyword]
        params = {"keywordSearch": keyword, "resultsPerPage": 50}
        data = self._get(params)
        results = self.parse(data)[: self.limit]
        self.cache[keyword] = results
        return results


def check_cve(keyword, client=None):
    """Backwards compatible helper used by v1."""
    client = client or NVDClient()
    try:
        return client.search(keyword)
    except Exception as e:  # noqa: BLE001 - network errors must not kill the scan
        print(f"  {C.RED}CVE error: {e}{C.RESET}")
        return []


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def print_host_report(report):
    print(f"\n{C.BOLD}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}Target:{C.RESET} {report['target']} ({report['ip']})")
    print(f"{C.BOLD}Open ports:{C.RESET} {len(report['ports'])}   "
          f"{C.BOLD}Duration:{C.RESET} {report['duration']}s")
    print(f"{'=' * 60}")
    for r in report["ports"]:
        print(f"{C.GREEN}[+] Port {r['port']}/tcp OPEN{C.RESET}  "
              f"{C.CYAN}{r['service']}{C.RESET}"
              + (f"  {C.GREY}[{r['tls']}]{C.RESET}" if r.get("tls") else ""))
        if r["product"]:
            ver = r["product"].get("version") or "?"
            print(f"    Product : {C.MAGENTA}{r['product']['name']} {ver}{C.RESET}")
        if r.get("server"):
            print(f"    Server  : {r['server'][:80]}")
        print(f"    Banner  : {(r['banner'] or 'banner is empty')[:80]}")
        if r.get("cve_keyword") is not None:
            if r["cves"]:
                note = (f" {C.YELLOW}(product-name match, version not verified){C.RESET}"
                        if r.get("cve_unverified") else "")
                print(f"    CVEs for '{r['cve_keyword']}':{note}")
                for c in r["cves"]:
                    score = c["score"] if c["score"] is not None else "N/A"
                    print(f"      {c['id']:<17} score {str(score):<4} "
                          f"{color_severity(c['severity'])}")
            else:
                print(f"    {C.GREY}CVE not found for '{r['cve_keyword']}'{C.RESET}")
        elif r.get("cve_skipped"):
            print(f"    {C.GREY}CVE lookup skipped (no product/version in banner){C.RESET}")
        print()
    print(f"{C.BOLD}Expected OS:{C.RESET} {C.YELLOW}{report['os']}{C.RESET}")


def write_report(reports, path):
    ext = os.path.splitext(path)[1].lower()
    meta = {
        "tool": "CTFO",
        "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    if ext == ".json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump({**meta, "hosts": reports}, f, indent=2)
    elif ext == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "ip", "port", "service", "product", "version",
                        "banner", "cve_id", "score", "severity"])
            for rep in reports:
                for r in rep["ports"]:
                    prod = r["product"] or {}
                    base = [rep["target"], rep["ip"], r["port"], r["service"],
                            prod.get("name", ""), prod.get("version", "") or "",
                            r["banner"]]
                    if r["cves"]:
                        for c in r["cves"]:
                            w.writerow(base + [c["id"], c["score"], c["severity"]])
                    else:
                        w.writerow(base + ["", "", ""])
    elif ext in (".html", ".htm"):
        with open(path, "w", encoding="utf-8") as f:
            f.write(render_html(reports, meta))
    else:
        raise ValueError("report must end with .json, .csv or .html")


def render_html(reports, meta):
    e = html.escape
    sev_cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CTFO report</title><style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#1d1d1f;background:#fafafa}}
h1{{margin-bottom:.2rem}} .meta{{color:#666;margin-bottom:2rem}}
section{{background:#fff;border:1px solid #e3e3e3;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1.5rem}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:.45rem .5rem;border-bottom:1px solid #eee;vertical-align:top}}
th{{font-weight:600;color:#555}} code{{font-size:12px;word-break:break-all}}
.sev{{font-weight:600;padding:1px 6px;border-radius:4px;font-size:12px}}
.crit{{background:#7a0010;color:#fff}} .high{{background:#d93025;color:#fff}} .med{{background:#f9ab00}} .low{{background:#cde8cd}}
a{{color:#0b57d0}}
</style></head><body><h1>CTFO scan report</h1>
<div class="meta">CTFO v{e(meta['version'])} &middot; {e(meta['generated'])}</div>"""]
    for rep in reports:
        parts.append(f"<section><h2>{e(rep['target'])} <small>({e(rep['ip'])})</small></h2>"
                     f"<p>Open ports: {len(rep['ports'])} &middot; Expected OS: "
                     f"<b>{e(rep['os'])}</b> &middot; Duration: {rep['duration']}s</p>")
        if not rep["ports"]:
            parts.append("<p>No open ports found.</p></section>")
            continue
        parts.append("<table><tr><th>Port</th><th>Service</th><th>Product</th>"
                     "<th>Banner</th><th>CVEs</th></tr>")
        for r in rep["ports"]:
            prod = r["product"] or {}
            prod_s = f"{prod.get('name', '')} {prod.get('version') or ''}".strip()
            cves = "".join(
                f"<div><a href='{e(c['url'])}'>{e(c['id'])}</a> "
                f"<span class='sev {sev_cls.get(str(c['severity']).upper(), '')}'>"
                f"{e(str(c['severity']))} {e(str(c['score']))}</span></div>"
                for c in r["cves"]) or "&ndash;"
            parts.append(f"<tr><td>{r['port']}/tcp</td><td>{e(r['service'])}</td>"
                         f"<td>{e(prod_s) or '&ndash;'}</td><td><code>{e(r['banner'] or '')}</code></td>"
                         f"<td>{cves}</td></tr>")
        parts.append("</table></section>")
    parts.append("</body></html>")
    return "\n".join(parts)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="CTFO",
        description="Network recon & CVE lookup tool (authorized testing only).",
        epilog="examples:\n"
               "  python CTFO.py scanme.nmap.org -p top --cve\n"
               "  python CTFO.py 192.168.1.10 -p 1-1024,3306 -o report.html\n"
               "  python CTFO.py 10.0.0.0/28 -p 22,80,443 -t 300 -o out.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="*", help="IP, hostname or CIDR (omit for interactive mode)")
    p.add_argument("-p", "--ports", default="all",
                   help="ports: 'all' (default), 'top', or list like 22,80,8000-8100")
    p.add_argument("-t", "--threads", type=int, default=200, help="worker threads (default 200)")
    p.add_argument("--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    p.add_argument("--no-banner", action="store_true", help="skip banner grabbing (faster)")
    p.add_argument("--cve", action="store_true", help="look up CVEs on NVD for detected products")
    p.add_argument("--cve-limit", type=int, default=5, help="max CVEs per service (default 5)")
    p.add_argument("--cve-all", action="store_true",
                   help="also query NVD with the raw banner when no product/version is detected")
    p.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                   help="NVD API key (or env NVD_API_KEY) for higher rate limits")
    p.add_argument("-o", "--output", help="write report to .json, .csv or .html")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-q", "--quiet", action="store_true", help="no banner art / progress")
    p.add_argument("-V", "--version", action="version", version=f"CTFO {__version__}")
    return p


def interactive_args(args):
    host = input("Enter Target IP / hostname / CIDR: ").strip()
    if not host:
        sys.exit("no target given")
    args.targets = [host]
    ports = input("Ports [all / top / e.g. 1-1024] (default: all): ").strip()
    if ports:
        args.ports = ports
    args.cve = input("Do you want to check CVE (y/n): ").strip().lower().startswith("y")
    out = input("Save report to file (.json/.csv/.html, empty = no): ").strip()
    if out:
        args.output = out
    return args


def run(args):
    ports = parse_ports(args.ports)
    targets = resolve_targets(args.targets)
    nvd = NVDClient(api_key=args.api_key, limit=args.cve_limit) if args.cve else None
    reports = []

    for label, ip in targets:
        print(f"{C.BOLD}------ {label} ({ip}) scanning {len(ports)} port(s) ------{C.RESET}")
        start = time.time()
        results = scan_host(ip, ports, threads=args.threads, timeout=args.timeout,
                            grab=not args.no_banner, progress=not args.quiet)
        duration = round(time.time() - start, 2)

        if nvd:
            for r in results:
                kw = cve_keyword(r)
                if not kw and args.cve_all and r["banner"]:
                    kw = r["banner"][:60]
                if kw:
                    r["cve_keyword"] = kw
                    r["cves"] = check_cve(kw, nvd)
                    prod = r.get("product") or {}
                    if not r["cves"] and prod.get("version"):
                        # Exact "name version" often has no keyword hit on NVD;
                        # fall back to the product name and flag it.
                        r["cve_keyword"] = prod["name"]
                        r["cves"] = check_cve(prod["name"], nvd)
                        r["cve_unverified"] = bool(r["cves"])
                else:
                    r["cve_skipped"] = True

        report = {
            "target": label,
            "ip": ip,
            "duration": duration,
            "os": guess_os([r["raw_banner"] for r in results], [r["port"] for r in results]),
            "ports": results,
        }
        reports.append(report)
        print_host_report(report)

    if args.output:
        write_report(reports, args.output)
        print(f"\n{C.GREEN}[+] report saved to {args.output}{C.RESET}")
    return reports


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_colors(args.no_color)
    if not args.quiet:
        interface()
    if not args.targets:
        args = interactive_args(args)
    try:
        run(args)
    except ValueError as e:
        parser.error(str(e))
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] aborted by user{C.RESET}")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
