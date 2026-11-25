# CTFO — Network Recon & CVE Lookup Tool

A fast, multi-threaded Python tool for network reconnaissance: port scanning, service banner grabbing, product/version detection, OS fingerprinting and live CVE lookup against the NIST NVD database.

**v2.0.0** — zero third-party dependencies (Python standard library only).

## Features

- **Flexible targets** — IP address, hostname, or CIDR range (`10.0.0.0/28`), several at once
- **Flexible ports** — `all` (1–65535), `top` (~80 most common ports) or a list such as `22,80,8000-8100`
- **Fast concurrent scan** — configurable thread pool (default 200) and connect timeout
- **Smart banner grabbing** — one connection per port; passive read for SSH/FTP/SMTP, HTTP probe for web ports, TLS handshake for HTTPS/IMAPS/POP3S…, MySQL/MariaDB greeting parsing
- **Service & version detection** — recognises OpenSSH, Apache, nginx, IIS, vsftpd, ProFTPD, Exim, Postfix, MySQL, MariaDB, Tomcat, and more
- **OS fingerprinting** — weighted scoring from banners and Windows-specific ports
- **Live CVE lookup** — NVD API 2.0 with CVSS v4.0/3.1/3.0/2.0 scores, sorted by severity, built-in rate limiting, retries, caching, optional API key
- **Reports** — export to **JSON**, **CSV** or a styled **HTML** report
- **Colored output**, progress indicator, Ctrl+C shows partial results
- **Interactive mode** — run without arguments and answer the prompts (like v1)

## Installation

```bash
git clone https://github.com/orduxanliorduxan3-oss/CTFO.git
cd CTFO
python CTFO.py --help
```

Requires Python 3.8+. No `pip install` needed.

## Usage

```bash
# interactive mode
python CTFO.py

# top ports + CVE lookup
python CTFO.py scanme.nmap.org -p top --cve

# custom ports, HTML report
python CTFO.py 192.168.1.10 -p 1-1024,3306,8080 --cve -o report.html

# small subnet, JSON report, more threads
python CTFO.py 10.0.0.0/28 -p 22,80,443 -t 300 -o out.json
```

| Option | Description |
| --- | --- |
| `targets` | IP, hostname or CIDR (omit for interactive mode) |
| `-p, --ports` | `all` (default), `top`, or `22,80,8000-8100` |
| `-t, --threads` | worker threads (default 200) |
| `--timeout` | connect timeout in seconds (default 1.0) |
| `--no-banner` | skip banner grabbing (faster) |
| `--cve` | look up CVEs on NVD for detected products |
| `--cve-limit N` | max CVEs per service (default 5) |
| `--cve-all` | also search with the raw banner when no product is detected |
| `--api-key KEY` | NVD API key (or env `NVD_API_KEY`) — 50 req/30 s instead of 5 |
| `-o, --output` | write report to `.json`, `.csv` or `.html` |
| `--no-color` | disable colors (also honours `NO_COLOR`) |
| `-q, --quiet` | no ASCII art / progress |
| `-V, --version` | show version |

Get a free NVD API key at <https://nvd.nist.gov/developers/request-an-api-key>.

## Example Output

```
[+] Port 22/tcp OPEN  ssh
    Product : OpenSSH 8.2p1
    Banner  : SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    CVEs for 'OpenSSH 8.2p1':
      CVE-2020-15778    score 7.8  HIGH
      CVE-2021-41617    score 7.0  HIGH

[+] Port 80/tcp OPEN  http
    Product : Apache HTTP Server 2.4.41
    Server  : Apache/2.4.41 (Ubuntu)
    Banner  : HTTP/1.1 200 OK

Expected OS: Linux (Ubuntu)
```

CVE results come from a keyword search, so treat them as leads to verify, not confirmed vulnerabilities. When no CVE matches the exact version, CTFO falls back to the product name and marks the results as *version not verified*.

## Running tests

```bash
python -m unittest discover -s tests -v
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only scan systems you own or have explicit permission to test.

## Author

Ordukhan Ordukhanli
