# Changelog

## [2.0.0] - 2026-11-25

### Added
- Command-line interface (`argparse`) with interactive mode kept as fallback.
- Hostname and CIDR target support, multiple targets per run.
- Port selection: `all`, `top`, lists and ranges.
- Configurable threads and timeout, `--no-banner` fast mode.
- TLS banner grabbing (HTTPS, IMAPS, POP3S, LDAPS, ...), MySQL/MariaDB greeting parsing.
- Product/version extraction from banners (OpenSSH, Apache, nginx, IIS, vsftpd, ProFTPD, Exim, ...).
- Service names for open ports.
- NVD client: rate limiting, retries, in-memory cache, API key support, CVSS v4.0, results sorted by score, CVE links and descriptions.
- JSON, CSV and HTML reports (`-o`).
- Colored output, progress indicator, Ctrl+C shows partial results.
- Unit tests and GitHub Actions CI.

### Changed
- Banner grabbing reuses the scan connection (v1 connected twice per open port).
- CVE searches use the detected product and version instead of the raw first banner line (e.g. `HTTP/1.1 200 OK`), and are URL-encoded.
- OS detection uses weighted scoring and Windows-specific ports.
- Replaced `requests` with the standard library: no dependencies.

### Fixed
- Bare `except:` clauses that hid errors and swallowed Ctrl+C.
- HTTP probes sent a fake `Host: target` header.

## [1.0.0]
- Initial release: full port scan, banner grabbing, OS guess, NVD CVE lookup.
