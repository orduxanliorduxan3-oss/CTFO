# Network Recon & CVE Lookup Tool

A multi-threaded Python tool for network reconnaissance — scanning ports, grabbing service banners, fingerprinting the target OS, and cross-referencing findings against live CVE data.

## Features

- **Full port scan (1–65535)** using a thread pool of 100 concurrent workers for fast results
- **Banner grabbing** on open ports (HTTP-based probes for common web ports)
- **OS fingerprinting** — infers the likely operating system from collected banners
- **Live CVE lookup** — queries the NIST NVD API in real time, returning CVE ID, CVSS score, and severity for each detected service

## How It Works

1. User provides a target IP
2. The tool scans all 65,535 ports concurrently
3. Every open port is banner-grabbed to identify the running service
4. Based on the banners, the tool guesses the target's OS
5. (Optional) Each banner/port is used as a search keyword against the NVD CVE database, surfacing known vulnerabilities

## Tech Stack

Python, `socket`, `concurrent.futures` (ThreadPoolExecutor), `requests`, NVD REST API

## Example Output

[+] Port 80 is OPEN
Banner : HTTP/1.1 200 OK
ID:CVE-2023-XXXXX, Score:7.5, Severity:HIGH

Excepting OS : Linux (Ubuntu/Debian)


## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Only scan systems you own or have explicit permission to test.

## Author

Ordukhan Ordukhanli
