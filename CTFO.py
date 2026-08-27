import socket
import requests
import json
from concurrent.futures import ThreadPoolExecutor
from functools import partial


def interface():
    print(f"""
    {"="*60}
    ║ [►] STATUS: INITIALIZING SYSTEM...                       ║
    ║ [►] MODULE: VULNERABILITY_SCAN_V2                        ║
    ╠{"═"*58}╣
    ║          ██████╗ ████████╗███████╗ ██████╗               ║
    ║         ██╔════╝ ╚══██╔══╝██╔════╝██╔═══██╗              ║
    ║         ██║         ██║   █████╗  ██║   ██║              ║
    ║         ██║         ██║   ██╔══╝  ██║   ██║              ║
    ║         ╚██████╗    ██║   ██║     ╚██████╔╝              ║
    ║          ╚═════╝    ╚═╝   ╚═╝      ╚═════╝               ║
    ╠{"═"*58}╣
    ║ >> CREATED BY: ORDUKHAN ORDUKHANLI [SECURED ACCESS]      ║
    ║ >> TARGETING: RECON & CVE LOOKUP                         ║
    {"="*60}
""")


def get_banner(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((ip, port))
        probes = {
            80:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            443:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
            8080:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
        }
        probe = probes.get(port, b"\r\n")
        s.send(probe)
        banner = s.recv(2048).decode(errors='ignore').strip()
        s.close()
        return banner
    except:
        return None


def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                banner = get_banner(host, port)
                if banner:
                    return f"{port}-->{banner.split(chr(10))[0]}"
                return f"{port}-->banner is empty"
    except:
        pass
    return None
def guess_os(banners):
    combined = " ".join(banners).lower()
    if "ubuntu" in combined or "debian" in combined:
        return "Linux (Ubuntu/Debian)"
    elif "centos" in combined or "red hat" in combined:
        return "Linux (CentOS/RHEL)"
    elif "windows" in combined or "iis" in combined:
        return "Windows Server"
    elif "freebsd" in combined:
        return "FreeBSD"
    elif "apache" in combined:
        return "Linux (Apache)"
    else:
        return "Unknown"
def check_cve(keyword):
    try:
        url=f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=5"
        respond=requests.get(url,timeout=10)
        if respond.status_code==200:
            result=[]
            data=respond.json()
            vulnerability=data.get("vulnerabilities",[])
            for vuln in vulnerability:
                cve=vuln["cve"]
                metrics=cve.get("metrics",{})
                severity=""
                score="N/A"
                for i in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if i in metrics:
                        m=metrics[i][0]
                        score=m["cvssData"]["baseScore"]
                        if i=='cvssMetricV2':
                            severity=m.get("baseSeverity","N/A")
                        else:
                            severity=m["cvssData"]["baseSeverity"]
                        break
                result.append({
                    "id":cve["id"],
                    "score":score,
                    "severity":severity,
                    })
            return result
    except Exception as e:
            print(f"CVE error:{e}")
    return[]
   
def main():
    interface()

    host = input("Enter Target IP: ")
    cve_answer = input("do you want to check CVE(y/n):")
    print(f"------{host} scanning------")
    allports = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        results = ex.map(partial(scan_port, host), range(1, 65536))
    for r in results:
        if r is not None:
            allports+=[r]
    found_banners = []
    for item in allports:
        if "-->" not in item:
            continue
        port = int(item.split("-->")[0])
        banner = item.split("-->")[1]
        found_banners.append(banner)

        print(f"[+] Port {port} is OPEN")
        print(f"    Banner : {banner[:80]}")
        if cve_answer == 'y':
            if banner not in ["banner is empty", "banner oxunmadi"]:
                keyword=banner
                cves=check_cve(keyword)
                if cves:
                    for c in cves:
                        print(f"   ID:{c['id']},Score:{c['score']},Severity:{c['severity']}")
                else:
                    print(f"   CVE not found")
            else:
                keyword=str(port)
                cves=check_cve(keyword)
                if cves:
                    for c in cves:
                        print(f"   ID:{c['id']},Score:{c['score']},Severity:{c['severity']}")
                else:
                    print(f"   CVE not found")
        print()

        print("=" * 50)
    if found_banners:
        print(f"Excepting OS : {guess_os(found_banners)}")

if __name__ == "__main__":
    main()
