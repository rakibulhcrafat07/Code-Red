#!/usr/bin/env python3
"""
port_scanner.py  —  Advanced multithreaded TCP/UDP port scanner
================================================================
Code-Red | 00 - Foundations | Project 03

A port scanner built from raw sockets, standing only on Python's
standard library (colorama / scapy are optional — the core works without them).

Features:
  * TCP connect scan (threaded + asyncio engine)
  * Multiple targets / CIDR     (192.168.1.0/24, host1,host2)
  * Top-ports mode              (--top 100)
  * Banner grabbing + service name (thread-safe getservbyport)
  * Host discovery              (--discover: skip dead hosts)
  * UDP scan                    (--udp)
  * CVE lookup                  (--cve: banner -> known CVEs, offline signature DB)
  * Detection companion         (--detection: generate Suricata + Wazuh rules)
  * Colored output + progress   (when colorama is installed)
  * CSV / JSON / HTML report
  * SYN scan                    (--syn: needs scapy + admin)

Author: Rakibul Hoque Chowdhury (@rakibulhcrafat07)

WARNING: Run only against your own hosts, your own lab/VMs, or targets
         for which you have explicit written authorization.
"""

import os
import socket
import errno
import threading
import concurrent.futures
import argparse
import json
import csv
import sys
import time
import re
import ipaddress
import asyncio
import html
import urllib.request
import urllib.parse
from datetime import datetime

# --- Optional: colored output (falls back to plain text if missing) ---
try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False

    class _Dummy:
        def __getattr__(self, _):   # any color requested -> empty string
            return ""
    Fore = Style = _Dummy()


def c(text, color):
    """Return colored text when color is on, otherwise plain text."""
    if _HAS_COLOR and _USE_COLOR:
        return f"{color}{text}{Style.RESET_ALL}"
    return str(text)


_USE_COLOR = True   # becomes False when --no-color is passed


# =============================================================
#  Reference data
# =============================================================
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2049: "nfs", 3306: "mysql", 3389: "rdp", 4222: "nats",
    5040: "cdp", 5432: "postgresql", 5900: "vnc", 5939: "teamviewer",
    6379: "redis", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 27017: "mongodb",
}

# Top-100-ish common ports (for --top), in priority order
TOP_PORTS = [
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9,
    5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 6379,
    27017, 9200,
]

HTTP_LIKE_PORTS = {80, 443, 8000, 8080, 8443, 8008, 8081, 8888, 3000}

# ─────────────────────────────────────────────────────────────
#  Step 1 — FINGERPRINTS: recognise software + version from a banner.
#  Each entry: (regex, product).  The regex's ( ) group captures the version.
#  This is how the scanner turns "220 (vsFTPd 2.3.4)" into ("vsftpd", "2.3.4").
#  Grow this list as you meet new services.
# ─────────────────────────────────────────────────────────────
FINGERPRINTS = [
    (r"OpenSSH[_/ ]?([\d.]+)",       "openssh"),
    (r"vsFTPd ([\d.]+)",             "vsftpd"),
    (r"ProFTPD ([\d.]+)",            "proftpd"),
    (r"Apache/([\d.]+)",             "apache"),
    (r"nginx/([\d.]+)",              "nginx"),
    (r"lighttpd/([\d.]+)",           "lighttpd"),
    (r"Microsoft-IIS/([\d.]+)",      "iis"),
    (r"Exim ([\d.]+)",               "exim"),
    (r"Sendmail ([\d.]+)",           "sendmail"),
    (r"Unreal[^0-9]*([\d.]+)",       "unrealircd"),
    (r"Samba ([\d.]+)",              "samba"),
    (r"([\d.]+)[-\w]*\s*(?:MySQL|mysql)", "mysql"),
    (r"PHP/([\d.]+)",                "php"),
    (r"mod_ssl/([\d.]+)",            "mod_ssl"),
]

# ─────────────────────────────────────────────────────────────
#  Step 2 — CVE_DB keyed by product -> list of (version-condition, CVE, severity, desc)
#  version-condition examples:  "2.3.4" (exact) | "<=7.6" | "2.2.*" | "4.80-4.91"
# ─────────────────────────────────────────────────────────────
CVE_DB = {
    "openssh":   [("<=7.6",         "CVE-2018-15473", "Medium",   "OpenSSH username enumeration")],
    "vsftpd":    [("2.3.4",         "CVE-2011-2523", "Critical", "vsftpd 2.3.4 backdoor — RCE")],
    "proftpd":   [("1.3.0-1.3.5",   "CVE-2015-3306", "Critical", "ProFTPD mod_copy RCE")],
    "apache":    [("2.2.*",         "CVE-2017-15715", "High",     "Apache 2.2.x end-of-life — multiple CVEs"),
                  ("2.4.49-2.4.50", "CVE-2021-41773", "Critical", "Apache path traversal -> RCE")],
    "nginx":     [("1.10.0-1.20.0", "CVE-2021-23017", "High",     "nginx DNS resolver off-by-one")],
    "iis":       [("6.*",           "CVE-2017-7269", "Critical", "IIS 6.0 WebDAV buffer overflow")],
    "exim":      [("4.80-4.91",     "CVE-2019-10149", "Critical", "Exim 'Return of the Wizard' RCE")],
    "unrealircd":[("3.2.*",         "CVE-2010-2075", "Critical", "UnrealIRCd 3.2.8.1 backdoor — RCE")],
    "samba":     [("3.0.20-3.0.25", "CVE-2007-2447", "Critical", "Samba 'username map script' RCE")],
    "mysql":     [("5.0.*",         "CVE-2012-2122", "High",     "MySQL 5.x authentication bypass")],
    "php":       [("5.0.0-5.4.2",   "CVE-2012-1823", "Critical", "PHP-CGI query-string argument injection")],
    "mod_ssl":   [("2.0.0-2.2.99",  "CVE-2002-0082", "High",     "mod_ssl outdated — remote code execution")],
}


def _ver_tuple(v):
    """'2.3.4' -> (2,3,4) ;  '4.7p1' -> (4,7).  Numbers only, for comparing."""
    nums = re.findall(r"\d+", v)
    return tuple(int(n) for n in nums) if nums else (0,)


def _ver_match(version, cond):
    """Does `version` satisfy `cond`?  Supports exact, <=, >=, range (a-b), wildcard (2.2.*)."""
    cond = cond.strip()
    if cond in ("*", ""):
        return True
    if cond.endswith(".*"):                       # "2.2.*"
        return version.startswith(cond[:-1])      # starts with "2.2."
    v = _ver_tuple(version)
    if cond.startswith("<="):
        return v <= _ver_tuple(cond[2:])
    if cond.startswith(">="):
        return v >= _ver_tuple(cond[2:])
    if "-" in cond:                               # "4.80-4.91"
        a, b = cond.split("-", 1)
        return _ver_tuple(a) <= v <= _ver_tuple(b)
    return v == _ver_tuple(cond)                  # exact


def identify(banner):
    """Return (product, version) recognised from the banner, or (None, None)."""
    for pattern, product in FINGERPRINTS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            version = ""
            for g in m.groups():                  # first non-empty capture = version
                if g:
                    version = g
                    break
            return product, version
    return None, None

# --- Locks and shared state ---
_SERVICE_LOCK = threading.Lock()   # getservbyport is not thread-safe
_PRINT_LOCK = threading.Lock()     # keep verbose output lines from interleaving
_COUNT_LOCK = threading.Lock()     # progress counter
_scanned = 0
_total = 0


# =============================================================
#  Helpers
# =============================================================
def parse_ports(spec):
    """'22,80,443' | '1-1000' | '22,8000-8100' -> sorted list of ints"""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def expand_targets(spec):
    """'192.168.1.0/24' | 'host1,host2' | '10.0.0.1' -> list of IPs"""
    targets = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            # CIDR or a single IP?
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > 1:
                targets.extend(str(ip) for ip in net.hosts())   # whole subnet
            else:
                targets.append(str(net.network_address))
        except ValueError:
            # hostname — resolve it to an IP
            try:
                targets.append(socket.gethostbyname(part))
            except socket.gaierror:
                print(c(f"[!] Could not resolve: {part}", Fore.RED))
    return targets


def get_service(port):
    if port in COMMON_PORTS:                 # known port -> instant, no lock (fast)
        return COMMON_PORTS[port]
    with _SERVICE_LOCK:                      # unknown port -> take the lock only then
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"                 # not in /etc/services


# --- CVE lookup: several online sources when online, else offline DB ---
_INTERNET = None                 # cache: None=unknown, True/False
_NVD_KEY = None                  # optional NVD API key (set from --nvd-key)
_VULNERS_KEY = None              # optional vulners.com API key (set from --vulners-key)
_FORCE_OFFLINE = False           # set True by --cve-offline
_CVE_CACHE = {}                  # "product version" -> result (avoid repeat queries)
_CVE_NET_LOCK = threading.Lock() # throttle NVD calls (rate limit)
_last_nvd_call = [0.0]           # timestamp of last NVD call (list = mutable)

# product name (from FINGERPRINTS) -> "vendor:product" for CPE-based queries
CPE_MAP = {
    "openssh": "openbsd:openssh",     "vsftpd":  "vsftpd:vsftpd",
    "proftpd": "proftpd:proftpd",     "apache":  "apache:http_server",
    "nginx":   "nginx:nginx",         "lighttpd":"lighttpd:lighttpd",
    "iis":     "microsoft:internet_information_services",
    "exim":    "exim:exim",           "sendmail":"sendmail:sendmail",
    "unrealircd":"unrealircd:unrealircd", "samba": "samba:samba",
    "mysql":   "mysql:mysql",         "php":     "php:php",
    "mod_ssl": "modssl:mod_ssl",
}


def _read_key_file(name):
    """Read an API key from a file sitting next to this script (e.g. vulners_key.txt).
    Lets you copy the script + the key file to any PC and just run — while the
    key file stays OUT of the public repo (add it to .gitignore)."""
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
        with open(path) as f:
            return f.read().strip() or None
    except Exception:
        return None


def _cvss_label(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Unknown"
    if s >= 9: return "Critical"
    if s >= 7: return "High"
    if s >= 4: return "Medium"
    return "Low"


def _throttle():
    """Keep under NVD's rate limit (spaced-out calls)."""
    gap = 6 if not _NVD_KEY else 1
    wait = gap - (time.time() - _last_nvd_call[0])
    if wait > 0:
        time.sleep(wait)
    _last_nvd_call[0] = time.time()


def _has_internet():
    """Check once whether the machine has general internet access; cache it.
    (Tries a plain TCP connection to a few reliable hosts — not tied to NVD.)"""
    global _INTERNET
    if _INTERNET is None:
        _INTERNET = False
        for host, port in (("1.1.1.1", 443), ("8.8.8.8", 443), ("services.nvd.nist.gov", 443)):
            try:
                socket.create_connection((host, port), timeout=3).close()
                _INTERNET = True
                break
            except OSError:
                continue
    return _INTERNET


def cve_lookup_offline(banner):
    """Fingerprint the banner -> (product, version) -> match against CVE_DB."""
    product, version = identify(banner)
    if not product:
        return []
    found = []
    for cond, cve_id, sev, desc in CVE_DB.get(product, []):
        if _ver_match(version, cond):
            found.append((cve_id, sev, desc))
    return found


def _query_nvd(product, version):
    """Source 1 — NVD (official). Uses CPE version-range matching when the product
    is known (comprehensive, like nmap), else falls back to keyword search."""
    out = {}
    vp = CPE_MAP.get(product)
    if vp:
        # virtualMatchString -> NVD returns EVERY CVE that affects this product+version
        cpe = f"cpe:2.3:a:{vp}:{version}"
        params = {"virtualMatchString": cpe, "resultsPerPage": 200}
    else:
        params = {"keywordSearch": f"{product} {version}".strip(), "resultsPerPage": 50}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    if _NVD_KEY:
        req.add_header("apiKey", _NVD_KEY)
    try:
        with _CVE_NET_LOCK:
            _throttle()
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.load(resp)
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            sev = "Unknown"
            metrics = cve.get("metrics", {})
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if k in metrics:
                    sev = metrics[k][0]["cvssData"].get("baseSeverity", "Unknown")
                    break
            desc = cve["descriptions"][0]["value"][:80]
            out[cve["id"]] = (cve["id"], sev.title(), desc)
    except Exception:
        pass
    return out


def _query_circl(product, version):
    """Source 2 — CIRCL (cve.circl.lu). Free, no key, CPE-based -> comprehensive."""
    out = {}
    vp = CPE_MAP.get(product)
    if not vp:
        return out
    cpe = f"cpe:2.3:a:{vp}:{version}"
    url = "https://cve.circl.lu/api/cvefor/" + urllib.parse.quote(cpe, safe="")
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.load(resp)
        items = data if isinstance(data, list) else data.get("results", [])
        for item in items:
            cid = item.get("id") or item.get("cveMetadata", {}).get("cveId")
            if not cid:
                continue
            sev = _cvss_label(item.get("cvss"))
            summ = (item.get("summary") or "")[:80]
            out[cid] = (cid, sev, summ)
    except Exception:
        pass
    return out


def _query_vulners(product, version):
    """Source 3 — vulners.com (the source nmap's vulners script uses). Needs a free API key."""
    out = {}
    if not _VULNERS_KEY:
        return out
    vp = CPE_MAP.get(product)
    if not vp:
        return out
    cpe = f"cpe:/a:{vp}:{version}"
    payload = json.dumps({"software": cpe, "version": version, "type": "cpe"}).encode()
    req = urllib.request.Request("https://vulners.com/api/v3/burp/software/",
                                 data=payload,
                                 headers={"Content-Type": "application/json",
                                          "X-Api-Key": _VULNERS_KEY})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.load(resp)
        for item in data.get("data", {}).get("search", []):
            src = item.get("_source", {})
            cid = src.get("id")
            if not cid:
                continue
            sev = _cvss_label((src.get("cvss") or {}).get("score"))
            title = (src.get("title") or "")[:80]
            out[cid] = (cid, sev, title)
    except Exception:
        pass
    return out


def cve_lookup_online(banner):
    """Query several CVE sources (CIRCL + NVD + vulners), combine and de-duplicate."""
    product, version = identify(banner)
    if not product or not version:
        return []
    cache_key = f"{product} {version}"
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]
    combined = {}
    combined.update(_query_nvd(product, version))       # official (keyword, up to 50)
    combined.update(_query_vulners(product, version))   # comprehensive — needs a key
    result = sorted(combined.values(), key=lambda x: x[0])
    _CVE_CACHE[cache_key] = result
    return result


def cve_lookup(banner):
    """Hybrid: use the live NVD API when online, fall back to the offline DB."""
    if not banner:
        return []
    if not _FORCE_OFFLINE and _has_internet():     # internet available -> API
        online = cve_lookup_online(banner)
        if online:
            return online
        return cve_lookup_offline(banner)          # API found nothing -> try local
    return cve_lookup_offline(banner)              # no internet -> offline DB


def _clean_banner(raw):
    """Keep the first line, and (for HTTP) also the Server: header where the
    software version lives — so CVE matching can see 'Apache/2.2.8' etc."""
    lines = [l.strip() for l in raw.splitlines() if l.strip()]
    if not lines:
        return ""
    first = lines[0]
    server = next((l for l in lines if l.lower().startswith("server:")), "")
    return f"{first}  {server}".strip() if server else first


def grab_banner(sock, port, target):
    try:
        # HTTP-like services don't speak first, so send a tiny request first
        if port in HTTP_LIKE_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
        data = sock.recv(1024)                      # read the service's reply
        return _clean_banner(data.decode(errors="ignore"))
    except Exception:
        return ""                                   # no banner -> quietly empty


def _bump_progress():
    global _scanned
    with _COUNT_LOCK:
        _scanned += 1
        if _total and _scanned % 200 == 0:
            pct = _scanned * 100 // _total
            with _PRINT_LOCK:
                print(c(f"\r[*] Scanning: {_scanned}/{_total} ({pct}%)",
                        Fore.CYAN), end="", flush=True)


# =============================================================
#  Host discovery — TCP ping (no ICMP, no admin needed)
# =============================================================
def is_host_up(ip, timeout=0.5):
    """Knock on a few common ports — a clear reply means the host is alive.
    (open or 'connection refused' = up; timeout/unreachable = try next port)"""
    # 'refused' means the host exists, the port is just closed -> alive.
    # (Linux errno 111 / Windows 10061)
    REFUSED = {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", 10061)}
    for port in (80, 443, 22, 445, 3389):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            rc = s.connect_ex((ip, port))
            if rc == 0 or rc in REFUSED:     # open, or refused -> both mean "up"
                return True
            # any other errno (unreachable/timeout code) -> undecided, try next
        except socket.timeout:
            continue
        except socket.error:
            continue
        finally:
            s.close()
    return False                             # no clear reply on any port -> down


# =============================================================
#  Scan one port — TCP (thread engine)
# =============================================================
def scan_tcp(ip, port, timeout, want_banner, want_cve, verbose):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # IPv4, TCP
    sock.settimeout(timeout)
    result = None
    try:
        if sock.connect_ex((ip, port)) == 0:     # knock — 0 means open
            banner = grab_banner(sock, port, ip) if want_banner else ""
            cves = cve_lookup(banner) if want_cve else []
            result = {"host": ip, "port": port, "proto": "tcp",
                      "service": get_service(port), "banner": banner, "cves": cves}
            if verbose:
                _print_hit(result)
    except socket.error:
        pass                                     # DNS/socket issue — skip this port
    finally:
        sock.close()                             # always release the connection
        _bump_progress()
    return result


# --- UDP scan (basic — a reply means open, else open|filtered) ---
def scan_udp(ip, port, timeout, verbose):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    result = None
    try:
        sock.sendto(b"\x00", (ip, port))         # send an empty packet
        data, _ = sock.recvfrom(1024)            # a reply confirms it's open
        result = {"host": ip, "port": port, "proto": "udp",
                  "service": get_service(port),
                  "banner": data.decode(errors="ignore").strip()[:80], "cves": []}
        if verbose:
            _print_hit(result)
    except socket.timeout:
        pass   # no reply -> in UDP this is open|filtered, can't be sure, so skip
    except socket.error:
        pass
    finally:
        sock.close()
    return result


def _print_hit(r):
    tag = c("[+]", Fore.GREEN)
    port = c(f"{r['port']:<6}", Fore.GREEN)
    svc = c(f"{r['service']:<12}", Fore.YELLOW)
    line = f"{tag} {r['host']:<15} {port} {r['proto']} {svc} {r['banner']}"
    if r.get("cves"):
        ids = ", ".join(x[0] for x in r["cves"])
        line += c(f"  ! {ids}", Fore.RED)
    with _PRINT_LOCK:
        print("\r" + line.rstrip())


# =============================================================
#  Engine 1: threads
# =============================================================
def run_thread_engine(targets, ports, args):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = []
        for ip in targets:
            for port in ports:
                futs.append(pool.submit(scan_tcp, ip, port, args.timeout,
                                        not args.no_banner, args.cve, args.verbose))
                if args.udp:
                    futs.append(pool.submit(scan_udp, ip, port, args.timeout, args.verbose))
        for f in concurrent.futures.as_completed(futs):
            r = f.result()
            if r:
                results.append(r)
    return results


# =============================================================
#  Engine 2: asyncio  (same job, done with async/await)
# =============================================================
async def _scan_tcp_async(ip, port, timeout, want_banner, want_cve, sem, verbose):
    async with sem:                      # cap concurrency with a semaphore
        try:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        except (asyncio.TimeoutError, OSError):
            _bump_progress()
            return None
        banner = ""
        if want_banner:
            try:
                if port in HTTP_LIKE_PORTS:
                    writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                banner = _clean_banner(data.decode(errors="ignore"))
            except Exception:
                banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        result = {"host": ip, "port": port, "proto": "tcp",
                  "service": get_service(port), "banner": banner,
                  "cves": cve_lookup(banner) if want_cve else []}
        if verbose:
            _print_hit(result)
        _bump_progress()
        return result


async def _async_main(targets, ports, args):
    sem = asyncio.Semaphore(args.threads)
    tasks = [
        _scan_tcp_async(ip, port, args.timeout, not args.no_banner,
                        args.cve, sem, args.verbose)
        for ip in targets for port in ports
    ]
    done = await asyncio.gather(*tasks)
    return [r for r in done if r]


def run_async_engine(targets, ports, args):
    return asyncio.run(_async_main(targets, ports, args))


# =============================================================
#  Engine 3: SYN scan (scapy + admin) — optional, stealthy
# =============================================================
def run_syn_engine(targets, ports, args):
    try:
        from scapy.all import IP, TCP, sr1, conf
        conf.verb = 0
    except ImportError:
        print(c("[!] SYN scan needs scapy:  pip install scapy", Fore.RED))
        print(c("    (Windows needs Npcap, and you must run as admin/root)", Fore.RED))
        return []
    results = []
    for ip in targets:
        for port in ports:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")      # SYN only
            resp = sr1(pkt, timeout=args.timeout)
            if resp and resp.haslayer(TCP) and resp[TCP].flags == 0x12:  # SYN-ACK
                results.append({"host": ip, "port": port, "proto": "tcp(syn)",
                                "service": get_service(port), "banner": "", "cves": []})
                if args.verbose:
                    _print_hit(results[-1])
                sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.2)  # polite close
            _bump_progress()
    return results


# =============================================================
#  Reports / export
# =============================================================
def save_results(results, path):
    rows = [{"host": r["host"], "port": r["port"], "proto": r["proto"],
             "service": r["service"], "banner": r["banner"],
             "cves": ";".join(x[0] for x in r["cves"])} for r in results]
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump(rows, f, indent=2)
    elif path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["host", "port", "proto", "service", "banner", "cves"])
            w.writeheader()
            w.writerows(rows)
    else:
        print(c("[!] Only .json / .csv supported — not saved.", Fore.RED))
        return
    print(c(f"[*] Saved: {path}", Fore.CYAN))


_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
_SEV_COLOR = {"Critical": "#ff5c5c", "High": "#ff9b4d",
              "Medium": "#ffd24d", "Low": "#7fd1ff", "Unknown": "#9aa"}


def save_html(results, meta, path):
    def nvd_link(cid):
        s = html.escape(cid)
        return f'<a href="https://nvd.nist.gov/vuln/detail/{s}" target="_blank">{s}</a>'

    summary_rows, detail_blocks = "", ""
    for r in sorted(results, key=lambda x: (x["host"], x["port"])):
        cves = sorted(r["cves"], key=lambda c: (_SEV_RANK.get(c[1], 4), c[0]))
        banner = html.escape(r["banner"][:90] + ("…" if len(r["banner"]) > 90 else ""))
        counts = {}
        for _, sev, _ in cves:
            counts[sev] = counts.get(sev, 0) + 1
        badges = " ".join(
            f'<span class="badge" style="background:{_SEV_COLOR.get(s,"#9aa")}">{counts[s]} {s}</span>'
            for s in ("Critical", "High", "Medium", "Low", "Unknown") if counts.get(s))
        cve_cell = f'<b>{len(cves)}</b> CVEs &nbsp; {badges}' if cves else '<span class="ok">none</span>'
        cls = ' class="vuln"' if cves else ""
        summary_rows += (f"<tr{cls}><td>{html.escape(r['host'])}</td><td>{r['port']}</td>"
                         f"<td>{html.escape(r['service'])}</td><td class='ban'>{banner}</td>"
                         f"<td>{cve_cell}</td></tr>\n")
        if cves:
            groups = ""
            for sev in ("Critical", "High", "Medium", "Low", "Unknown"):
                g = [c for c in cves if c[1] == sev]
                if not g:
                    continue
                chips = " ".join(nvd_link(cid) for cid, _, _ in g)
                groups += (f'<div class="grp"><span class="sev" style="color:{_SEV_COLOR[sev]}">'
                           f'{sev} ({len(g)})</span><div class="chips">{chips}</div></div>')
            detail_blocks += (f'<section><h3>{html.escape(r["host"])}:{r["port"]} '
                              f'<small>{html.escape(r["service"])} — {banner}</small></h3>{groups}</section>')

    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>Port Scan Report — {html.escape(meta['target'])}</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;margin:2rem;background:#0f1115;color:#e6e6e6}}
 h1{{color:#ff5c5c;margin-bottom:.2rem}} h3{{margin:1.4rem 0 .5rem;border-bottom:1px solid #2a2f3a;padding-bottom:.3rem}}
 h3 small{{color:#9aa;font-weight:normal;font-size:13px}}
 .meta{{color:#9aa;font-size:14px}} table{{border-collapse:collapse;width:100%;margin-top:1rem}}
 th,td{{border:1px solid #2a2f3a;padding:.5rem .7rem;text-align:left;font-size:14px;vertical-align:top}}
 th{{background:#1a1e26}} tr:nth-child(even){{background:#141821}}
 tr.vuln td:first-child{{color:#ff9b9b}}
 td.ban{{font-family:monospace;font-size:12px;color:#9ad}}
 .badge{{display:inline-block;color:#111;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600;margin:1px}}
 .ok{{color:#5fd38d}}
 section{{margin-top:1rem}} .grp{{margin:.5rem 0}}
 .sev{{font-weight:700;display:inline-block;min-width:110px;vertical-align:top}}
 .chips{{display:inline-block;line-height:1.9}}
 .chips a{{color:#cfe;text-decoration:none;background:#1a1e26;border:1px solid #2a2f3a;border-radius:4px;padding:1px 6px;margin:2px;font-size:12px;display:inline-block}}
 .chips a:hover{{background:#243b2e}}
</style></head><body>
<h1>Port Scan Report</h1>
<p class="meta">Target: <b>{html.escape(meta['target'])}</b> &nbsp;|&nbsp; Ports scanned: {meta['nports']}
 &nbsp;|&nbsp; engine: {meta['engine']} &nbsp;|&nbsp; time: {meta['elapsed']:.2f}s &nbsp;|&nbsp; {meta['when']}</p>
<p class="meta">Open ports: <b>{len(results)}</b></p>

<h3>Summary</h3>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th><th>Vulnerabilities</th></tr>
{summary_rows}</table>

<h3 style="color:#ff5c5c">Vulnerability details</h3>
{detail_blocks or '<p class="meta">No CVEs found.</p>'}

<p class="meta" style="margin-top:2rem">Generated by Code-Red port_scanner.py — authorized testing only.</p>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    print(c(f"[*] HTML report: {path}", Fore.CYAN))


def save_detection(meta, path):
    """Generate Suricata + Wazuh rules that detect this scan (blue-team companion)."""
    suricata = (
        'alert tcp any any -> $HOME_NET any (msg:"Code-Red PortScan: '
        'many TCP connections from single source"; flow:to_server; '
        'threshold:type both, track by_src, count 30, seconds 10; '
        'classtype:attempted-recon; sid:9000001; rev:1;)'
    )
    wazuh = """<!-- Wazuh custom rule: host port-scan detection (ossec-style) -->
<group name="recon,portscan,">
  <rule id="100201" level="10" frequency="30" timeframe="10">
    <if_matched_sid>5710</if_matched_sid>   <!-- repeated connection attempts -->
    <same_source_ip />
    <description>Possible port scan: 30+ connection attempts from same source in 10s</description>
    <mitre><id>T1046</id></mitre>
  </rule>
</group>"""
    text = f"""# ============================================================
#  Detection Companion  —  Code-Red port_scanner.py
#  Target: {meta['target']}   |   {meta['when']}
#
#  What a connect scan leaves on the target: many full TCP
#  handshakes from one source to many ports in a short window.
#  The two rules below detect exactly that.
#  MITRE ATT&CK: T1046 (Network Service Discovery)
# ============================================================

## Suricata (IDS) rule
{suricata}

## Wazuh (SIEM) rule
{wazuh}

# Note: tune the threshold (30 / 10s) to your environment.
# This file can be linked to the matching detection in Code-Blue.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(c(f"[*] Detection rules: {path}", Fore.CYAN))


# =============================================================
#  main
# =============================================================
def main():
    global _total, _USE_COLOR, _FORCE_OFFLINE, _NVD_KEY, _VULNERS_KEY

    p = argparse.ArgumentParser(
        description="Advanced TCP/UDP port scanner (Code-Red / Foundations)",
        epilog="Run only against authorized targets.")
    p.add_argument("target", help="IP / hostname / CIDR / comma-list (192.168.1.0/24)")
    p.add_argument("-p", "--ports", default="1-1024", help="22,80 or 1-1000 (default 1-1024)")
    p.add_argument("--top", type=int, metavar="N", help="scan only the top N common ports")
    p.add_argument("-T", "--threads", type=int, default=200, help="concurrency (default 200)")
    p.add_argument("--timeout", type=float, default=0.5, help="per-port timeout in seconds (default 0.5)")
    p.add_argument("--engine", choices=["thread", "async", "syn"], default="thread",
                   help="scan engine (default thread; syn = scapy+admin)")
    p.add_argument("--udp", action="store_true", help="also scan UDP alongside TCP")
    p.add_argument("--discover", action="store_true", help="host discovery first, skip dead hosts")
    p.add_argument("--cve", action="store_true", help="look up CVEs from banners (online if internet, else offline DB)")
    p.add_argument("--cve-offline", action="store_true", help="force the offline CVE DB (skip the internet check)")
    p.add_argument("--nvd-key", metavar="KEY", help="NVD API key for a higher online rate limit")
    p.add_argument("--vulners-key", metavar="KEY", help="vulners.com API key (adds the source nmap uses)")
    p.add_argument("--no-banner", action="store_true", help="disable banner grabbing")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-o", "--output", help="results.json or results.csv")
    p.add_argument("--html", metavar="FILE", help="write an HTML report")
    p.add_argument("--detection", metavar="FILE", help="write Suricata+Wazuh rules")
    p.add_argument("-v", "--verbose", action="store_true", help="print each hit as it is found")
    args = p.parse_args()

    _USE_COLOR = not args.no_color
    _FORCE_OFFLINE = args.cve_offline
    # Keys: use the flag if given, else fall back to an environment variable.
    # This keeps the key OUT of the code/repo — set it once with:
    #   Windows:  setx VULNERS_API_KEY "<key>"
    #   Linux:    export VULNERS_API_KEY="<key>"
    # Key lookup order: command-line flag -> environment variable -> local key file.
    _NVD_KEY = args.nvd_key or os.environ.get("NVD_API_KEY") or _read_key_file("nvd_key.txt")
    _VULNERS_KEY = (args.vulners_key or os.environ.get("VULNERS_API_KEY")
                    or _read_key_file("vulners_key.txt"))

    # Tell the user which CVE source will be used
    if args.cve:
        if args.cve_offline:
            print(c("[*] CVE source: offline DB (forced)", Fore.CYAN))
        elif _has_internet():
            srcs = "NVD" + (" + vulners" if _VULNERS_KEY else "")
            print(c(f"[*] CVE source: online APIs ({srcs})", Fore.CYAN))
        else:
            print(c("[*] CVE source: offline DB (no internet)", Fore.CYAN))

    # Decide the ports
    ports = TOP_PORTS[:args.top] if args.top else parse_ports(args.ports)

    # Expand targets (CIDR/list)
    targets = expand_targets(args.target)
    if not targets:
        print(c("[!] No valid targets.", Fore.RED))
        sys.exit(1)

    # Host discovery
    if args.discover and len(targets) > 1:
        print(c(f"[*] Host discovery: checking {len(targets)} hosts...", Fore.CYAN))
        alive = [ip for ip in targets if is_host_up(ip, args.timeout)]
        print(c(f"[*] Alive hosts: {len(alive)}/{len(targets)}", Fore.CYAN))
        targets = alive
        if not targets:
            print(c("[!] No hosts are up.", Fore.RED))
            sys.exit(0)

    _total = len(targets) * len(ports) * (2 if args.udp else 1)

    print(c("\n+==========================================+", Fore.RED))
    print(c("|   Code-Red  -  Port Scanner  v6          |", Fore.RED))
    print(c("+==========================================+", Fore.RED))
    print(f"[*] Target : {args.target}  ({len(targets)} host[s])")
    print(f"[*] Ports  : {len(ports)}  |  engine: {args.engine}  |  threads: {args.threads}")
    print(f"[*] Start  : {datetime.now():%H:%M:%S}\n")

    start = time.time()
    if args.engine == "async":
        results = run_async_engine(targets, ports, args)
    elif args.engine == "syn":
        results = run_syn_engine(targets, ports, args)
    else:
        results = run_thread_engine(targets, ports, args)
    elapsed = time.time() - start

    # Results table
    results.sort(key=lambda r: (r["host"], r["port"]))
    print("\r" + " " * 50 + "\r", end="")   # clear the progress line
    print(c("\n" + "=" * 60, Fore.RED))
    if results:
        print(f"{'HOST':<16}{'PORT':<7}{'PROTO':<6}{'SERVICE':<13}BANNER")
        print("-" * 60)
        for r in results:
            banner = r["banner"][:60] + ("…" if len(r["banner"]) > 60 else "")
            line = (f"{r['host']:<16}{r['port']:<7}{r['proto']:<6}"
                    f"{r['service']:<13}{banner}")
            print(line)
            if r["cves"]:
                # one tidy severity summary line, not hundreds of CVE lines
                counts = {}
                for _, sev, _ in r["cves"]:
                    counts[sev] = counts.get(sev, 0) + 1
                parts = [f"{counts[s]} {s}" for s in ("Critical", "High", "Medium", "Low", "Unknown")
                         if counts.get(s)]
                print(c(f"    ! {len(r['cves'])} CVEs ({', '.join(parts)})"
                        f" — see HTML report for the list", Fore.RED))
    else:
        print("No open ports found.")
    print(c("=" * 60, Fore.RED))

    vuln = sum(1 for r in results if r["cves"])
    print(f"[*] {len(results)} open port(s)" +
          (c(f"  |  {vuln} with possible CVEs", Fore.RED) if vuln else "") +
          f"  |  time {elapsed:.2f}s")

    # Export
    meta = {"target": args.target, "nports": len(ports), "engine": args.engine,
            "elapsed": elapsed, "when": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    if args.output and results:
        save_results(results, args.output)
    if args.html:
        save_html(results, meta, args.html)
    if args.detection:
        save_detection(meta, args.detection)


if __name__ == "__main__":
    main()
