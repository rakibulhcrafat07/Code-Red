# Building a Simple Port Scanner — Notes

**Phase 1 — Project 3: Build a Simple Port Scanner**
Red Team Foundations | Self-study notes (not TryHackMe rooms)

---

## Table of Contents

1. Goal
2. How a TCP Connect Scan Works
3. Sockets in Python
4. Why Threading
5. Banner Grabbing
6. Service Name Lookup — and a Concurrency Bug
7. Open vs Closed vs Filtered
8. The Script
9. Usage
10. Legal / Ethics

---

## Goal

Build a working TCP port scanner from raw sockets — no `nmap`, no libraries beyond
the Python standard library — to actually understand what a scanner is doing
under the hood instead of just running someone else's tool.

**Scope delivered (Advanced tier):**
- Multithreaded TCP connect scan
- Configurable port ranges/lists, thread count, timeout
- Banner grabbing on open ports (protocol-aware for HTTP-ish ports)
- Common-port service name mapping + libc fallback
- CSV/JSON export
- Error handling for closed/filtered ports and DNS failures

---

## How a TCP Connect Scan Works

This is the same technique `nmap -sT` uses. It relies on the normal TCP
3-way handshake — no raw packet crafting, no root privileges required.

```
Client                          Server
  |------ SYN ------------------->|
  |<----- SYN-ACK -----------------|   (port open — completes the handshake)
  |------ ACK -------------------->|
  |------ RST -------------------->|   (we close it immediately, we don't need the session)
```

If the OS completes the handshake, the port is **open**. If it gets an
immediate `RST`, the port is **closed**. If nothing comes back at all within
the timeout, something (a firewall, usually) is silently dropping the
packets — the port is **filtered**.

The tradeoff vs. a raw SYN scan: connect scans are slower and noisier (a
full connection gets logged by the target), but they don't need raw socket
privileges, which makes them the right starting point for learning.

---

## Sockets in Python

The whole scanner sits on top of one call:

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # IPv4, TCP
sock.settimeout(1.0)
rc = sock.connect_ex((ip, port))
```

`connect_ex` is the key detail — a plain `sock.connect()` *raises an
exception* on failure, which is awkward to branch on. `connect_ex` instead
*returns an errno integer*: `0` means success (port open), anything else
means the OS refused or reset the connection (port closed). A timeout is
still raised as `socket.timeout` and has to be caught separately — that's
the "filtered" case.

---

## Why Threading

A single-threaded scan of 1,024 ports at ~1 second per port would take over
17 minutes, almost entirely spent waiting on the network (I/O-bound, not
CPU-bound). Python's GIL prevents true CPU parallelism, but it releases the
GIL during blocking I/O calls like `socket.connect()` — so threads are
still a big win here even though Python "isn't really parallel."

```python
with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
    futures = {pool.submit(scan_port, ip, port, timeout, banner): port for port in ports}
    for future in concurrent.futures.as_completed(futures):
        result = future.result()
```

`ThreadPoolExecutor` + `as_completed` is the pattern: submit every port as
its own job, then collect results as they finish rather than in submission
order. 100 threads brought a 1,024-port localhost scan down to a fraction
of a second in testing.

---

## Banner Grabbing

Once a port is open, the socket is still connected — so before closing it,
try to read whatever the service sends first (SSH and FTP banners are
usually sent unprompted), and for protocols that wait to be spoken to
first (HTTP), send a minimal probe:

```python
if port in HTTP_LIKE_PORTS:
    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
data = sock.recv(1024)
```

This is exactly why banner grabbing matters for recon: an open port alone
just tells you *something* is listening; the banner often tells you
**what** (`SSH-2.0-OpenSSH_9.6`, `Apache/2.4.58`) — which is what you'd
cross-reference against a CVE database next.

---

## Service Name Lookup — and a Concurrency Bug

`socket.getservbyport(port, "tcp")` maps a port number to its registered
service name (from `/etc/services` on Linux) — e.g. `22 -> ssh`.

**Bug found while testing:** calling `getservbyport` from many threads at
once occasionally returned garbage, like the literal string
`"# Local services\n"` (a comment line from `/etc/services`) for port 1.
The function wraps a C library call that isn't reentrant — on most
platforms it fills a static buffer, so two threads calling it at the same
instant can read each other's half-written result.

**Fix:** serialize access with a lock —

```python
_SERVICE_LOOKUP_LOCK = threading.Lock()

def service_name(port):
    if port in COMMON_PORTS:        # fast path, no lock needed
        return COMMON_PORTS[port]
    with _SERVICE_LOOKUP_LOCK:
        return socket.getservbyport(port, "tcp")
```

Verified with three repeated 1,024-port scans post-fix — zero corrupted
service names, versus reproducible corruption before. Worth remembering
generally: **not every stdlib function is thread-safe just because Python
has a GIL.** The GIL protects Python-level bytecode execution, not calls
that drop into non-reentrant C library code.

---

## Open vs Closed vs Filtered

| State | What happened | `connect_ex` behavior |
|-------|----------------|------------------------|
| Open | Handshake completed | Returns `0` |
| Closed | Target sent RST (nothing listening) | Returns non-zero errno (e.g. `ECONNREFUSED`) |
| Filtered | No response before timeout (firewall drop) | Raises `socket.timeout` |

A connect scan genuinely can't fully distinguish "filtered by a firewall"
from "just a slow/lossy network" — a SYN scan with ICMP unreachable
detection does better here, which is one reason tools like `nmap` support
multiple scan types.

---

## The Script

`port_scanner.py` — CLI structure:

| Flag | Purpose | Default |
|------|---------|---------|
| `target` (positional) | Hostname or IP | required |
| `-p / --ports` | Port spec: `22,80,443` or `1-1000` or mixed | `1-1024` |
| `-T / --threads` | Worker thread count | `100` |
| `--timeout` | Per-connection timeout (seconds) | `1.0` |
| `--no-banner` | Disable banner grabbing | banner on |
| `-o / --output` | Write results to `.json` or `.csv` | none |
| `-v / --verbose` | Print each result as it completes | off |

Core flow: `parse_ports()` → resolve target via `socket.gethostbyname()` →
fan out `scan_port()` across the thread pool → sort results by port number
→ print an open-ports table → optionally export.

> The script itself lives in [`../../tools/port_scanner.py`](../../tools/port_scanner.py).

---

## Usage

```bash
# Basic scan of common ports
python3 port_scanner.py 192.168.1.10

# Custom range, more threads, tighter timeout
python3 port_scanner.py scanme.nmap.org -p 1-1000 -T 200 --timeout 0.75

# Specific ports + mixed ranges, export to JSON
python3 port_scanner.py 10.0.0.5 -p 22,80,443,8000-8100 -o results.json

# Verbose mode, CSV export
python3 port_scanner.py 10.0.0.5 -p 1-1024 -o results.csv -v
```

**Tested against:** a local `python3 -m http.server` on `127.0.0.1:8000` —
correctly identified it as `open`, service `http-alt`, and grabbed the
`HTTP/1.0 200 OK` banner via the HEAD-request probe. Unused ports in the
1–1024 range correctly reported as `closed`.

---

## Legal / Ethics

Connect scans complete a full TCP handshake against the target — this is
active, loggable network activity. Only run this against:
- Hosts you own,
- Lab/VM environments you control (e.g. a local Docker/VM target),
- Or hosts with **explicit written authorization** (e.g. `scanme.nmap.org`,
  which Nmap's project explicitly permits scanning).

Scanning systems without authorization can be a criminal offense (CFAA in
the US, Computer Misuse Act in the UK, and equivalents elsewhere) even when
no exploitation follows — the scan itself is the violation in many
jurisdictions.

---

## Status

Phase 1 — Project 3 (Build a Simple Port Scanner): **complete.**
Threaded TCP connect scanner built, tested locally (open/closed states,
banner grabbing, CSV/JSON export), and one real concurrency bug found and
fixed during testing (`getservbyport` thread-safety).

*Next: Project 4 — TBD*
