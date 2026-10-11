# Project 03 — Port Scanner (from raw sockets)

> **Status:** ✅ Done
> Part of [00 - Foundations](../README.md) — Code-Red, Red Team Operations.

A multithreaded TCP/UDP port scanner built from **raw sockets** using only the
Python standard library — no `nmap`, no external packages for the core engine.
It fingerprints the software behind each open port, looks up known CVEs from
several sources (offline **or** live), and produces a clean, organized report.

The point of the project was **not** to replace `nmap`, but to understand what a
scanner actually does under the hood — and to build a tool whose software
detection is on par with `nmap`, with a CVE pipeline I wrote myself.

---

## Objective

- Understand the TCP connect scan, banner grabbing and service/version
  identification by building them from scratch.
- Turn a raw banner (`220 (vsFTPd 2.3.4)`) into a precise
  `(product, version)` — my own fingerprint engine.
- Match that version against CVEs, offline for isolated labs and online
  (NVD + vulners) when internet is available.
- Add a **blue-team** companion: generate detection rules for the very scan the
  tool performs.

---

## Development journey (v1 → v6)

This tool grew one question at a time. Each version came from a real limitation.

| Version | The question that drove it | What was added |
|:--:|---|---|
| **v1** | "`nmap` exists — but what happens *inside* a scanner?" | TCP connect scan, threading, banner grabbing, service name (thread-safe `getservbyport`), CSV/JSON export, CLI flags |
| **v2** | "One port, one host isn't enough — make it a real tool." | CIDR / multi-target, top-ports mode, color, progress, host discovery, UDP scan, async engine, SYN scan, first CVE lookup, Suricata + Wazuh detection rules |
| **v3** | "Prepare it for GitHub; the CVE list is tiny." | Full English rewrite, offline CVE DB 7 → 13, live NVD fallback, fix so the HTTP `Server:` header (and thus the version) is captured |
| **v4** | "The real challenge is identifying the software from the banner." | My own **fingerprint engine** (`banner → product + version`) and **version-range** CVE matching (`<=7.6`, `2.2.*`, `4.80-4.91`) |
| **v5** | "One source isn't enough, and the internet check was wrong." | **Multi-source** CVE lookup (NVD by CPE `virtualMatchString` + vulners.com), fixed internet detection, API keys read from a file / env var so they never land in the repo |
| **v6** | "Hundreds of CVEs on one line is unreadable." | **Organized HTML report** — grouped by severity, counted, color-coded, each CVE a clickable NVD link; tidy terminal summary |

**The `getservbyport` bug (v1):** running the service lookup from many threads at
once occasionally returned garbage (a comment line from `/etc/services`). The
function wraps a non-reentrant C call, so two threads could read each other's
half-written result — a classic **race condition**. Fixed with a lock, with
common ports cached to avoid the lock on the fast path. The GIL protects Python
bytecode, not C-library calls.

---

## Features

- **TCP connect scan** (`connect_ex`) — the `nmap -sT` technique, no root needed
- **Three engines** — threaded (default), `asyncio`, and SYN (scapy + admin)
- **Multiple targets / CIDR** — `192.168.1.0/24`, comma lists, hostnames
- **Top-ports mode** — `--top 100`
- **Banner grabbing** + own **fingerprint engine** (`product` + `version`)
- **CVE lookup**
  - *Offline:* curated signature DB with version-range matching (works isolated)
  - *Online:* NVD (CPE version-range) + vulners.com — automatic when internet is up
- **Host discovery** — skip dead hosts (`--discover`)
- **UDP scan** (`--udp`)
- **Detection companion** — generate Suricata + Wazuh rules (MITRE **T1046**)
- **Reports** — organized HTML (severity groups + NVD links), CSV, JSON

---

## Lab setup

| Component | Detail |
|---|---|
| Attacker | Kali Linux (VirtualBox) — isolated internal network |
| Target | Metasploitable 2 — deliberately vulnerable services |
| Public test target | `scanme.nmap.org` (Nmap's authorized scan host) |

> The isolated lab has no internet, so there the tool uses the **offline** CVE
> DB. The online sources are used from internet-connected machines.

Kali on the internal lab network, with an `nmap` baseline against Metasploitable
for comparison:

[![Kali + nmap baseline](./screenshots/01-lab-kali-nmap.png)](./screenshots/01-lab-kali-nmap.png)

---

## Usage

```bash
# Basic scan
python port_scanner.py 192.168.100.10 -p 1-1024 -v

# Full scan with report + detection rules (offline CVE — good for the isolated lab)
python port_scanner.py 192.168.100.10 -p 1-10000 -T 50 --timeout 3 \
    --cve --cve-offline -v --html report.html -o results.json --detection rules.txt

# Online CVE (internet machine) — NVD is automatic, add vulners with a key
python port_scanner.py scanme.nmap.org -p 22,80 --cve \
    --vulners-key YOUR_VULNERS_API_KEY -v --html report.html

# Whole subnet, discover live hosts first
python port_scanner.py 192.168.100.0/24 --discover --top 100 -o results.csv
```

### Key options

| Flag | Purpose |
|---|---|
| `-p, --ports` | `22,80,443` or `1-1000` (default `1-1024`) |
| `--top N` | scan only the top N common ports |
| `-T, --threads` | concurrency (default 200) |
| `--engine` | `thread` (default), `async`, or `syn` |
| `--cve` | look up CVEs (online if internet, else offline DB) |
| `--cve-offline` | force the offline DB (skip the internet check) |
| `--udp` / `--discover` | add UDP scanning / host discovery |
| `-o`, `--html`, `--detection` | export CSV/JSON, HTML report, detection rules |

### API keys (kept out of the repo)

The scanner never stores keys in code. It reads them in this order:

1. the flag (`--vulners-key` / `--nvd-key`)
2. an environment variable (`VULNERS_API_KEY` / `NVD_API_KEY`)
3. a local file next to the script (`vulners_key.txt` / `nvd_key.txt`)

To run on any machine without typing the key, copy a `vulners_key.txt` next to
the script (see `vulners_key.txt.example`). **`.gitignore` excludes these files**,
so the key never reaches the public repo.

```bash
cp vulners_key.txt.example vulners_key.txt   # then paste your real key inside
```

> Optional dependencies: `pip install colorama` (color on Windows),
> `pip install scapy` (SYN scan, needs admin).

---

## How the CVE pipeline works

```
open port  →  grab banner  →  FINGERPRINTS: banner → (product, version)
                                   │
          offline ──────────────┐  │  ┌────────────── online
   CVE_DB + version-range match │  │  │  NVD (CPE virtualMatchString) + vulners
                                └──┴──┘
                         combine + de-duplicate → report
```

- **Fingerprint engine:** a small table of `(regex, product)` where the regex
  captures the version — e.g. `OpenSSH[_/ ]?([\d.]+) → openssh`. Grows as new
  services are met. This is what makes version detection comparable to `nmap`.
- **Version matching (offline):** `_ver_match()` handles exact, `<=`, ranges
  (`4.80-4.91`) and wildcards (`2.2.*`) without any external library.
- **Online (comprehensive):** NVD's `virtualMatchString` does server-side
  version-range matching (like `nmap`'s vulners), returning every CVE that
  affects the detected `product:version`.

---

## Execution & results

**Offline fingerprint CVE matching on Metasploitable** — the fingerprint engine
identifies the service and version from the banner, then the offline DB flags the
known-vulnerable ones (e.g. `vsFTPd 2.3.4 → CVE-2011-2523`, `OpenSSH 4.7 → CVE-2018-15473`):

[![Metasploitable CVE scan](./screenshots/02-metasploitable-cve.png)](./screenshots/02-metasploitable-cve.png)

**Organized HTML report** — open ports, services, banners and a per-port
vulnerability summary:

[![HTML report](./screenshots/03-html-report.png)](./screenshots/03-html-report.png)

**Online, multi-source CVE lookup** — against `scanme.nmap.org` with internet,
NVD (CPE `virtualMatchString`) + vulners return comprehensive, `nmap`-level
coverage for OpenSSH 6.6.1 and Apache 2.4.7:

[![Online comprehensive CVE](./screenshots/04-online-cve-comprehensive.png)](./screenshots/04-online-cve-comprehensive.png)

---

## Comparison with nmap

Validated against `scanme.nmap.org` (`nmap -sV -p 1-1000 --script vuln`):

| | This tool | nmap |
|---|---|---|
| Version detection | OpenSSH 6.6.1, Apache 2.4.7 | OpenSSH 6.6.1, Apache 2.4.7 |
| CVE coverage (online) | comprehensive via NVD CPE + vulners | comprehensive via vulners |
| CVE coverage (offline) | curated signature DB | n/a |

**Takeaway:** the fingerprint engine matches `nmap`'s version detection exactly.
The difference is only in the CVE **database** — `nmap`'s vulners pulls from a
huge online source (lots of coverage, lots of noise), while this tool offers a
precise curated offline DB *and* the same comprehensive online sources.

---

## Detection companion (blue team)

`--detection rules.txt` generates rules that detect this scan's footprint
(many TCP handshakes from one source in a short window), mapped to MITRE
**T1046 — Network Service Discovery**:

- a **Suricata** threshold rule
- a **Wazuh** correlation rule

This is the purple-team angle — attack, then detect your own attack — and links
back to the defensive work in [Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue).

---

## Lessons learned

- **Not every stdlib function is thread-safe** just because Python has a GIL —
  `getservbyport` taught that the hard way.
- **Port scanning is I/O-bound, not CPU-bound** — speed comes from concurrency
  (waiting in parallel), not from a faster CPU.
- **Finding the version is harder than listing CVEs** — a huge CVE DB is useless
  if you can't identify the software first.
- **Keyword search ≠ version matching** — switching NVD to CPE
  `virtualMatchString` turned a handful of CVEs into comprehensive coverage.
- **Keys never belong in a public repo** — file / env with `.gitignore`.

---

## Legal / ethics

This performs active, loggable network activity. Run **only** against:

- hosts you own,
- isolated lab/VM environments you control (e.g. Metasploitable), or
- targets with explicit written authorization (e.g. `scanme.nmap.org`).

Unauthorized scanning can be a criminal offense even without exploitation.

---

**Author:** Rakibul Hoque Chowdhury ([@rakibulhcrafat07](https://github.com/rakibulhcrafat07))
