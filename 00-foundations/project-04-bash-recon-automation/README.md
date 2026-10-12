# Project 04 — Bash Scripting for Recon Automation

> **Status:** ⬜ Planned (theory / methodology defined — implementation next)
> Part of [00 - Foundations](../README.md) — Code-Red, Red Team Operations.

The **theory and methodology** for automating the reconnaissance phase with Bash.
The scanning engine itself was already built in
[**Project 03 — Port Scanner**](../project-03-port-scanner) (complete); this
project is about the **Bash workflow** that drives recon end-to-end and chains
existing tools together — including Project 03's `port_scanner.py` as one stage.

This README documents the *concepts* first. The scripts are written against this
plan afterwards.

---

## How this differs from Project 03

| | Project 03 | Project 04 (this) |
|---|---|---|
| Skill learned | **Python** — build one tool | **Bash** — orchestrate many tools |
| Deliverable | a scanner | a repeatable **recon pipeline** |
| Focus | sockets, threading, CVE lookup | loops, pipes, `awk`/`sed`/`grep`, `cron` |
| Reuses | — | **Project 03's `port_scanner.py`** as the scan stage |

Project 03's scanner already does scanning well. The point here is **not** to
rebuild it, but to learn how an operator *glues tools into a workflow*.

---

## 1. What is reconnaissance?

Recon is the **first phase** of any engagement or audit — gathering information
about the target before doing anything else.

```
Which hosts exist?  →  Which ports are open?  →  What services run?  →  What versions?
```

That information decides where it is worth acting next. Better recon makes the
rest of the engagement easier.

## 2. Why automate it?

A 5-host lab can be done by hand. A real `/24` subnet is **254 hosts**, each with
up to 65,535 ports — by hand that is slow, error-prone, and endlessly repetitive.

Write the workflow once → run it on any target, in one command. The core value of
automation is being **repeatable, fast, and consistent**.

## 3. Why Bash (and not Python)?

The strength of Bash is not building new tools — it is **gluing existing tools
together**. Linux ships thousands of them (`nmap`, `dig`, `whois`, `curl`, …), and
Bash binds them into a pipeline where one tool's output becomes the next tool's
input. That gluing is an operator's day-to-day skill, and it is a different muscle
from the Python tool-building of Project 03.

## 4. The recon phases (methodology)

Recon is not random — it has an **order**, and each phase is the foundation for
the next.

| Phase | Question | Idea |
|---|---|---|
| **1. Host discovery** | *Who is alive?* | Don't scan 254 hosts blindly — find the live ones first, don't waste time on dead hosts |
| **2. Port scan** | *What is open?* | Scan only the live hosts (this is where Project 03's scanner plugs in) |
| **3. Service enumeration** | *What is running?* | For open ports, identify the service and version from the banner |
| **4. Parse & report** | *Organize it* | Turn raw, messy output into clean, searchable (greppable) files |

## 5. The core idea — chaining

This is the heart of automation: **one phase's output is the next phase's input.**

```
host discovery  →  live_hosts.txt
                        │  (the next phase reads this file)
                        ▼
port scan       →  open ports per host
                        │
                        ▼
service enum    →  service / version per port
```

Each phase is separate, but linked like a chain. This is *why* the output must be
**greppable** (clean, one fact per line) — so the next phase can read it reliably.

## 6. Bash concepts this project practices

The actual skills being learned here:

| Concept | Used for |
|---|---|
| variables & positional args (`$1`) | taking the target as input |
| loops (`while read`) | doing the same step for every host |
| pipes (`\|`) | passing one tool's output into another |
| redirection (`>`, `>>`) | saving results to files |
| text processing (`grep`, `awk`, `sed`) | extracting the useful parts from raw output |
| `cron` | running recon on a schedule |

## 7. Detection view (blue team)

Recon is not silent — it leaves a footprint on the target:

- **host discovery** → a burst of ICMP/ARP requests from one source → MITRE **T1018**
- **port scan** → many connections from one source to many ports → MITRE **T1046**

A good operator knows how their recon *looks*; a good defender knows how to *catch*
it. This ties back to the detection work in
[Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue).

---

## Planned implementation

Against the methodology above, the scripts will be built as small per-phase pieces
plus a master orchestrator:

```
scripts/
├── live-hosts.sh     # phase 1 — discover live hosts
├── port-scan.sh      # phase 2 — scan each live host (nmap or port_scanner.py)
├── enum-services.sh  # phase 3 — service / version enumeration
├── summarize.sh      # phase 4 — build one greppable summary
└── recon.sh          # orchestrator — runs the phases in order
```

Output lands in a per-target folder structure (`results/<ip>/…`) with one summary
file across all hosts.

---

## Legal / ethics

All scripting is run against hosts I own or isolated lab targets I control
(the Kali + Metasploitable lab from
[Project 01](../project-01-home-lab-setup)). No unauthorized targets.

---

**Author:** Rakibul Hoque Chowdhury ([@rakibulhcrafat07](https://github.com/rakibulhcrafat07))
