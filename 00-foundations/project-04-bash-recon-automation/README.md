# Project 04 — Bash Scripting for Recon Automation

> **Status:** 🟡 In progress
> Part of [00 - Foundations](../README.md) — Code-Red, Red Team Operations.

A **recon playbook**: a set of small Bash scripts that chain existing tools into
a repeatable reconnaissance workflow — host discovery → port scanning → service
enumeration → organized output. The engine work (scanning, fingerprinting, CVE
lookup) was already built in
[**Project 03 — Port Scanner**](../project-03-port-scanner), which is complete;
this project is about **Bash orchestration**, not rebuilding a scanner.

---

## How this differs from Project 03

Project 03 built a scanning **tool** in Python. Project 04 is about the **Bash
workflow** that drives recon end-to-end and glues several tools together —
including Project 03's own `port_scanner.py` as one stage.

| | Project 03 | Project 04 (this) |
|---|---|---|
| Skill | Python — build one tool | **Bash** — orchestrate many tools |
| Output | a scanner | a repeatable **recon pipeline** |
| Focus | sockets, threading, CVE lookup | loops, pipes, `awk`/`sed`/`grep`, argument parsing, `cron` |
| Reuses | — | **Project 03's `port_scanner.py`** as the scan stage |

---

## Objective

- Automate the repetitive early phase of an engagement with Bash.
- Chain tools so each stage's output feeds the next (host list → port scan →
  service enumeration → report).
- Produce **clean, greppable** output and a tidy per-target folder structure.
- Add a short **Detection** note for each phase (blue-team view, links to
  [Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue)).

---

## The recon playbook

Reconnaissance here is split into clear phases. Each phase is a small script; a
master script (`recon.sh`) runs them in order and organizes the output.

```
            ┌─────────────────────────────────────────────┐
  target →  │  Phase 1  Host discovery   (who is alive?)   │
            │  Phase 2  Port scan        (what's open?)    │
            │  Phase 3  Service enum      (what's running?)│
            │  Phase 4  Loot / parse      (organize it)    │
            └─────────────────────────────────────────────┘
                              │
                     results/<target>/   (greppable files)
```

### Phase 1 — Host discovery

*Which hosts are alive?* A ping/ARP sweep across the subnet, then extract just
the live IPs into a file the next phase reads.

```bash
# live-hosts.sh — discover live hosts on a /24 and save clean IPs
subnet="$1"                                   # e.g. 192.168.100.0/24
nmap -sn "$subnet" -oG - \
  | awk '/Up$/{print $2}' \
  | sort -u > live_hosts.txt
echo "[*] $(wc -l < live_hosts.txt) live hosts -> live_hosts.txt"
```

> **Detection:** a sweep is many ICMP/ARP requests from one source in seconds —
> visible as a burst of `Echo Request` or ARP traffic. Maps to MITRE **T1018**
> (Remote System Discovery).

### Phase 2 — Port scan

*What ports are open?* Loop over the live hosts and scan each. This stage can use
`nmap` **or Project 03's own scanner** — showing the two projects connect.

```bash
# port-scan.sh — scan every live host
while read -r ip; do
    echo "[*] Scanning $ip"
    # option A: nmap
    nmap -p- --min-rate 1000 -oN "results/$ip/ports.txt" "$ip"
    # option B: my own tool from Project 03
    # python3 ../project-03-port-scanner/port_scanner.py "$ip" -p 1-10000 \
    #     -o "results/$ip/ports.json"
done < live_hosts.txt
```

> **Detection:** many full TCP handshakes from one source to many ports in a
> short window — MITRE **T1046** (Network Service Discovery). The Suricata/Wazuh
> rules from Project 03 fire here too.

### Phase 3 — Service / version enumeration

*What software is running?* For the open ports, grab versions and banners.

```bash
# enum-services.sh — pull open ports from phase 2 and enumerate them
while read -r ip; do
    open_ports=$(grep -oP '^\d+(?=/tcp\s+open)' "results/$ip/ports.txt" | paste -sd,)
    [ -z "$open_ports" ] && continue
    nmap -sV -p "$open_ports" -oN "results/$ip/services.txt" "$ip"
done < live_hosts.txt
```

> **Detection:** version probes send crafted requests to each service — a slower
> but more distinctive pattern than a plain port sweep.

### Phase 4 — Loot / parse

*Organize it.* Pull the interesting lines into one greppable summary.

```bash
# summarize.sh — one clean summary across all targets
{
  echo "host,port,service,version"
  for dir in results/*/; do
    ip=$(basename "$dir")
    awk -v ip="$ip" '/open/{print ip","$1","$3","substr($0, index($0,$4))}' \
        "$dir/services.txt"
  done
} > recon_summary.csv
echo "[*] Summary -> recon_summary.csv"
```

---

## Orchestration — `recon.sh`

The master script ties the phases together and builds the folder structure.
See [`scripts/recon.sh`](./scripts/recon.sh).

```bash
./recon.sh 192.168.100.0/24
# →  results/<ip>/ports.txt, services.txt   +   recon_summary.csv
```

### Output structure

```
results/
├── 192.168.100.10/
│   ├── ports.txt
│   └── services.txt
├── 192.168.100.20/
│   └── ...
└── recon_summary.csv        ← one greppable file across all hosts
```

---

## Bash concepts practiced

The point of the project — the skills Project 03 did **not** cover:

- variables, `"$1"` positional args, `while read` loops
- pipes and redirection (`|`, `>`, `>>`), process substitution
- text processing: `awk`, `sed`, `grep -oP`, `sort -u`, `paste`
- functions, exit codes, simple error handling
- scheduling a recurring recon with `cron`

---

## Legal / ethics

All scripting is run against hosts I own or isolated lab targets I control
(e.g. the Kali + Metasploitable lab from
[Project 01](../project-01-home-lab-setup)). No unauthorized targets.

---

**Author:** Rakibul Hoque Chowdhury ([@rakibulhcrafat07](https://github.com/rakibulhcrafat07))
