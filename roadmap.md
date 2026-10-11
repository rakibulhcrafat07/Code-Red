# Code-Red — Red Team Operations Roadmap

A deep, project-by-project portfolio organized along the full attack lifecycle — from reconnaissance and initial access through payload development, post-exploitation, adversary emulation, and the engagement methodology that turns a collection of exploits into an actual *operation*. Each project is self-contained with its own write-up and a **Detection** section tying it back to the blue-team side ([Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue)).

Status legend: ✅ Done · 🟡 In progress · ⬜ Planned · 🔒 Reserved

**Totals:** 10 active sections · 64 projects (+ Cloud Red Teaming reserved)

---

## 00 — Foundations

Networking, OS, scripting, and first self-built tooling — the groundwork everything else stands on.

| # | Project | Status |
|---|---|---|
| 1 | [Home Lab Setup](./00-foundations/project-01-home-lab-setup) | ✅ Done |
| 2 | [Networking & Linux Fundamentals](./00-foundations/project-02-networking-linux) | ✅ Done |
| 3 | [Simple Port Scanner (from raw sockets)](./00-foundations/project-03-port-scanner) | ✅ Done |
| 4 | First CTF Write-ups | ⬜ Planned |
| 5 | Bash scripting for recon automation | ⬜ Planned |
| 6 | Python for offensive tooling (sockets, requests, argparse) | ⬜ Planned |
| 7 | Windows internals & PowerShell fundamentals | ⬜ Planned |

## 01 — Recon & OSINT

Finding and mapping the target before touching it.

| # | Project | Status |
|---|---|---|
| 1 | Passive recon & OSINT profile | ⬜ Planned |
| 2 | DNS enumeration & subdomain discovery | ⬜ Planned |
| 3 | Active service fingerprinting (Nmap deep-dive) | ⬜ Planned |
| 4 | Email & employee harvesting (theHarvester, LinkedIn) | ⬜ Planned |
| 5 | Metadata & document analysis | ⬜ Planned |
| 6 | Cloud asset discovery (buckets, exposed services) | ⬜ Planned |
| 7 | Attack-surface map of a lab target | ⬜ Planned |

## 02 — Initial Access & Social Engineering

How an operator actually gets the first foothold — the entry point real engagements start from. **Lab / authorized targets only.**

| # | Project | Status |
|---|---|---|
| 1 | Phishing infrastructure setup (domains, mail, in isolated lab) | ⬜ Planned |
| 2 | Credential-harvesting phishing page (lab) | ⬜ Planned |
| 3 | Malicious document / macro payload delivery | ⬜ Planned |
| 4 | Pretexting & OSINT-driven lure design | ⬜ Planned |
| 5 | Payload delivery & establishing the foothold | ⬜ Planned |
| 6 | Detection: phishing & initial-access telemetry | ⬜ Planned |

## 03 — Web App Exploitation

OWASP-style attacks against intentionally vulnerable apps in the lab.

| # | Project | Status |
|---|---|---|
| 1 | SQL injection (manual + sqlmap) | ⬜ Planned |
| 2 | Command / OS injection | ⬜ Planned |
| 3 | Cross-site scripting (reflected, stored, DOM) | ⬜ Planned |
| 4 | Broken authentication & session handling | ⬜ Planned |
| 5 | Access control & IDOR | ⬜ Planned |
| 6 | File upload to RCE | ⬜ Planned |
| 7 | SSRF chain | ⬜ Planned |
| 8 | Insecure deserialization | ⬜ Planned |
| 9 | API security testing (Burp Suite workflow) | ⬜ Planned |

## 04 — Network & Active Directory

Internal network attack paths and AD tradecraft in a lab domain.

| # | Project | Status |
|---|---|---|
| 1 | Internal enumeration & network pivoting | ⬜ Planned |
| 2 | SMB / relay attacks | ⬜ Planned |
| 3 | AD recon & BloodHound path mapping | ⬜ Planned |
| 4 | Kerberoasting | ⬜ Planned |
| 5 | AS-REP roasting | ⬜ Planned |
| 6 | Pass-the-Hash / Pass-the-Ticket | ⬜ Planned |
| 7 | Credential access & lateral movement | ⬜ Planned |
| 8 | Domain dominance (DCSync, Golden Ticket) | ⬜ Planned |

## 05 — Privilege Escalation

Local privesc on both platforms.

| # | Project | Status |
|---|---|---|
| 1 | Linux privesc — SUID & sudo misconfigs | ⬜ Planned |
| 2 | Linux privesc — cron, PATH, capabilities | ⬜ Planned |
| 3 | Linux privesc — kernel exploits | ⬜ Planned |
| 4 | Windows privesc — services & unquoted paths | ⬜ Planned |
| 5 | Windows privesc — token impersonation | ⬜ Planned |
| 6 | Windows privesc — registry & autorun misconfigs | ⬜ Planned |

## 06 — Payload Development & Defense Evasion

The craft side of offense — building and hiding payloads, and getting past AV/EDR. **Lab testing only.**

| # | Project | Status |
|---|---|---|
| 1 | Custom reverse shell / loader (Python & C#) | ⬜ Planned |
| 2 | Obfuscation & packing basics | ⬜ Planned |
| 3 | AMSI & ETW bypass | ⬜ Planned |
| 4 | LOLBins & living-off-the-land techniques | ⬜ Planned |
| 5 | AV evasion testing | ⬜ Planned |
| 6 | EDR evasion concepts (lab) | ⬜ Planned |

## 07 — Post-Exploitation & C2

Persistence, lateral movement, and command-and-control tradecraft — **isolated lab environments only.**

| # | Project | Status |
|---|---|---|
| 1 | Post-ex fundamentals (persistence, data staging) | ⬜ Planned |
| 2 | C2 framework setup (Sliver / Havoc in isolated lab) | ⬜ Planned |
| 3 | Beaconing & OPSEC-aware C2 configuration | ⬜ Planned |
| 4 | Lateral movement techniques | ⬜ Planned |
| 5 | Exfiltration simulation & detection | ⬜ Planned |

## 08 — Cloud Red Teaming 🔒

*Reserved — to be added together later.* AWS / Azure / GCP attack paths, IAM privilege escalation, metadata abuse, and cloud-specific persistence. This is a natural differentiator given the AWS + Azure/SC-200 background.

| # | Project | Status |
|---|---|---|
| — | *(projects to be defined)* | 🔒 Reserved |

## 09 — Adversary Emulation

Full attack chains mapped end-to-end to MITRE ATT&CK, with the defender's view documented alongside.

| # | Project | Status |
|---|---|---|
| 1 | Emulate a known threat actor TTP chain | ⬜ Planned |
| 2 | Purple-team exercise: attack + Code-Blue detection | ⬜ Planned |
| 3 | Atomic Red Team test execution & mapping | ⬜ Planned |
| 4 | Full engagement (recon → domain admin → report) | ⬜ Planned |

## 10 — Methodology & Reporting

What makes it an *operation* rather than a pile of exploits: scoping, OPSEC, and client-grade reporting.

| # | Project | Status |
|---|---|---|
| 1 | Scoping & Rules of Engagement template | ⬜ Planned |
| 2 | OPSEC & deconfliction planning | ⬜ Planned |
| 3 | MITRE ATT&CK Navigator mapping workflow | ⬜ Planned |
| 4 | Note-taking & evidence collection workflow | ⬜ Planned |
| 5 | Client-grade engagement report (template + sample) | ⬜ Planned |
| 6 | Debrief & remediation recommendations | ⬜ Planned |

---

## Author

**Rakibul Hoque Chowdhury** ([@rakibulhcrafat07](https://github.com/rakibulhcrafat07))
