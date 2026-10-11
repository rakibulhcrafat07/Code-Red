# Code-Red — Red Team Operations

A hands-on offensive security portfolio: adversary tradecraft organized along the attack lifecycle, from reconnaissance through full-chain adversary emulation. Every project ships with an objective, lab setup, MITRE ATT&CK mapping, execution write-up, a **Detection** section, and lessons learned.

Companion to [Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue) (DFIR / SOC / blue-team). Where Code-Blue defends, Code-Red attacks — and every Code-Red project closes the loop by documenting how the same activity looks from the defender's side.

> ⚠️ **Scope & ethics.** Everything here is built and run against hosts I own, isolated lab/VM environments I control, or targets with explicit written authorization (e.g. `scanme.nmap.org`). Nothing in this repo is intended for use against systems without permission. Unauthorized scanning or exploitation is illegal in most jurisdictions (CFAA, Computer Misuse Act, and equivalents) — the activity itself is the offense, regardless of outcome.

---

## Why this repo looks different

Most red-team portfolios stop at "I ran the exploit." This one carries a **purple-team angle**: because my background is SOC / SIEM (Microsoft SC-200, Wazuh, Sentinel), each attack is paired with how to detect it — the ATT&CK technique, the telemetry it generates, and a link to the matching detection logic in Code-Blue where one exists.

The story this tells: *I understand the attack well enough to defend against it.*

---

## Structure

```
Code-Red/
├── README.md
├── roadmap.md
├── 00-foundations/                 # networking, Linux, scripting, first tooling
├── 01-recon-osint/                 # passive + active reconnaissance
├── 02-initial-access-social-eng/   # phishing, payload delivery, first foothold
├── 03-web-app-exploitation/        # OWASP-style web attacks
├── 04-network-and-active-directory/# internal network + AD attack paths
├── 05-privilege-escalation/        # Linux + Windows privesc
├── 06-payload-dev-evasion/         # payload crafting + AV/EDR evasion (lab)
├── 07-post-exploitation-c2/        # lab-only post-ex and C2 tradecraft
├── 08-cloud-red-team/              # AWS/Azure/GCP attack paths (reserved)
├── 09-adversary-emulation/         # ATT&CK-mapped full-chain emulation
├── 10-methodology-and-reporting/   # scoping, OPSEC, client-grade reporting
├── tools/                          # self-built offensive tooling
└── writeups/                       # CTF / HTB / THM write-ups
```

## Progress

| Section | Focus | Status |
|---|---|---|
| [00 — Foundations](./00-foundations) | Networking, Linux/CLI, scripting, first tooling | 🟡 In progress |
| [01 — Recon & OSINT](./01-recon-osint) | Passive/active recon, enumeration | ⬜ Planned |
| [02 — Initial Access & Social Eng.](./02-initial-access-social-eng) | Phishing, payload delivery, first foothold | ⬜ Planned |
| [03 — Web App Exploitation](./03-web-app-exploitation) | Injection, auth, access control | ⬜ Planned |
| [04 — Network & Active Directory](./04-network-and-active-directory) | Internal pivoting, AD attack paths | ⬜ Planned |
| [05 — Privilege Escalation](./05-privilege-escalation) | Linux + Windows privesc | ⬜ Planned |
| [06 — Payload Dev & Evasion](./06-payload-dev-evasion) | Payload crafting, AV/EDR evasion (lab) | ⬜ Planned |
| [07 — Post-Exploitation & C2](./07-post-exploitation-c2) | Persistence, lateral movement, C2 (lab only) | ⬜ Planned |
| [08 — Cloud Red Teaming](./08-cloud-red-team) | AWS/Azure/GCP attack paths | 🔒 Reserved |
| [09 — Adversary Emulation](./09-adversary-emulation) | Full-chain, ATT&CK-mapped | ⬜ Planned |
| [10 — Methodology & Reporting](./10-methodology-and-reporting) | Scoping, OPSEC, client-grade reporting | ⬜ Planned |

See [`roadmap.md`](./roadmap.md) for the project-level breakdown.

---

## Per-project template

Every project folder follows the same shape so the repo reads consistently:

1. **Objective** — what this project demonstrates
2. **Lab Setup** — hosts, tools, network layout
3. **ATT&CK Mapping** — tactics/techniques exercised
4. **Execution** — the actual work, with notes and diagrams
5. **Detection** — how it appears in Wazuh / Sentinel, relevant logs, link to Code-Blue detection where available
6. **Lessons Learned** — what broke, what surprised me, what I'd do differently

---

## Author

**Rakibul Hoque Chowdhury** ([@rakibulhcrafat07](https://github.com/rakibulhcrafat07))
IT & Cybersecurity — networking, blue-team SOC/SIEM, and offensive security.
