# 00 - Foundations

> **Status:** In progress
> Part of [Code-Red](../README.md) — Red Team Operations. See the [roadmap](../roadmap.md) for the full project list.

## Objective

Networking, OS, scripting, and first self-built tooling - the groundwork everything else stands on.

## Projects in this section

- [x] [Home Lab Setup](./project-01-home-lab-setup)
- [x] [Networking & Linux Fundamentals](./project-02-networking-linux)
- [x] [Simple Port Scanner](./project-03-port-scanner)
- [ ] [First CTF Write-ups](./project-04-first-ctf-writeups)
- [ ] Bash scripting for recon automation
- [ ] Python for offensive tooling (sockets, requests, argparse)
- [ ] Windows internals & PowerShell fundamentals

---

### Per-project template

Each project here follows the repo's standard shape:

1. **Objective** - what the project demonstrates
2. **Lab Setup** - hosts, tools, network layout
3. **ATT&CK Mapping** - tactics / techniques exercised
4. **Execution** - the work itself, with notes and diagrams
5. **Detection** - how it looks in Wazuh / Sentinel, relevant logs, and a link to the matching [Code-Blue](https://github.com/rakibulhcrafat07/Code-Blue) detection where one exists
6. **Lessons Learned** - what broke, what surprised me, what I would do differently

> **Scope & ethics.** All work here is against hosts I own, isolated lab/VM environments I control, or targets with explicit written authorization. Nothing here is for use against systems without permission.
