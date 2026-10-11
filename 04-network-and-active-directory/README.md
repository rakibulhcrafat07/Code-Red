# 04 - Network & Active Directory

> **Status:** Planned
> Part of [Code-Red](../README.md) — Red Team Operations. See the [roadmap](../roadmap.md) for the full project list.

## Objective

Internal network attack paths and Active Directory tradecraft in a lab domain.

## Projects in this section

- [ ] Internal enumeration & network pivoting
- [ ] SMB / relay attacks
- [ ] AD recon & BloodHound path mapping
- [ ] Kerberoasting
- [ ] AS-REP roasting
- [ ] Pass-the-Hash / Pass-the-Ticket
- [ ] Credential access & lateral movement
- [ ] Domain dominance (DCSync, Golden Ticket)

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
