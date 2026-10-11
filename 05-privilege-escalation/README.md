# 05 - Privilege Escalation

> **Status:** Planned
> Part of [Code-Red](../README.md) — Red Team Operations. See the [roadmap](../roadmap.md) for the full project list.

## Objective

Local privilege escalation on both platforms - from a foothold to full control of the host.

## Projects in this section

- [ ] Linux privesc - SUID & sudo misconfigs
- [ ] Linux privesc - cron, PATH, capabilities
- [ ] Linux privesc - kernel exploits
- [ ] Windows privesc - services & unquoted paths
- [ ] Windows privesc - token impersonation
- [ ] Windows privesc - registry & autorun misconfigs

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
