# 02 - Initial Access & Social Engineering

> **Status:** Planned
> Part of [Code-Red](../README.md) — Red Team Operations. See the [roadmap](../roadmap.md) for the full project list.

## Objective

How an operator actually gets the first foothold - the entry point real engagements start from. **Lab / authorized targets only.**

## Projects in this section

- [ ] Phishing infrastructure setup (domains, mail, in isolated lab)
- [ ] Credential-harvesting phishing page (lab)
- [ ] Malicious document / macro payload delivery
- [ ] Pretexting & OSINT-driven lure design
- [ ] Payload delivery & establishing the foothold
- [ ] Detection: phishing & initial-access telemetry

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
