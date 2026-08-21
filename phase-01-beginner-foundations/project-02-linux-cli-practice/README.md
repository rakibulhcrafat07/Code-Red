# Project 2: Linux & CLI Practice

**Status:** ✅ Done

## Goal

Build comfort with the command line and core networking concepts before attempting anything offensive.

**Note:** completed via self-study instead of TryHackMe's rooms — worked through Networking Fundamentals and Linux Fundamentals topics directly, with hands-on exercises, and wrote up the notes below as the portfolio deliverable.

## Portfolio Deliverable

A cheat-sheet summarizing the commands and concepts learned, covering both networking and Linux fundamentals.

---

## Table of Contents

1. [Networking Fundamentals](#networking-fundamentals)
   - [OSI & TCP/IP Model](#osi--tcpip-model)
   - [Ports & Protocols](#ports--protocols)
   - [Subnetting](#subnetting)
   - [DNS](#dns)
   - [HTTP / HTTPS](#http--https)
2. [Linux Fundamentals](#linux-fundamentals)
   - [Filesystem](#filesystem)
   - [Permissions](#permissions)
   - [Bash Basics](#bash-basics)
   - [SSH](#ssh)

---

## Networking Fundamentals

### OSI & TCP/IP Model

**OSI Model (7 layers, top to bottom):**

| # | Layer | Data Unit | Example |
|---|-------|-----------|---------|
| 7 | Application | Data | HTTP, FTP, DNS, SMTP |
| 6 | Presentation | Data | Encryption, compression |
| 5 | Session | Data | Session establishment |
| 4 | Transport | Segments | TCP, UDP (ports live here) |
| 3 | Network | Packets | IP, ICMP (routing) |
| 2 | Data Link | Frames | MAC address, switches |
| 1 | Physical | Bits | Cables, Wi-Fi signal |

Mnemonic (Physical → Application): **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way

**TCP/IP Model (4 layers, what's used in practice):**

- Application (OSI: Application + Presentation + Session)
- Transport (TCP/UDP)
- Internet (IP, routing)
- Network Access (Data Link + Physical)

**Practical mapping for red teaming:**
- Port scanning (nmap) → Transport layer
- Packet sniffing → Data Link layer
- Web exploitation → Application layer

---

### Ports & Protocols

**TCP vs UDP**

| | TCP | UDP |
|---|-----|-----|
| Connection | Connection-oriented (3-way handshake) | Connectionless |
| Reliability | Guaranteed delivery, ordered | No guarantee |
| Speed | Slower | Faster |
| Use case | Web, file transfer, email | DNS, streaming, gaming |

**TCP 3-way handshake:** `SYN` → `SYN-ACK` → `ACK`

**Well-known ports:**

| Port | Protocol | Service |
|------|----------|---------|
| 20/21 | TCP | FTP (data/control) |
| 22 | TCP | SSH |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP (send mail) |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP |
| 80 | TCP | HTTP |
| 110 | TCP | POP3 (read mail) |
| 143 | TCP | IMAP (read mail) |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 3306 | TCP | MySQL |
| 3389 | TCP | RDP |

**Port ranges:**
- `0–1023` — Well-known/system ports
- `1024–49151` — Registered ports
- `49152–65535` — Dynamic/ephemeral ports

---

### Subnetting

**Key formulas:**
- Host bits = `32 − CIDR`
- Total addresses = `2^(host bits)`
- Usable hosts = `2^(host bits) − 2` (minus network + broadcast address)
- Block size = `256 − last non-255 octet of the subnet mask`

**Common CIDR reference:**

| CIDR | Subnet Mask | Host bits | Usable hosts |
|------|-------------|-----------|---------------|
| /24 | 255.255.255.0 | 8 | 254 |
| /25 | 255.255.255.128 | 7 | 126 |
| /26 | 255.255.255.192 | 6 | 62 |
| /27 | 255.255.255.224 | 5 | 30 |
| /28 | 255.255.255.240 | 4 | 14 |

**Worked example — `192.168.1.32/27`:**
- Block size = 32 → blocks are `.0, .32, .64, .96...`
- Network address: `192.168.1.32`
- Broadcast address: `192.168.1.63`
- Usable range: `192.168.1.33 – 192.168.1.62` (30 hosts)

**Method:** find block size → find which block the IP falls in → network = block start, broadcast = one before the next block starts.

---

### DNS

**Resolution flow:** Browser cache → OS cache → Recursive resolver → Root server → TLD server → Authoritative server → IP returned.

**Record types:**

| Record | Purpose |
|--------|---------|
| A | Domain → IPv4 |
| AAAA | Domain → IPv6 |
| CNAME | Domain → another domain (alias) |
| MX | Mail server for the domain |
| NS | Authoritative nameserver |
| TXT | Text data (SPF, verification) |
| PTR | IP → domain (reverse lookup) |
| SOA | Zone administrative info |

**CNAME example:**
```
example.com       A       93.184.216.34
www.example.com   CNAME   example.com
```
`www` has no IP of its own — it points to `example.com`, which resolves the IP. One update point instead of two.

**Tools:**
```bash
nslookup example.com
dig example.com
dig example.com MX
dig -x 8.8.8.8          # reverse lookup
dig axfr @ns example.com # zone transfer test (misconfig recon)
```

`dig` is preferred in red teaming — more detail, scriptable, supports zone transfer testing.

**Recon value:** subdomain enumeration, mail server discovery, TXT record leaks, zone transfer misconfigurations.

---

### HTTP / HTTPS

**Methods:**

| Method | Purpose |
|--------|---------|
| GET | Request data (no server change) |
| POST | Send/create data |
| PUT | Replace a resource |
| PATCH | Partially update a resource |
| DELETE | Remove a resource |
| HEAD | Headers only, no body |
| OPTIONS | Ask what methods are allowed |

**Why POST for login, not GET:** GET puts data in the URL → saved in browser history, server logs, shareable links. POST puts data in the request body → not logged/visible in the URL. (Note: POST alone doesn't encrypt — HTTPS does.)

**Status codes:**

| Range | Meaning | Examples |
|-------|---------|----------|
| 1xx | Informational | 100 Continue |
| 2xx | Success | 200 OK, 201 Created |
| 3xx | Redirection | 301, 302 |
| 4xx | Client error | 401 Unauthorized, 403 Forbidden, 404 Not Found |
| 5xx | Server error | 500, 503 |

`403` = resource exists but access denied (interesting recon target). `401` = not authenticated. `404` = doesn't exist.

**Key headers:** `Host`, `User-Agent`, `Cookie`, `Authorization`, `Content-Type`

**HTTPS = HTTP + TLS.** Provides encryption, integrity, and authentication (via certificates signed by a trusted CA — proves you're talking to the real server, not an impersonator).

**TLS handshake (simplified):** ClientHello → ServerHello + certificate → client verifies cert → shared session key established → encrypted communication begins.

---

## Linux Fundamentals

### Filesystem

**Hierarchy (all under root `/`):**

| Path | Contents |
|------|----------|
| `/bin` | Basic commands |
| `/etc` | Configuration files |
| `/home` | User personal folders |
| `/root` | Root user's home |
| `/var` | Variable data, logs (`/var/log`) |
| `/tmp` | Temporary files (often writable — payload staging) |
| `/usr` | Installed programs/libraries |
| `/dev` | Device files |
| `/proc` | Running process info (virtual) |

**Recon-relevant paths:** `/etc/passwd` (user accounts), `/etc/shadow` (password hashes, root-only), `/var/log` (system activity).

**Navigation commands:**

| Command | Purpose |
|---------|---------|
| `pwd` | Show current directory |
| `ls -la` | List contents incl. hidden files, details |
| `cd <path>` / `cd ..` / `cd ~` | Change directory / up one / home |
| `mkdir <name>` | Create directory |
| `rm <file>` / `rm -r <dir>` | Delete file / delete directory recursively |
| `cp <src> <dst>` | Copy |
| `mv <src> <dst>` | Move/rename |
| `find / -name "file"` | Search filesystem |
| `cat <file>` | Print file contents |
| `touch <file>` | Create empty file |

**Absolute path** starts with `/` (always the same location). **Relative path** is based on current directory.

---

### Permissions

**`ls -la` output:**
```
-rwxr-xr--  1 rafat  staff  1024 Aug 21 10:00 script.sh
```

```
-   rwx   r-x   r--
│    │     │     │
│    │     │     └─ Others
│    │     └─────── Group
│    └───────────── Owner
└────────────────── Type (- file, d directory, l symlink)
```

**Numeric notation:** `r=4, w=2, x=1` → sum per group.

| Symbolic | Numeric |
|----------|---------|
| rwx | 7 |
| rw- | 6 |
| r-x | 5 |
| r-- | 4 |
| --- | 0 |

Common combos: `755` (owner full, others read+execute — typical for scripts), `644` (owner read+write, others read-only — typical for regular files), `777` (everyone full access — security red flag).

**Commands:**
```bash
chmod 755 file.sh       # set numeric permissions
chmod +x file.sh        # add execute permission
chown user:group file   # change ownership
```

**Red team relevance:** world-writable (`777`) files and misconfigured SUID/SGID bits are common privilege escalation vectors.

---

### Bash Basics

**Pipes & redirection:**

| Symbol | Purpose |
|--------|---------|
| `\|` | Pipe output of one command into another |
| `>` | Write output to file (overwrite) |
| `>>` | Append output to file |
| `<` | Use file as input |
| `2>` | Redirect error output |

```bash
cat access.log | grep "404" | wc -l     # count lines containing "404"
nmap -sV 192.168.1.1 > scan_result.txt  # save scan output to file
nmap 192.168.1.1 | grep open            # filter for open ports
```

**Common commands:**

| Command | Purpose |
|---------|---------|
| `grep "pattern" file` | Search text in file |
| `grep -r "pattern" dir/` | Recursive search |
| `wc -l file` | Count lines |
| `sort` / `uniq` | Sort data / remove duplicates |
| `head -n 10` / `tail -n 10` | First/last N lines |
| `tail -f log.txt` | Follow a log live |
| `awk '{print $1}'` | Extract column |
| `sed 's/old/new/g'` | Find & replace |
| `ps aux` | List running processes |
| `kill <PID>` | Stop a process |
| `curl url` | Fetch data from a URL |

**Variables & simple scripting:**
```bash
target="192.168.1.1"
echo "Scanning $target"

for ip in 192.168.1.1 192.168.1.2 192.168.1.3
do
  ping -c 1 $ip
done
```

---

### SSH

SSH = encrypted remote login, replaces plaintext Telnet.

```bash
ssh username@192.168.1.10          # basic login
ssh username@192.168.1.10 -p 2222  # non-default port
```

**Key-based auth (preferred over password):**
```bash
ssh-keygen -t ed25519       # generate key pair (private + .pub)
ssh-copy-id username@host   # copy public key to server's authorized_keys
```

Private key stays local and secret; public key goes on the server. No password brute-forcing possible without the private key.

**SSH config shortcut** (`~/.ssh/config`):
```
Host myserver
    HostName 192.168.1.10
    User rafat
    Port 2222
```
Then just `ssh myserver`.

**Red team relevance:** SSH is a common brute-force target; a leaked private key allows direct server access (lateral movement); SSH tunneling (`ssh -L`) can reach internal network resources.

## Next

[Project 3: Build a Simple Port Scanner](../project-03-port-scanner)
