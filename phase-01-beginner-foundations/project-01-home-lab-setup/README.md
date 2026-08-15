# Project 1: Home Lab Setup

Built a small, isolated penetration-testing lab using VirtualBox: a Kali Linux attack machine and a deliberately vulnerable Metasploitable2 target, both on a private internal network with no route to the internet or the host's home network.

## Goal

Learn to build and network virtual machines safely — the foundation every later project in this roadmap runs on.

## Environment

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Attack VM | Kali Linux 2024.3 (installed from official ISO) — 4096 MB RAM, 2 vCPU, 30 GB disk |
| Target VM | Metasploitable2 (pre-built vulnerable image) — 512 MB RAM, 1 vCPU, 8 GB disk |
| Network | VirtualBox Internal Network (`intnet`) — isolated from host & internet |

## Network Diagram

```mermaid
graph TB
    subgraph Host["Host Machine (Windows)"]
        subgraph VBox["Oracle VirtualBox"]
            subgraph IntNet["Internal Network: intnet (isolated, no internet)"]
                Kali["Kali Linux<br/>Attack VM<br/>192.168.100.20/24"]
                Meta["Metasploitable2<br/>Target VM<br/>192.168.100.10/24"]
                Kali <-->|ping / nmap| Meta
            end
        end
    end
```

The `intnet` Internal Network exists only inside VirtualBox — it has no link to the host's real network adapter or the internet, so the intentionally-vulnerable target VM is never exposed outside the lab.

## Detailed Walkthrough

Every screenshot below is from the actual build, in order. All 45 images also live in [`screenshots/`](./screenshots) at full resolution.

### Step 1 — Creating the Kali Linux VM

Opened VirtualBox and started a new VM: named it **Kali Linux**, and pointed the ISO Image field at the official `kali-linux-2024.3-installer-amd64.iso`. VirtualBox auto-detected the OS type as "Linux / Ubuntu (64-bit)" from the ISO — close enough for Kali (Debian-based) that it wasn't worth correcting.

Gave it **4096 MB RAM** and **2 CPUs** — enough headroom to run a full Xfce desktop and tools without the VM crawling — then created a **30 GB** virtual disk with "Pre-allocate Full Size" checked (trades a slightly longer VM-creation step for steadier disk performance later).

| Naming the VM & selecting the ISO | Allocating RAM & CPU | Creating the 30 GB disk |
|---|---|---|
| [![](./screenshots/01.png)](./screenshots/01.png) | [![](./screenshots/02.png)](./screenshots/02.png) | [![](./screenshots/03.png)](./screenshots/03.png) |

### Step 2 — Booting the installer and setting language/locale

VM created (shown below with its full spec summary), started it, and it booted straight into the Kali installer's boot menu — picked **Graphical Install**. Walked through language (**English**), location (**Bangladesh** — this drives the timezone and available locales), the resulting locale choice (**United States**, since `en_BD` isn't a defined locale), and keyboard layout (**American English**). The installer then scanned the mounted ISO for its package pool.

| VM created, ready to boot | Boot menu — Graphical Install | Language: English |
|---|---|---|
| [![](./screenshots/04.png)](./screenshots/04.png) | [![](./screenshots/05.png)](./screenshots/05.png) | [![](./screenshots/06.png)](./screenshots/06.png) |

| Location: Bangladesh | Locale: United States | Keyboard: American English | Scanning installation media |
|---|---|---|---|
| [![](./screenshots/07.png)](./screenshots/07.png) | [![](./screenshots/08.png)](./screenshots/08.png) | [![](./screenshots/09.png)](./screenshots/09.png) | [![](./screenshots/10.png)](./screenshots/10.png) |

### Step 3 — Hostname, domain, and the user account

Set the hostname to `kali` and left the domain name as `kali` (this is a standalone lab machine, not joined to any real domain, so it doesn't matter what's here). Created the actual login account: full name **Rakibul Rafat**, username **rakib**, and a password. The password was intentionally kept simple since this is an isolated lab VM with no external exposure — noted as a to-do to strengthen later if the VM's role ever changes.

| Hostname | Domain name | Full name | Username | Password |
|---|---|---|---|---|
| [![](./screenshots/11.png)](./screenshots/11.png) | [![](./screenshots/12.png)](./screenshots/12.png) | [![](./screenshots/13.png)](./screenshots/13.png) | [![](./screenshots/14.png)](./screenshots/14.png) | [![](./screenshots/15.png)](./screenshots/15.png) |

### Step 4 — Disk partitioning (and hitting an actual error)

Picked **Guided - use entire disk** as the partitioning method — but on the first pass, went straight from selecting the method to "Finish partitioning" *without* explicitly choosing a partitioning **scheme**. The installer let this happen silently and then refused to proceed:

> **No root file system** — No root file system is defined. Please correct this from the partitioning menu.

Went back into the partitioning menu — it now showed the disk (`sda`, 32.2 GB) with **no partitions defined at all**, confirming nothing had actually been written yet. Redid it properly this time: **Guided - use entire disk** → selected the `sda` disk → this time explicitly picked **"All files in one partition (recommended for new users)"** as the scheme → the overview now showed `#1 primary 31.2 GB ext4 /` and `#5 logical 1.0 GB swap` → **Finish partitioning and write changes to disk**. That kicked off the actual base-system install.

| Partitioning method | ⚠️ Error: no root filesystem | Menu after error — disk still empty |
|---|---|---|
| [![](./screenshots/16.png)](./screenshots/16.png) | [![](./screenshots/17.png)](./screenshots/17.png) | [![](./screenshots/18.png)](./screenshots/18.png) |

| Retry: method again | Select disk (sda) | This time, pick a scheme | Confirmed: root + swap partitions | Base system installing |
|---|---|---|---|---|
| [![](./screenshots/19.png)](./screenshots/19.png) | [![](./screenshots/20.png)](./screenshots/20.png) | [![](./screenshots/21.png)](./screenshots/21.png) | [![](./screenshots/22.png)](./screenshots/22.png) | [![](./screenshots/23.png)](./screenshots/23.png) |

**Takeaway:** the Debian/Kali installer's guided partitioning is a two-part decision — *method* (guided vs. manual) and *scheme* (how many partitions) — and skipping the scheme step silently leaves the disk unpartitioned instead of erroring immediately.

### Step 5 — Software selection

Left the defaults as-is: **Xfce** (Kali's default, lightweight desktop) plus the **top10** and **default** tool collections, which pull in the commonly-used pentesting tools (Nmap, Metasploit Framework, Wireshark, etc.) out of the box.

[![](./screenshots/24.png)](./screenshots/24.png)

### Step 6 — GRUB and finishing the install

Installed the GRUB bootloader to the VM's primary drive, and explicitly pointed it at `/dev/sda` when asked which device to install it to.

| Install GRUB to primary drive | GRUB device: /dev/sda |
|---|---|
| [![](./screenshots/25.png)](./screenshots/25.png) | [![](./screenshots/26.png)](./screenshots/26.png) |

### Step 7 — First boot

The VM rebooted off the newly-installed disk straight into the LightDM login screen, then into a full Xfce desktop after logging in with the `rakib` account — Kali install complete.

| Login screen | Xfce desktop |
|---|---|
| [![](./screenshots/27.png)](./screenshots/27.png) | [![](./screenshots/28.png)](./screenshots/28.png) |

### Step 8 — Importing Metasploitable2 (the target VM)

Metasploitable2 doesn't ship as an ISO — it's a pre-built disk image. Downloaded `Metasploitable2-Linux.zip` from SourceForge and extracted it to get `Metasploitable.vmdk`. When creating its VM, instead of creating a new virtual disk, used the Hard Disk Selector to **attach the existing `Metasploitable.vmdk`** directly. Gave it a lighter spec since it's just a target — **512 MB RAM, 1 CPU** — and the disk step confirmed "Use an Existing Virtual Hard Disk File: Metasploitable.vmdk (Normal, 8.00 GB)".

| Selecting the existing .vmdk | Naming the VM (Other Linux 64-bit) | Hardware: 512 MB / 1 CPU | Disk: existing Metasploitable.vmdk |
|---|---|---|---|
| [![](./screenshots/29.png)](./screenshots/29.png) | [![](./screenshots/30.png)](./screenshots/30.png) | [![](./screenshots/31.png)](./screenshots/31.png) | [![](./screenshots/32.png)](./screenshots/32.png) |

Both VMs now show up in the VirtualBox Manager, side by side:

[![](./screenshots/33.png)](./screenshots/33.png)

### Step 9 — Isolating both VMs on an internal network

By default both VMs were on **NAT**, which routes out to the internet through the host — not what you want for a machine that's deliberately full of vulnerabilities. Opened each VM's **Settings → Network → Adapter 1** and switched **Attached to** from NAT to **Internal Network**, using the exact same network name (`intnet`) on both VMs so they can only see each other.

| Metasploitable2 — Internal Network `intnet` | Kali Linux — Internal Network `intnet` |
|---|---|
| [![](./screenshots/34.png)](./screenshots/34.png) | [![](./screenshots/35.png)](./screenshots/35.png) |

### Step 10 — Metasploitable2: no IP, so assign one manually

Started Metasploitable2 and logged in with the default `msfadmin` / `msfadmin` credentials. Running `ip a` showed `eth0` was up but had **no IPv4 address at all** — only an IPv6 link-local address. That's because VirtualBox's Internal Network mode ships with **no DHCP server**, so nothing hands out addresses.

Fixed it with a direct interface command:
```
sudo ifconfig eth0 192.168.100.10 netmask 255.255.255.0 up
```
(First attempt had a typo — `udo` instead of `sudo` — and then a mistyped `sudo` password on the retry. Third try worked cleanly.) A follow-up `ip a` confirmed `inet 192.168.100.10/24` was now live on `eth0`.

| Logged in, `ip a` shows no IPv4 | Typo, wrong password, then success | Confirmed: 192.168.100.10/24 is live |
|---|---|---|
| [![](./screenshots/36.png)](./screenshots/36.png) | [![](./screenshots/37.png)](./screenshots/37.png) | [![](./screenshots/38.png)](./screenshots/38.png) |

### Step 11 — Kali: the same fix doesn't work, because NetworkManager

Tried the identical approach on Kali:
```
sudo ip addr add 192.168.100.20/24 dev eth0
sudo ip link set eth0 up
ping 192.168.100.10
```
This time `ping` failed with **"Network is unreachable"**. Checking `ip a` afterward showed the address had **silently disappeared** — `eth0` was back to only an IPv6 link-local address, as if the `ip addr add` had never happened.

The cause: unlike Metasploitable2's older, unmanaged networking, this Kali install runs **NetworkManager**, which actively owns `eth0`. Low-level commands like `ip addr add` bypass NetworkManager, so it silently reverts them back to whatever its own connection profile says (which had no static config). `nmcli connection show` confirmed there was a **"Wired connection 1"** profile, but its `DEVICE` column showed `--` — it wasn't even active.

| First attempt: address added, then "Network unreachable" | `ip a` afterward: the address is gone | `nmcli connection show`: profile exists, but inactive |
|---|---|---|
| [![](./screenshots/39.png)](./screenshots/39.png) | [![](./screenshots/40.png)](./screenshots/40.png) | [![](./screenshots/41.png)](./screenshots/41.png) |

Tried activating that profile directly with `sudo nmcli connection up "Wired connection 1"` — it failed too, because the profile was still set to DHCP (`ipv4.method: auto`) and there's no DHCP server on this network, so it timed out trying to get a lease:

> Error: Connection activation failed: IP configuration could not be reserved (no available address, timeout, etc.)

| `nmcli connection up` fails — still on DHCP | Same error, ping still unreachable |
|---|---|
| [![](./screenshots/42.png)](./screenshots/42.png) | [![](./screenshots/43.png)](./screenshots/43.png) |

**The actual fix**: configure the static IP *through NetworkManager itself*, on the connection profile, instead of fighting it:
```
sudo nmcli connection modify "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.100.20/24
```
Verified the profile picked it up (`nmcli connection show "Wired connection 1" | grep ipv4` showed `ipv4.method: manual` and `ipv4.addresses: 192.168.100.20/24`), then brought it up:
```
sudo nmcli connection up "Wired connection 1"
```
This time it activated cleanly. `ip a` showed `192.168.100.20/24` on `eth0`, and finally:
```
$ ping 192.168.100.10
PING 192.168.100.10 (192.168.100.10) 56(84) bytes of data.
64 bytes from 192.168.100.10: icmp_seq=1 ttl=64 time=11.2 ms
64 bytes from 192.168.100.10: icmp_seq=2 ttl=64 time=0.454 ms
64 bytes from 192.168.100.10: icmp_seq=3 ttl=64 time=0.537 ms

--- 192.168.100.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2022ms
```

| Setting the static IP on the actual connection profile | Success: activated, IP set, 0% packet loss ping |
|---|---|
| [![](./screenshots/44.png)](./screenshots/44.png) | [![](./screenshots/45.png)](./screenshots/45.png) |

0% packet loss — Kali can reach Metasploitable2, and the lab is fully isolated from the outside network. Home lab setup complete.

## Key Learnings

- VirtualBox's **Internal Network** mode is the right choice for isolating intentionally vulnerable machines, but it ships with no DHCP — static IPs (or a custom DHCP server) are required.
- On modern Debian/Kali installs, **NetworkManager owns the interface**; low-level commands like `ip addr add` get silently reverted the moment NetworkManager re-asserts its own (DHCP) configuration. Static configuration has to go through `nmcli connection modify` on the actual connection profile so it persists and doesn't fight with NetworkManager.
- Guided partitioning in the Debian/Kali installer is **two separate decisions** — method, then scheme. Confirming the method alone and skipping the scheme selection leaves no root filesystem defined, and the installer only complains about it once you try to finish, not when you skip the step.
- Older, "bare" Linux images (Metasploitable2, Ubuntu 8.04) manage networking with simple `ifconfig`/`init.d` scripts, so a direct `ifconfig ... up` sticks. Modern distros with NetworkManager or systemd-networkd need to be configured *through* that manager, not around it.

## Next

[Project 2: Linux & CLI Practice](../project-02-linux-cli-practice) — TryHackMe's Linux Fundamentals and Networking Fundamentals rooms.
