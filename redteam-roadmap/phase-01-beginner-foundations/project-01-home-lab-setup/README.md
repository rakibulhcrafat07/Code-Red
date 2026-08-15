# Project 1: Home Lab Setup

Built a small, isolated penetration-testing lab using VirtualBox: a Kali Linux attack machine and a deliberately vulnerable Metasploitable2 target, both on a private internal network with no route to the internet or the host's home network.

## Goal

Learn to build and network virtual machines safely — the foundation every later project in this roadmap runs on.

## Environment

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| Attack VM | Kali Linux 2024.3 (installed from official ISO) — 4096 MB RAM, 2 vCPU, 30 GB disk |
| Target VM | Metasploitable2 (pre-built vulnerable image) — 512 MB RAM, 8 GB disk |
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

## Setup Steps

### 1. Install VirtualBox
Downloaded and installed Oracle VirtualBox on the host machine.

### 2. Create & Install Kali Linux (Attack VM)
- Created a new VM in VirtualBox: 4096 MB RAM, 2 CPUs, 30 GB dynamically allocated disk.
- Booted from the official `kali-linux-2024.3-installer-amd64.iso` and ran the graphical installer.
- Configured language/locale, hostname (`kali`), user account, and guided disk partitioning ("All files in one partition").
- Installed the GRUB bootloader to `/dev/sda`.
- Installed the default Xfce desktop environment plus Kali's recommended tool collection.

### 3. Import Metasploitable2 (Target VM)
- Downloaded `Metasploitable2-Linux.zip` and extracted the pre-built `Metasploitable.vmdk`.
- Created a new VM (512 MB RAM, "Other Linux 64-bit") and attached the existing `.vmdk` as its disk instead of creating a new one.
- Default credentials: `msfadmin` / `msfadmin`.

### 4. Isolate Both VMs on an Internal Network
- In each VM's **Settings → Network → Adapter 1**, set **Attached to: Internal Network**, name `intnet` (must match exactly on both VMs).
- VirtualBox's Internal Network has no DHCP server by default, so static IPs were assigned manually:
  - **Metasploitable2** (`eth0`):
    ```
    sudo ifconfig eth0 192.168.100.10 netmask 255.255.255.0 up
    ```
  - **Kali Linux** (`eth0`, managed by NetworkManager — a plain `ip addr add` doesn't persist, so the connection profile was configured instead):
    ```
    sudo nmcli connection modify "Wired connection 1" ipv4.method manual ipv4.addresses 192.168.100.20/24
    sudo nmcli connection up "Wired connection 1"
    ```

### 5. Verify Connectivity
From Kali:
```
$ ping 192.168.100.10
PING 192.168.100.10 (192.168.100.10) 56(84) bytes of data.
64 bytes from 192.168.100.10: icmp_seq=1 ttl=64 time=11.2 ms
64 bytes from 192.168.100.10: icmp_seq=2 ttl=64 time=0.454 ms
64 bytes from 192.168.100.10: icmp_seq=3 ttl=64 time=0.537 ms

--- 192.168.100.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2022ms
```

0% packet loss — Kali can reach Metasploitable2, and the lab is fully isolated from the outside network.

## Screenshot Log

Every screenshot captured while building this lab, in order, grouped by stage. All 46 images live in [`screenshots/`](./screenshots).

<details>
<summary><b>1. Kali Linux — VM creation wizard, guided install & disk partitioning</b> (images 01–24)</summary>
<br>

Naming the VM and pointing it at the Kali ISO, setting RAM/CPU/disk size, then the full Debian-installer walkthrough (language, location, locale, keyboard, hostname, user account, password) and disk partitioning — including hitting and fixing a "No root file system is defined" error along the way by re-running guided partitioning and explicitly picking the "All files in one partition" scheme.

| | | | |
|---|---|---|---|
| [![](./screenshots/01.png)](./screenshots/01.png) | [![](./screenshots/02.png)](./screenshots/02.png) | [![](./screenshots/03.png)](./screenshots/03.png) | [![](./screenshots/04.png)](./screenshots/04.png) |
| [![](./screenshots/05.png)](./screenshots/05.png) | [![](./screenshots/06.png)](./screenshots/06.png) | [![](./screenshots/07.png)](./screenshots/07.png) | [![](./screenshots/08.png)](./screenshots/08.png) |
| [![](./screenshots/09.png)](./screenshots/09.png) | [![](./screenshots/10.png)](./screenshots/10.png) | [![](./screenshots/11.png)](./screenshots/11.png) | [![](./screenshots/12.png)](./screenshots/12.png) |
| [![](./screenshots/13.png)](./screenshots/13.png) | [![](./screenshots/14.png)](./screenshots/14.png) | [![](./screenshots/15.png)](./screenshots/15.png) | [![](./screenshots/16.png)](./screenshots/16.png) |
| [![](./screenshots/17.png)](./screenshots/17.png) | [![](./screenshots/18.png)](./screenshots/18.png) | [![](./screenshots/19.png)](./screenshots/19.png) | [![](./screenshots/20.png)](./screenshots/20.png) |
| [![](./screenshots/21.png)](./screenshots/21.png) | [![](./screenshots/22.png)](./screenshots/22.png) | [![](./screenshots/23.png)](./screenshots/23.png) | [![](./screenshots/24.png)](./screenshots/24.png) |

</details>

<details>
<summary><b>2. Kali Linux — software package selection</b> (images 25–26)</summary>
<br>

Keeping the default Xfce desktop environment and Kali's recommended tool collection.

| | |
|---|---|
| [![](./screenshots/25.png)](./screenshots/25.png) | [![](./screenshots/26.png)](./screenshots/26.png) |

</details>

<details>
<summary><b>3. Kali Linux — GRUB boot loader install</b> (image 27)</summary>
<br>

Installing GRUB to the VM's primary drive.

[![](./screenshots/27.png)](./screenshots/27.png)

</details>

<details>
<summary><b>4. Kali Linux — GRUB device selection</b> (image 28)</summary>
<br>

Pointing GRUB at `/dev/sda`.

[![](./screenshots/28.png)](./screenshots/28.png)

</details>

<details>
<summary><b>5. Kali Linux — first login screen</b> (images 29–30)</summary>
<br>

First boot after installation, reaching the LightDM login prompt.

| | |
|---|---|
| [![](./screenshots/29.png)](./screenshots/29.png) | [![](./screenshots/30.png)](./screenshots/30.png) |

</details>

<details>
<summary><b>6. Kali Linux — Xfce desktop</b> (images 31–32)</summary>
<br>

Successfully logged in — Kali's Xfce desktop, install complete.

| | |
|---|---|
| [![](./screenshots/31.png)](./screenshots/31.png) | [![](./screenshots/32.png)](./screenshots/32.png) |

</details>

<details>
<summary><b>7. Metasploitable2 — importing the pre-built VM</b> (images 33–35)</summary>
<br>

Creating the Metasploitable2 VM and attaching the downloaded `Metasploitable.vmdk` as an existing disk instead of creating a new one.

| | | |
|---|---|---|
| [![](./screenshots/33.png)](./screenshots/33.png) | [![](./screenshots/34.png)](./screenshots/34.png) | [![](./screenshots/35.png)](./screenshots/35.png) |

</details>

<details>
<summary><b>8. Metasploitable2 — hard disk configuration</b> (image 36)</summary>
<br>

[![](./screenshots/36.png)](./screenshots/36.png)

</details>

<details>
<summary><b>9. Metasploitable2 — VM ready</b> (image 37)</summary>
<br>

[![](./screenshots/37.png)](./screenshots/37.png)

</details>

<details>
<summary><b>10. Network isolation & connectivity troubleshooting</b> (images 38–46)</summary>
<br>

Setting both VMs' network adapters to the same Internal Network (`intnet`), discovering there's no DHCP on an Internal Network, assigning a static IP to Metasploitable2 with `ifconfig`, then hitting "Network is unreachable" on Kali because NetworkManager kept reverting a plain `ip addr add` — fixed by configuring the static IP through `nmcli connection modify` on the actual connection profile instead. Ends with a clean 0%-packet-loss ping between the two VMs.

| | | |
|---|---|---|
| [![](./screenshots/38.png)](./screenshots/38.png) | [![](./screenshots/39.png)](./screenshots/39.png) | [![](./screenshots/40.png)](./screenshots/40.png) |
| [![](./screenshots/41.png)](./screenshots/41.png) | [![](./screenshots/42.png)](./screenshots/42.png) | [![](./screenshots/43.png)](./screenshots/43.png) |
| [![](./screenshots/44.png)](./screenshots/44.png) | [![](./screenshots/45.png)](./screenshots/45.png) | [![](./screenshots/46.png)](./screenshots/46.png) |

</details>

## Key Learnings

- VirtualBox's **Internal Network** mode is the right choice for isolating intentionally vulnerable machines, but it ships with no DHCP — static IPs (or a custom DHCP server) are required.
- On modern Debian/Kali installs, NetworkManager owns the interface; low-level commands like `ip addr add` get silently reverted. Static configuration has to go through `nmcli connection modify` on the actual connection profile so it persists and doesn't fight with NetworkManager.
- Guided partitioning in the Debian/Kali installer must explicitly select a partitioning **scheme** (e.g. "All files in one partition") — skipping that step leaves no root filesystem defined and the installer errors out.

## Next

[Project 2: Linux & CLI Practice](../project-02-linux-cli-practice) — TryHackMe's Linux Fundamentals and Networking Fundamentals rooms.
