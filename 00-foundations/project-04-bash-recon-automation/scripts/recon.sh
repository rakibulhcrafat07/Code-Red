#!/usr/bin/env bash
#
# recon.sh — a small Bash recon pipeline (Code-Red / 00-Foundations / Project 04)
#
# Chains existing tools into a repeatable workflow:
#   Phase 1  host discovery   (who is alive?)
#   Phase 2  port scan        (what is open?)
#   Phase 3  service enum      (what is running?)
#   Phase 4  summarize         (one greppable CSV)
#
# The port-scan stage can use nmap OR Project 03's own port_scanner.py.
#
# Usage:   ./recon.sh <subnet-or-host>        e.g.  ./recon.sh 192.168.100.0/24
#
# WARNING: run only against hosts you own, your isolated lab, or authorized targets.
# ---------------------------------------------------------------------------------

set -u                                   # error on unset variables

TARGET="${1:-}"
OUTDIR="results"
HOSTS_FILE="live_hosts.txt"
SUMMARY="recon_summary.csv"

usage() {
    echo "Usage: $0 <subnet-or-host>    e.g. $0 192.168.100.0/24"
    exit 1
}
[ -z "$TARGET" ] && usage

# small helper so every stage prints a consistent, greppable banner
log() { echo "[*] $*"; }

# --- Phase 1: host discovery ---------------------------------------------------
phase_discovery() {
    log "Phase 1 — host discovery on $TARGET"
    nmap -sn "$TARGET" -oG - 2>/dev/null \
        | awk '/Up$/{print $2}' \
        | sort -u > "$HOSTS_FILE"
    log "$(wc -l < "$HOSTS_FILE") live host(s) -> $HOSTS_FILE"
}

# --- Phase 2: port scan --------------------------------------------------------
phase_portscan() {
    log "Phase 2 — port scan"
    while read -r ip; do
        [ -z "$ip" ] && continue
        mkdir -p "$OUTDIR/$ip"
        log "  scanning $ip"
        nmap -p- --min-rate 1000 -oN "$OUTDIR/$ip/ports.txt" "$ip" >/dev/null 2>&1
        # --- or use the Project 03 tool instead: ---
        # python3 ../project-03-port-scanner/port_scanner.py "$ip" \
        #     -p 1-10000 -o "$OUTDIR/$ip/ports.json" >/dev/null 2>&1
    done < "$HOSTS_FILE"
}

# --- Phase 3: service / version enumeration ------------------------------------
phase_enum() {
    log "Phase 3 — service enumeration"
    while read -r ip; do
        [ -z "$ip" ] && continue
        open_ports=$(grep -oP '^\d+(?=/tcp\s+open)' "$OUTDIR/$ip/ports.txt" 2>/dev/null | paste -sd,)
        [ -z "$open_ports" ] && { log "  $ip: no open ports"; continue; }
        log "  $ip: enumerating $open_ports"
        nmap -sV -p "$open_ports" -oN "$OUTDIR/$ip/services.txt" "$ip" >/dev/null 2>&1
    done < "$HOSTS_FILE"
}

# --- Phase 4: summarize --------------------------------------------------------
phase_summary() {
    log "Phase 4 — building $SUMMARY"
    {
        echo "host,port,service,version"
        for dir in "$OUTDIR"/*/; do
            [ -d "$dir" ] || continue
            ip=$(basename "$dir")
            [ -f "$dir/services.txt" ] || continue
            awk -v ip="$ip" '/open/{print ip","$1","$3","substr($0, index($0,$4))}' \
                "$dir/services.txt"
        done
    } > "$SUMMARY"
    log "done -> $SUMMARY"
}

# --- run the pipeline ----------------------------------------------------------
mkdir -p "$OUTDIR"
phase_discovery
phase_portscan
phase_enum
phase_summary
log "Recon complete. See $OUTDIR/ and $SUMMARY"
