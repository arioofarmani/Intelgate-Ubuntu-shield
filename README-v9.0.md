# IntelShield v9.0

**System Immutability, Network Filtering, and SIEM-Compliant State Export for Ubuntu servers.**

IntelShield v9.0 is a production-grade Bash security suite for **Ubuntu 22.04 / 24.04 LTS** servers. It implements a global OS immutability framework, high-performance nftables network filtering with CrowdSec/Suricata 8 IPS harmonization, and RFC 8259-compliant JSON state export for SIEM ingestion.

> **Use only on servers you own or are authorized to administer.** IntelShield makes real changes to filesystem immutability, firewall rules, and kernel parameters. Always test on a throwaway VM first.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive TUI](#interactive-tui)
  - [CLI Flags](#cli-flags)
- [System Immutability Engine](#system-immutability-engine)
- [nftables Network Pipeline](#nftables-network-pipeline)
- [SIEM State Export](#siem-state-export)
- [Atomic Rollbacks](#atomic-rollbacks)
- [Files & Locations](#files--locations)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

---

## Features

| Module | Description |
|---|---|
| **System Immutability** | Global On/Off toggle for `chattr +i` on `/bin`, `/sbin`, `/usr`, `/boot`, and critical `/etc` files. State persisted for crash recovery. |
| **nftables Pipeline** | Priority-orchestrated chains: CrowdSec at priority 0, Suricata 8 at priority 10. UFW coexistence via explicit hook priorities. |
| **Suricata 8 Firewall Mode** | Deterministic packet pipeline with default-drop policy. Explicit action scopes (`accept:packet`, `drop:flow`) and rule hooks. |
| **SIEM State Export** | Native `jq -n` serialization to RFC 8259 JSON. Ready for Wazuh, Elastic, or any JSON-capable SIEM. |
| **Atomic Rollbacks** | `restart_or_rollback` accepts callback function arguments directly. No global state dependencies. |
| **CLI & TUI** | Full headless operation via flags, or interactive high-contrast TUI menu. |

---

## Architecture

```
         IntelShield v9.0
              │
    ┌─────────┼─────────┐
    │         │         │
    ▼         ▼         ▼
 Immutability  Network   SIEM
 Engine       Filtering  Export
    │         │         │
    ▼         ▼         ▼
 chattr +i   nftables   jq -n
 recursive   priority   RFC 8259
 lock/unlock orchestration JSON
              │
    ┌─────────┼─────────┐
    │         │         │
    ▼         ▼         ▼
 CrowdSec   Suricata   UFW
 priority 0 priority 10 coexist
```

### nftables Priority Orchestration

| Component | Priority | Role |
|---|---|---|
| UFW | 0 (default) | Base allow/deny rules |
| CrowdSec bouncer | 0 (explicit) | IP reputation drops |
| Suricata FW mode | 10 | Deep inspection, default-drop |
| Suricata IPS | 100 | Legacy inline NFQUEUE |

IntelShield's chains run at explicit priorities that process packets **after** UFW's rules, ensuring UFW allow/deny decisions are honored before deep inspection.

---

## Requirements

- **OS:** Ubuntu 22.04 or 24.04 LTS
- **Privileges:** root (the script warns if run without root)
- **Dependencies:** `jq`, `nftables`, `chattr`, `systemctl`, `ss`, `awk`, `sed`, `grep`
- **Optional:** CrowdSec engine + bouncer, Suricata 8+ (for IPS/Firewall Mode)

All dependencies are verified at startup via `--check-deps`.

---

## Installation

```bash
# Download
wget -O IntelShield.sh https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield-v9.0.sh

# Inspect
less IntelShield.sh

# Make executable and run
chmod +x IntelShield.sh
sudo ./IntelShield.sh
```

---

## Usage

### Interactive TUI

Run with no arguments for the menu:

```
╔══════════════════════════════════════════════════════════════╗
║  IntelShield v9.0 — System Immutability · Network Filtering ║
╚══════════════════════════════════════════════════════════════╝

  Status:  Lock=UNLOCKED  |  Kernel=6.5.0-44  |  2026-07-11 02:30:00

  Options:
    1  Toggle Immutability Switch  [UNLOCKED]
    2  Sync Firewall Rules & IPS Pipelines
    3  Trigger System Diagnostic & SIEM Export
    4  View Current State (JSON)
    5  Exit
```

### CLI Flags

```bash
# Immutability
sudo ./IntelShield.sh --lock              # Lock system (chattr +i)
sudo ./IntelShield.sh --unlock            # Unlock system (chattr -i)
sudo ./IntelShield.sh --status            # Show LOCKED/UNLOCKED + count

# Network & IPS
sudo ./IntelShield.sh --sync-fw           # Deploy/sync nftables pipeline
sudo ./IntelShield.sh --fw-enable         # Enable Suricata 8 Firewall Mode
sudo ./IntelShield.sh --fw-disable        # Disable Firewall Mode (revert to IDS)
sudo ./IntelShield.sh --fw-teardown       # Remove all nftables rules

# State & SIEM
sudo ./IntelShield.sh --export-state      # Export RFC 8259 JSON for SIEM
sudo ./IntelShield.sh --write-state       # Update state database

# System
sudo ./IntelShield.sh --check-deps        # Verify dependencies
sudo ./IntelShield.sh --help              # Show help
```

---

## System Immutability Engine

The immutability engine applies `chattr +i` (the Linux immutable flag) to critical system directories and files, preventing any modification — even by root — until explicitly unlocked.

### What Gets Locked

| Path | Purpose |
|---|---|
| `/bin` | Core system binaries |
| `/sbin` | System administration binaries |
| `/usr` | User programs and libraries |
| `/boot` | Kernel and bootloader files |
| `/etc/passwd` | User account database |
| `/etc/shadow` | Password hashes |
| `/etc/fstab` | Filesystem mount table |
| `/etc/group` | Group database |
| `/etc/sudoers` | Sudo configuration |

### What Never Gets Locked

| Path | Reason |
|---|---|
| `/var/log` | Logging must continue |
| `/var/run`, `/run` | Runtime state, PID files |
| `/var/tmp`, `/tmp` | Temporary files |
| `/proc`, `/sys`, `/dev` | Virtual filesystems |
| `/etc/resolv.conf` | DNS resolution |
| `/etc/hostname` | Network identity |
| `/var/lib/intelshield` | IntelShield's own state |

### Workflow

1. **Lock** (`--lock`): applies `chattr +i` recursively, skips excluded paths
2. **Work**: system is hardened against tampering
3. **Update** (`--unlock`): removes flags before `apt-get` or config changes
4. **Re-lock** (`--lock`): re-applies after updates complete

State is persisted to `/var/lib/intelshield/lock-state` for crash recovery.

---

## nftables Network Pipeline

IntelShield deploys a single nftables table (`inet intelshield_pipeline`) with:

- **SSH rate limiting** via dynamic sets (5/min burst, 15/min hard limit)
- **Established connection fast-path** (skips deep inspection)
- **ICMP rate limiting** (path MTU, diagnostics)
- **Suricata NFQUEUE integration** (mode-dependent: fw, ips, or off)

### UFW Coexistence

UFW uses its own nftables chains at priority 0. IntelShield's chains use explicit priorities (10 for Suricata, 100 for legacy IPS) that process packets **after** UFW. This means:

- UFW allow/deny rules are evaluated first
- IntelShield deep inspection runs on survivors
- No chain conflicts or rule ordering issues

### Suricata 8 Firewall Mode

When enabled (`--fw-enable`), the pipeline uses Suricata 8's deterministic packet pipeline with default-drop policy:

- Every packet NOT explicitly accepted by a rule is dropped
- Action scopes: `accept:packet`, `accept:flow`, `drop:flow`
- Rule hooks: `packet:filter` (fast path) + `app:filter` (deep inspection)
- Fail-open: if Suricata stops, traffic flows (no outage)

---

## SIEM State Export

IntelShield builds its state database entirely via `jq -n`, guaranteeing RFC 8259 compliance:

```bash
sudo ./IntelShield.sh --export-state
# Writes to: /var/lib/intelshield/siem-export-20260711_023000.json
```

### JSON Structure

```json
{
  "version": "9.0",
  "timestamp": "2026-07-11T02:30:00Z",
  "host": {
    "hostname": "server01",
    "kernel": "6.5.0-44-generic",
    "os": "Ubuntu 24.04 LTS",
    "nic": "eth0",
    "public_ip": "203.0.113.5",
    "ssh_port": 22
  },
  "immutability": {
    "state": "LOCKED",
    "immutable_count": 1847
  },
  "services": {
    "crowdsec": "active",
    "crowdsec_bouncer": "active",
    "suricata": "active",
    "suricata_mode": "ips",
    "suricata_fw_mode": "off",
    "suricata_mutex": "none"
  },
  "resources": {
    "memory_mb": 3932,
    "disk_free_mb": 15234,
    "load_avg": 0.42
  }
}
```

The output is ready for direct ingestion by Wazuh logcollector, Elastic ingest pipelines, or any JSON-capable SIEM.

---

## Atomic Rollbacks

`restart_or_rollback` accepts the target unit and rollback callback directly:

```bash
restart_or_rollback "suricata" "rollback_suricata_ips"
```

**Contract:**
1. Restart the unit
2. Wait 2 seconds for stabilization
3. Check if the unit is active
4. If active: return 0
5. If NOT active: call the rollback callback, restart again, return 1

No global variables, no hidden dependencies — the callback is passed as an argument.

---

## Files & Locations

| Path | Purpose |
|---|---|
| `/usr/local/sbin/intelshield` | Canonical installed copy |
| `/var/lib/intelshield/state.json` | Machine-readable state (RFC 8259 JSON) |
| `/var/lib/intelshield/lock-state` | Immutability state: `LOCKED` or `UNLOCKED` |
| `/var/lib/intelshield/siem-export-*.json` | SIEM export files |
| `/var/log/intelshield.log` | Operations log |
| `/etc/nftables.d/` | nftables hook files |

---

## FAQ

**Will locking the system break `apt-get`?**
Yes — `/usr` and `/boot` are immutable. You must unlock (`--unlock`) before running `apt-get`, then re-lock (`--lock`) after.

**Will locking break running services?**
No — running services use already-loaded binaries in memory. Only attempts to modify files on disk will fail.

**Does the nftables pipeline conflict with UFW?**
No — IntelShield uses explicit hook priorities that process packets after UFW's chains. UFW allow/deny rules are honored first.

**What happens if Suricata crashes in Firewall Mode?**
Fail-open: the nftables queue uses `flags bypass`, so if nothing is reading the queue, the kernel accepts the traffic. No outage, no lockout.

**How do I export state for my SIEM?**
Run `--export-state`. The JSON output at `/var/lib/intelshield/siem-export-*.json` is ready for Wazuh, Elastic, or any JSON ingest pipeline.

---

## Disclaimer

IntelShield is provided **as-is, without warranty of any kind**. It modifies filesystem immutability flags, firewall rules, and kernel parameters. You are responsible for testing it in a non-production environment first. The authors are not liable for lockouts, downtime, or data loss.

This is a **defensive** hardening tool. Use it only on infrastructure you own or are explicitly permitted to administer.

---

<p align="center"><em>IntelShield v9.0 — immutable systems, zero trust, full visibility.</em></p>
