# IntelShield v9.5

**Unified hardening, forensics, SIEM/XDR, and performance tuning for Ubuntu servers -- in a single Bash script with a full text UI.**

IntelShield v9.5 is a complete production-grade security suite for **Ubuntu 22.04 / 24.04 LTS** servers. It merges the v9.0 architectural core (system immutability, nftables pipeline, RFC-8259 state export, atomic rollbacks) with the full v8.9 feature set (ClamAV, CrowdSec, Suricata, Wazuh, forensics, backups, maintenance engine).

> **Use only on servers you own or are authorized to administer.** IntelShield makes real changes to firewall rules, SSH, kernel parameters, filesystem immutability, and system services. Always test on a throwaway VM first and keep console/out-of-band access available.

---

## Table of Contents

- [What's New in v9.5](#whats-new-in-v95)
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
- [Suricata: IDS, IPS & Firewall Mode](#suricata-ids-ips--firewall-mode)
- [CrowdSec Integration](#crowdsec-integration)
- [ClamAV Antivirus](#clamav-antivirus)
- [Wazuh SIEM / XDR](#wazuh-siem--xdr)
- [Backup & Restore](#backup--restore)
- [Maintenance Engine](#maintenance-engine)
- [Files & Locations](#files--locations)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)

---

## What's New in v9.5

| Feature | Description |
|---|---|
| **System Immutability** | Global On/Off toggle for `chattr +i` on `/bin`, `/sbin`, `/usr`, `/boot`, and critical `/etc` files. Bulk find+xargs for instant execution. |
| **RFC-8259 State JSON** | Native `jq -n` serialization replaces raw string building. Guaranteed valid JSON for Wazuh/Elastic ingestion. |
| **nftables Pipeline** | Priority-orchestrated chains: CrowdSec @priority 0, Suricata @priority 10. UFW coexistence via explicit hook priorities. |
| **UFW Survivability** | Systemd drop-in auto-resyncs nftables pipeline after any UFW reload/restart. |
| **Atomic Rollbacks** | `restart_or_rollback(unit, callback_fn)` -- callback passed as argument, no global state. |
| **x-ui/Xray Removed** | Global immutability replaces application-level sandboxing. All sandbox code stripped. |
| **Performance Fix** | Immutability lock/unlock uses `find + xargs -0` (instant on 100k+ files, no subshell spawning). |

---

## Features

| Domain | What IntelShield manages |
|---|---|
| **Immutability** | Global chattr +i toggle for system directories and critical files. State persisted for crash recovery. |
| **Firewall** | UFW with anti-lockout defaults, SSH brute-force damping, per-rule allow/deny builder, safe re-baseline. |
| **Intrusion prevention** | CrowdSec engine + nftables firewall bouncer, admin allowlist, console enrollment, decision management. |
| **IDS / IPS / Firewall** | Suricata as passive IDS **or** inline IPS (NFQUEUE) **or** Suricata 8 Firewall Mode (default-drop), rule-source/category selection, drop-policy control, JA3/JA4 & encrypted-metadata monitoring. |
| **Antivirus** | ClamAV with quarantine vault (mode/owner-preserving restore), scheduled scans, on-access toggle, DLP/PUA hardening. |
| **File integrity & audit** | AIDE baseline, auditd rules (32-bit syscall coverage), AppArmor. |
| **Rootkit detection** | rkhunter + chkrootkit with safe-area whitelisting, manual protected-path quarantine, scheduled scans. |
| **Kernel & network** | sysctl hardening, BBR + queue tuning, anti-spoofing, CPU microcode & platform (Secure Boot / TPM) audit. |
| **Forensics** | One-command "forensic bundle" -- collects CrowdSec/Suricata/ClamAV/system/kernel/process state into one AI-ready archive. |
| **Backup / restore** | Config snapshots (tar), verified archives, pruning, one-click rollback, weekly cron. |
| **SIEM / XDR** | Wazuh agent integration: log forwarding, FIM, command collection, safe active response. |
| **Performance** | CPU governor + EPP profiles, latency/throughput sysctl sets, live jitter dashboard. |
| **Update center** | Package/full upgrade (never a release upgrade), firmware (fwupd) + driver updates, auto-update with automatic 01:11 reboot. |
| **Maintenance engine** | Opt-in cron: unattended OS upgrades, sequential component updates, secure script self-update -- restarts only on verified success. |
| **Live console** | On by default -- every command and its real output streams to your terminal (still logged). |
| **State export** | RFC 8259 JSON state database for SIEM ingestion (Wazuh, Elastic, any JSON-capable pipeline). |

---

## Architecture

```
                 Internet
                    |
        +-----------v-------------+
        |  UFW (deny-in default)  |  <- anti-lockout: SSH limit + 443 tcp/udp
        +-------------------------+
        |  CrowdSec bouncer (nft)  |  <- drops known-bad IPs (reputation)  [priority 0]
        +-------------------------+
        |  Suricata FW/IPS (nftq)  |  <- deep inspection, default-drop     [priority 10]
        +-------------------------+
        |  System Immutability     |  <- chattr +i on /bin, /sbin, /usr, /boot
        +-------------------------+
        |  ClamAV / Wazuh / AIDE   |  <- AV, SIEM, file integrity
        +-------------------------+
   Suricata eve.json ------> CrowdSec (IDS->IPS feedback loop)
   All logs/state -----------> Wazuh agent -------> your Wazuh manager
   state.json (jq -n) -------> SIEM ingest pipeline
```

### nftables Priority Orchestration

| Component | Priority | Role |
|---|---|---|
| UFW | 0 (default) | Base allow/deny rules |
| CrowdSec bouncer | 0 (explicit) | IP reputation drops |
| Suricata FW mode | 10 | Deep inspection, default-drop |
| Suricata IPS | 100 | Legacy inline NFQUEUE |

UFW coexistence: IntelShield uses explicit hook priorities that process packets **after** UFW's chains. A systemd drop-in (`ufw.service.d/99-intelshield-resync.conf`) automatically re-syncs the nftables pipeline after any UFW reload.

---

## Requirements

- **OS:** Ubuntu 22.04 or 24.04 LTS
- **Privileges:** root (the script auto-elevates via sudo)
- **Dependencies:** `jq`, `nftables`, `chattr`, `systemctl`, `ss`, `awk`, `sed`, `grep`
- **Optional:** CrowdSec engine + bouncer, Suricata 8+ (for IPS/Firewall Mode), ClamAV, Wazuh agent

---

## Installation

```bash
# Download
wget -O IntelShield.sh https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield-v9.5.sh

# Inspect before running (recommended for any root script)
less IntelShield.sh

# Make executable and launch
chmod +x IntelShield.sh
sudo ./IntelShield.sh

# On first launch, installs canonical copy at /usr/local/sbin/intelshield
# After that:
sudo intelshield
```

---

## Usage

### Interactive TUI

Run with no arguments for the full whiptail menu:

```
 1  Guided automated hardening run
 2  Select individual modules
 3  Profiles / production modes
 4  Preflight risk engine
 5  State database view
 6  CrowdSec management
 7  UFW firewall management
 8  ClamAV antivirus management
 9  Suricata IDS/IPS intelligence
10  Anti-rootkit defense
11  Wazuh SIEM / XDR integration
12  Advanced forensics engine
13  Performance / kernel tuning
14  Backup / restore snapshots
15  Status / diagnostics
16  View IntelShield log
17  Component control center (enable/disable modules)
 U  Update center (system / firmware / drivers / auto-update)
 M  Maintenance engine (scheduled updates + self-update)
 I  System immutability control [LOCKED/UNLOCKED]
 F  Firewall & IPS sync (nftables pipeline)
 L  Live console output: ON/OFF
18  Uninstall / revert safely
19  Exit
```

### CLI Flags

```bash
# Immutability
sudo intelshield --lock              # Lock system (chattr +i)
sudo intelshield --unlock            # Unlock system (chattr -i)

# Network & IPS
sudo intelshield --sync-fw           # Deploy/sync nftables pipeline
sudo intelshield --suricata-fw on    # Enable Suricata 8 Firewall Mode

# State & SIEM
sudo intelshield --export-state      # Export RFC 8259 JSON for SIEM

# System
sudo intelshield --update safe       # Package upgrade (no removals)
sudo intelshield --auto-update on    # Auto-update + 01:11 reboot
sudo intelshield --maintain all      # Full maintenance (cron-driven)
sudo intelshield --backup            # Create config snapshot
sudo intelshield --self-update       # Check GitHub for newer version
sudo intelshield --preflight         # Risk report
sudo intelshield --state             # Refresh + print state.json
```

---

## System Immutability Engine

The immutability engine applies `chattr +i` (the Linux immutable flag) to critical system directories and files, preventing any modification -- even by root -- until explicitly unlocked.

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
| `/etc/group`, `/etc/gshadow` | Group databases |
| `/etc/sudoers` | Sudo configuration |

### What Never Gets Locked

| Path | Reason |
|---|---|
| `/var/log`, `/var/run`, `/run` | Logging and runtime must continue |
| `/var/tmp`, `/tmp` | Temporary files |
| `/proc`, `/sys`, `/dev` | Virtual filesystems |
| `/etc/resolv.conf`, `/etc/hostname` | Network identity |

### Workflow

1. **Lock** (`--lock` or menu `I`): applies `chattr +i` recursively via bulk find+xargs
2. **Work**: system is hardened against tampering
3. **Update** (`--unlock`): removes flags before `apt-get` or config changes
4. **Re-lock** (`--lock`): re-applies after updates

State is persisted to `/var/lib/intelshield/lock-state` for crash recovery.

---

## nftables Network Pipeline

IntelShield deploys a single nftables table (`inet intelshield_pipeline`) with:

- **SSH rate limiting** via dynamic sets (5/min burst, 15/min hard limit)
- **Established connection fast-path** (skips deep inspection)
- **ICMP rate limiting** (path MTU, diagnostics)
- **Suricata NFQUEUE integration** (mode-dependent: fw, ips, or off)

### UFW Survivability

UFW reloads can flush custom nftables chains. IntelShield installs a systemd drop-in (`ufw.service.d/99-intelshield-resync.conf`) that calls `--sync-fw` after any UFW state change, automatically restoring the Suricata/CrowdSec priority pipeline.

---

## SIEM State Export

IntelShield builds its state database entirely via `jq -n`, guaranteeing RFC 8259 compliance:

```bash
sudo intelshield --export-state
# Writes to: /var/lib/intelshield/siem-export-<timestamp>.json
```

The JSON includes: host info, security posture, immutability state, all service statuses, resource metrics, and timestamps -- ready for Wazuh, Elastic, or any JSON-capable SIEM.

---

## Atomic Rollbacks

`restart_or_rollback` accepts the target unit and rollback callback directly:

```bash
restart_or_rollback "suricata" "rollback_suricata_ips"
```

**Contract:** restart -> wait 2s -> check active -> if down: call rollback -> restart again -> return 1 if still down.

No global variables, no hidden dependencies.

---

## Suricata: IDS, IPS & Firewall Mode

Three operational modes:

- **IDS (default):** passive monitoring, alerts only
- **IPS (inline):** NFQUEUE with fail-open, SSH excluded, runs after CrowdSec
- **Suricata 8 Firewall Mode:** deterministic packet pipeline with default-drop policy

Safety rails: fail-open (traffic flows if Suricata crashes), SSH exclusion, mutex toggle prevents CrowdSec/Suricata conflicts.

---

## CrowdSec Integration

CrowdSec provides crowd-sourced IP reputation. The nftables bouncer drops known-bad IPs at priority 0 (edge) before Suricata inspects survivors at priority 10 (deep inspection).

---

## ClamAV Antivirus

Full ClamAV suite: install, full/smart scans, quarantine vault with mode/owner-preserving restore, on-access toggle, DLP/PUA hardening, scheduled scans (daily/weekly), signature updates.

---

## Wazuh SIEM / XDR

Agent-only integration: log forwarding (IntelShield, Suricata, CrowdSec, UFW, auth, audit, ClamAV), FIM, command/status collection, safe active response (evidence-only).

---

## Backup & Restore

Config snapshots via tar, verified archives, pruning (keep last 10), one-click rollback, weekly cron. Snapshot before restores, profile switches, and Wazuh/uninstall operations.

---

## Maintenance Engine

Opt-in cron (02:15 OS, 03:15 components, 04:30 Sun self-update). Every step's real exit code is captured. Services restart only after verified success. Atomic rollbacks on failure. Dedicated audit trail.

---

## Files & Locations

| Path | Purpose |
|---|---|
| `/usr/local/sbin/intelshield` | Canonical installed copy |
| `/var/lib/intelshield/state.json` | Machine-readable state (RFC 8259 JSON) |
| `/var/lib/intelshield/lock-state` | Immutability state: LOCKED or UNLOCKED |
| `/var/lib/intelshield/siem-export-*.json` | SIEM export files |
| `/var/log/intelshield.log` | Operations log |
| `/var/log/intelshield-maintenance.log` | Maintenance engine audit trail |
| `/etc/nftables.d/` | nftables hook files |
| `/etc/suricata/intelshield/*.yaml` | Suricata config override drop-ins |

---

## FAQ

**Will locking the system break `apt-get`?**
Yes -- `/usr` and `/boot` are immutable. You must unlock (`--unlock`) before running apt, then re-lock after.

**Does the nftables pipeline conflict with UFW?**
No -- IntelShield uses explicit hook priorities that process packets after UFW's chains. A systemd drop-in auto-resyncs after UFW reloads.

**What happens if Suricata crashes in Firewall Mode?**
Fail-open: the nftables queue uses `flags bypass`, so if nothing reads the queue, the kernel accepts traffic. No outage.

**Can I run just one component?**
Yes -- use **Select individual modules (2)** or the **Component control center (17)**.

---

## Disclaimer

IntelShield is provided **as-is, without warranty of any kind**. It modifies filesystem immutability flags, firewall rules, SSH, kernel parameters, and system services. You are responsible for testing it in a non-production environment first. The authors are not liable for lockouts, downtime, or data loss.

This is a **defensive** hardening tool. Use it only on infrastructure you own or are explicitly permitted to administer.

---

<p align="center"><em>IntelShield v9.5 -- immutable systems, zero trust, full visibility, complete hardening.</em></p>
