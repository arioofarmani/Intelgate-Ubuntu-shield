<div align="center">

# IntelShield v9.9

### Unified Server Hardening . Forensics . SIEM/XDR . Performance . OS-Aware Immutability . Audit-Hardened

**Production-grade security hardening for Ubuntu 22.04 / 24.04 LTS servers**

[![Version](https://img.shields.io/badge/version-9.9-blue.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Ubuntu%2022.04%20%7C%2024.04-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](#)
[![Audit](https://img.shields.io/badge/audit-Round%202%20resolved-red.svg)](#audit-hardening-round-2)
[![Functions](https://img.shields.io/badge/functions-260%2B-purple.svg)](#)

---

*One script. One execution. A fully hardened, forensics-ready, SIEM-integrated server.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [What's New in v9.9](#whats-new-in-v99)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Hardening Profiles](#hardening-profiles)
- [Immutability Engine](#immutability-engine)
- [Security Stack](#security-stack)
- [Forensics and SIEM](#forensics-and-siem)
- [Update and Maintenance](#update-and-maintenance)
- [CLI Reference](#cli-reference)
- [File Layout](#file-layout)
- [Audit Hardening (Round 2)](#audit-hardening-round-2)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

IntelShield is a **single-file, zero-dependency** bash script that transforms a vanilla Ubuntu server into a production-hardened, forensics-ready, SIEM-integrated node. It orchestrates **21 security modules**, **6 deployment profiles**, **14 manageable components**, and **260+ functions** — all from a unified TUI or headless CLI.

### What It Does

| Layer | Capability |
|-------|-----------|
| **Kernel Hardening** | Sysctl tuning (network performance, security, BBR congestion control) |
| **Firewall** | UFW baseline + nftables pipeline with CrowdSec/Suricata priority orchestration |
| **IPS/IDS** | CrowdSec (behavioral IPS) + Suricata (signature IDS/IPS) with automated rule management |
| **Antivirus** | ClamAV with on-access scanning, quarantine vault, and DLP detection |
| **Integrity** | File integrity monitoring (AIDE), anti-rootkit (rkhunter + chkrootkit), auditd |
| **Immutability** | OS-aware `chattr +i` on critical system binaries and config files |
| **SIEM/XDR** | Wazuh agent integration with FIM, log forwarding, and safe active response |
| **Forensics** | Full DFIR bundle collection, live packet capture, connection tracing |
| **Performance** | CPU governor management, memory/disk tuning, high-throughput profiles |
| **Self-Healing** | Atomic restart with automatic rollback, Suricata rule self-healing |
| **Maintenance** | Automated OS updates, component sync, script self-update with integrity verification |

---

## What's New in v9.9

IntelShield v9.9 is the **audit-hardened** release, addressing all findings from the Round 2 blind-spot security audit. Every fix has been verified with `bash -n` syntax validation.

### Critical Fixes

| ID | Finding | Fix |
|----|---------|-----|
| **C2-1** | Self-update permanent no-op on locked hosts | `self_update_check()` now calls `ensure_unlocked_for_apt()` before staging; `/usr/local/sbin` added to `IMMUTABLE_EXCLUDES` |
| **C2-2** | apt/immutability interlock covered only 3 of ~30 call sites | Created `apt_do()` — **single entry point** for ALL apt operations, owning unlock/relock + dpkg lock timeout |
| **C2-3** | `apt_get()` wrapper was dead code | Replaced with `apt_do()`; all ~30 apt call sites now routed through it |

### High Fixes

| ID | Finding | Fix |
|----|---------|-----|
| **H2-4** | IPS drop-in broke on Suricata 6/7 archive builds | Drop-in now detects engine version and sets correct `Type=` (forking vs notify) + `-D` flag + `TimeoutStartSec=180` |
| **H2-8** | SSH socket-activation unhandled on Ubuntu 24.04 | Detects `ssh.socket`, writes `ListenStream` drop-in, verifies listener with `ss -tlnp` |
| **H2-11** | ClamAV on-access OOM on 1 GB VPS | Gated on `MemTotal >= 2048 MB`; added `OnAccessMaxFileSize`, `OnAccessDisableDDD`, `MaxThreads`, `MaxQueue` |
| **H2-15** | No global mutex for TUI/cron/timers | Added `global_lock()` flock function for serializing concurrent access |
| **H2-16** | `suricata_update_rules` concurrent mutation | Wrapped in dedicated `suri_rules_lock()` flock |

### Medium Fixes

| ID | Finding | Fix |
|----|---------|-----|
| **M2-5** | Missing HUP trap | Added `trap 'cleanup; exit 129' HUP` — most common SSH abnormal termination |
| **M2-6** | `valid_ip()` accepts multiple `::` | Now rejects addresses with more than one `::` (RFC 4291 compliance) |
| **M2-9** | Log newline injection | `log()` strips control characters (`tr -d '\r' | sed 's/[[:cntrl:]]/?/g'`) |
| **M2-10** | SSH port change never re-syncs nft | Port change now removes old UFW rule and calls `nft_sync()` |
| **M2-12** | Low-RAM tuning missing memcaps | Sets explicit memcaps: flow=32m, stream=32m, reassembly=64m, defrag=32m |
| **M2-13** | IPS no conntrack fast-path | Added `ct state established,related accept` before queue rule |
| **M2-14** | `tcp_bbr` written without verification | Now checks `/proc/sys/net/ipv4/tcp_available_congestion_control` before writing |
| **M2-17** | Non-atomic lock-state file writes | Added `atomic_state_write()` for `LOCK_STATE_FILE`, `SURICATA_MUTEX_FILE`, `PROFILE_FILE` |
| **M2-18** | `restart_or_rollback` unbounded stall | IPS drop-in now sets `TimeoutStartSec=180` |
| **M2-19** | `deploy_nft_pipeline` decorative no-op | Simplified; removed misleading case statement, added clear documentation |

### Low/Info Fixes

- Dead code removed: `_lock_path()`, `_unlock_path()`, `_is_excluded()`, duplicate `SURICATA_CROWDSEC_PRIORITY`
- `install_self()` callers now propagate exit code with `|| self="$0"` fallback
- `/usr/local/sbin` added to `IMMUTABLE_EXCLUDES` (tool never locks its own binary)

---

## Architecture

```
+-------------------------------------------------------------------+
|                      IntelShield v9.9                              |
+------------+------------+------------+------------+----------------+
|   Kernel   |  Network   |  Service   |  Forensic  |  Maintenance   |
| Hardening  |  Firewall  | Enforcem.  |   Engine   |    Engine      |
+------------+------------+------------+------------+----------------+
|   sysctl   |    UFW     | CrowdSec   |   Bundle   |  Auto-update   |
|   BBR      | nftables   | Suricata   |  Capture   |  Self-update   |
|  Security  |  iptables  |  ClamAV    |   Triage   |  Cron jobs     |
|   Perf     |  IPS/FW    |  auditd    |  SIEM exp  | Log rotation   |
+------------+------------+------------+------------+----------------+
|           Immutability Engine (chattr +i)                          |
|   OS-aware exclusions . Filesystem-type filtering                  |
|   /boot/efi . /snap . /netplan . /systemd/network guards          |
|   /usr/local/sbin exclusion (self-update path)                     |
+-------------------------------------------------------------------+
|         State Database (JSON) . Preflight Risk Engine              |
|    Atomic state writes . Global flock . Component Control Center   |
+-------------------------------------------------------------------+
```

### nftables Priority Pipeline

```
Traffic -> [CrowdSec Bouncer]   priority 0   (IP reputation, cheap drops)
         -> [Suricata FW Mode]  priority 10  (deep packet inspection)
         -> [Suricata IPS]      priority 100 (NFQUEUE with conntrack fast-path)
         -> Kernel
```

### Concurrency Model (v9.9)

```
+------------------+     +------------------+     +------------------+
|   TUI Session    |     |  Cron Jobs       |     |  Systemd Timers  |
|  (interactive)   |     |  (02:15/03:15)   |     |  (health/scan)   |
+--------+---------+     +--------+---------+     +--------+---------+
         |                        |                        |
         v                        v                        v
+-------------------------------------------------------------------+
|                    Global Lock (flock)                             |
|              Serializes all mutating operations                   |
+-------------------------------------------------------------------+
         |
         v
+-------------------------------------------------------------------+
|                    apt_do() Wrapper                                |
|         Unlock -> apt operation -> Relock                         |
|         + dpkg lock timeout (600s)                                |
+-------------------------------------------------------------------+
```

---

## Quick Start

### Interactive Mode (TUI)

```bash
# Download and execute
curl -fsSL https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield.sh -o IntelShield.sh
chmod +x IntelShield.sh
sudo ./IntelShield.sh
```

### Guided Hardening (Recommended for first run)

```bash
sudo ./IntelShield.sh          # Select option 1: Guided automated run
```

### Headless / CI Mode

```bash
sudo ./IntelShield.sh --profile vps-high --yes --non-interactive
```

### One-Line Deploy

```bash
sudo ./IntelShield.sh --profile vps-balanced --yes --non-interactive --lock
```

---

## Hardening Profiles

| Profile | Target | Modules | Description |
|---------|--------|---------|-------------|
| **`vps-balanced`** | Cloud VPS | 9 | Lightweight: kernel + UFW + CrowdSec + health. No IPS overhead. |
| **`vps-high`** | Production VPS | 15 | Full stack: + SSH hardening, Suricata IDS, ClamAV, auditd, anti-rootkit. |
| **`baremetal-high`** | Bare metal | 17 | Maximum: + AIDE, AppArmor, high-throughput Suricata tuning. |
| **`vpn-performance`** | VPN gateway | 7 | Minimal surface: kernel network + UFW + CrowdSec. Optimized for throughput. |
| **`forensic-audit`** | Compliance | 13 | Audit-focused: + Suricata, ClamAV, auditd, AIDE, anti-rootkit. |
| **`minimal-safe`** | Any server | 6 | Baseline: kernel security + UFW + CrowdSec. Lowest resource footprint. |

### Profile Comparison Matrix

| Module | vps-balanced | vps-high | baremetal-high | vpn-perf | forensic-audit | minimal-safe |
|--------|:---:|:---:|:---:|:---:|:---:|:---:|
| System Backup | Y | Y | Y | Y | Y | Y |
| System Baseline | Y | Y | Y | Y | Y | Y |
| Kernel Network (BBR) | Y | Y | Y | Y | - | - |
| Kernel Security | Y | Y | Y | - | Y | Y |
| CPU Microcode | Y | Y | Y | Y | Y | - |
| Platform Security | Y | Y | Y | - | Y | - |
| UFW Firewall | Y | Y | Y | Y | Y | Y |
| SSH Hardening | - | Y | Y | - | - | - |
| CrowdSec Engine | Y | Y | Y | Y | Y | Y |
| Admin Allowlist | Y | Y | Y | - | Y | Y |
| CrowdSec Bouncer | Y | Y | Y | Y | Y | Y |
| Suricata IDS | - | Y | Y | - | Y | - |
| IPS Wiring | - | Y | Y | - | Y | - |
| ClamAV | - | Y | Y | - | Y | - |
| auditd | - | Y | Y | - | Y | - |
| AIDE | - | - | Y | - | Y | - |
| AppArmor | - | - | Y | - | - | - |
| Anti-rootkit | - | Y | Y | - | Y | - |
| Health Timer | Y | Y | Y | Y | Y | Y |

---

## Immutability Engine

The immutability engine applies `chattr +i` (Linux immutable attribute) to critical system files and directories, preventing modification even by root — until explicitly unlocked.

### Protected Paths

| Category | Paths |
|----------|-------|
| **System Binaries** | `/bin`, `/sbin`, `/usr`, `/boot` |
| **Critical Config** | `/etc/passwd`, `/etc/shadow`, `/etc/fstab`, `/etc/group`, `/etc/gshadow`, `/etc/sudoers` |

### OS-Aware Exclusions

On Ubuntu 22.04/24.04, the engine dynamically excludes paths that would cause kernel errors or break system services:

| Excluded Path | Reason |
|---------------|--------|
| `/boot/efi` | FAT32/vfat — prevents `Inappropriate ioctl for device` kernel crashes |
| `/usr/lib/snapd`, `/snap` | Prevents Ubuntu's snapd auto-updater from crashing |
| `/etc/netplan`, `/run/systemd/network` | Ensures DHCP lease renewals don't sever network |
| `/usr/local/sbin` | Tool's own binary path — must remain writable for self-update |

### Filesystem-Aware Filtering

`chattr` is **only** executed on compatible filesystems: ext2, ext3, ext4, btrfs, xfs. This prevents ioctl crashes on tmpfs, vfat, devtmpfs, overlay, and other non-ext filesystems.

### Automatic Unlock for Operations

The `apt_do()` wrapper automatically unlocks `/usr` before any package operation and re-locks afterward, preventing the "locked host can't install packages" failure mode.

---

## Security Stack

### CrowdSec — Behavioral IPS

- **Engine**: Real-time log parsing with community-sourced threat intelligence
- **Bouncer**: nftables-based IP reputation enforcement at priority 0
- **Allowlist**: Admin IP anti-lockout protection (atomic YAML insertion, duplicate-aware)
- **Console**: Optional cloud dashboard enrollment

### Suricata — Signature IDS/IPS

- **IDS Mode**: Passive monitoring with eve.json event logging
- **IPS Mode**: Inline NFQUEUE with fail-open safety (SSH bypass, CrowdSec coexistence)
  - **Conntrack fast-path**: Established flows skip the userspace queue (M2-13 fix)
  - **Version-aware drop-in**: Correct `Type=` for Suricata 6/7 vs 8+ (H2-4 fix)
- **Firewall Mode** (Suricata 8): Full stateful firewall with default-drop policy
- **Rule Management**: Transactional rule updates with atomic rollback, serialized via flock
- **Self-Healing**: Automatic SID disabling on config validation failures
- **Low-RAM Tuning**: Explicit memcaps for 1 GB VPS (flow=32m, stream=32m, reassembly=64m)
- **Drop-in Architecture**: 6 override files — never edits suricata.yaml directly

### UFW — Base Firewall

- Deny incoming, allow outgoing
- SSH rate limiting (5/min burst 3)
- Port 443 TCP/UDP allowed
- Systemd resync hook (restores nftables pipeline after UFW reload)
- Port change auto-removes old rules (M2-10 fix)

### ClamAV — Antivirus

- **MemTotal gate**: Real-time scanning requires >= 2 GB RAM (H2-11 fix)
- On-access (real-time) scanning with safe bounds (`OnAccessMaxFileSize`, `MaxThreads`)
- Quarantine vault with manifest tracking and restore
- DLP detection (SSN, credit card numbers)
- Scheduled scans (full/smart, daily/weekly)

### Kernel Hardening

**Network Performance** (`99-intelshield-network.conf`):
- BBR congestion control (verified against `/proc` before writing — M2-14 fix)
- TCP MTU probing, large socket buffers
- SYN cookies, RFC 1337 TIME-WAIT protection, Martian logging
- ICMP redirect/source routing disabled

**Security** (`97-intelshield-security.conf`):
- Kernel pointer hiding (`kptr_restrict=2`)
- dmesg restriction, ptrace restriction
- BPF hardening, perf event restriction
- Protected hardlinks/symlinks/fifos/regulars

---

## Forensics and SIEM

### Forensic Bundle Collection

Generates a comprehensive DFIR package with 10 subdirectories:
- System overview, network connections, firewall state
- CrowdSec alerts/decisions, Suricata eve.json summaries
- ClamAV scan results, system logs, kernel info, process snapshots

Each bundle includes a ready-made AI prompt for automated analysis.

### Live Forensics

- **Port Scanner**: Quick view of all listening services
- **Connection Tracer**: Full TCP/UDP connection table with process mapping
- **Packet Capture**: 15-second tcpdump with PCAP export
- **Auth Failure Extractor**: SSH/auth log brute-force analysis

### Wazuh SIEM/XDR Integration

- Agent installation with manager enrollment
- FIM (File Integrity Monitoring) for all IntelShield-managed paths
- Log forwarding (syslog, auditd, Suricata eve.json, CrowdSec)
- Safe active response (evidence collection only, no blocking)
- Deb822 repository format on Ubuntu 24.04 Noble

---

## Update and Maintenance

### Self-Update (v9.9 hardened)

- HTTPS-only (TLS 1.2+)
- Identity marker verification + `bash -n` syntax validation
- Atomic install (stage -> rename)
- **Automatic unlock**: Writes to `/usr` even when immutability is active (C2-1 fix)
- Hot-reload option

### Maintenance Engine

Three-phase daily maintenance (opt-in via cron):

| Phase | Schedule | Action |
|-------|----------|--------|
| **OS Update** | Daily 02:15 | `apt update` + safe upgrade + autoremove |
| **Component Sync** | Daily 03:15 | Suricata rules, CrowdSec hub, ClamAV signatures, Wazuh agent |
| **Self-Update** | Sunday 04:30 | Script integrity check and update |

All phases use `apt_do()` for immutability-safe package operations.

### Update Center

- Package upgrades (safe or full — never release upgrades)
- Firmware updates via fwupd
- Driver updates via ubuntu-drivers
- Auto-update with scheduled reboot at 01:11
- Kernel/engine auto-upgrade protection (blacklist)

---

## CLI Reference

### Headless Flags

| Flag | Description |
|------|-------------|
| `--profile NAME` | Apply a hardening profile |
| `--backup` | Create a configuration snapshot |
| `--preflight` | Run risk engine, print report |
| `--state` | Refresh state database |
| `--lock` | Apply immutable flags |
| `--unlock` | Remove immutable flags |
| `--sync-fw` | Deploy nftables pipeline |
| `--export-state` | Export SIEM-ready JSON |
| `--update safe\|full` | Package upgrade |
| `--auto-update on\|off` | Toggle auto-updates |
| `--maintain os\|components\|self\|all` | Maintenance phases |
| `--self-update` | Check for script updates |
| `--clamav-scan full\|smart` | Headless antivirus scan |
| `--antirootkit-scan rkhunter\|chkrootkit\|all` | Headless rootkit scan |
| `--suricata-ips on\|off` | Toggle IPS mode |
| `--suricata-fw on\|off\|status` | Toggle Firewall Mode |
| `--wazuh-menu` | Open Wazuh integration |
| `--uninstall` | Open uninstall menu |

### Global Switches

| Switch | Description |
|--------|-------------|
| `--yes`, `-y` | Assume "yes" for all confirmations |
| `--non-interactive` | No TUI; dialogs degrade to log lines |
| `--verbose`, `--live`, `-V` | Stream command output to terminal |
| `--help`, `-h` | Show help |

---

## File Layout

### State Directory (`/var/lib/intelshield/`)

| File | Purpose |
|------|---------|
| `state.json` | RFC 8259 state database (SIEM export) |
| `lock-state` | Immutability state (`LOCKED` / `UNLOCKED`) — atomic writes |
| `active-profile` | Current profile name — atomic writes |
| `preflight-risk.txt` | Risk assessment report |
| `preflight-risk.json` | Risk assessment (JSON) |
| `suricata-mode` | IDS or IPS |
| `suricata-fw-mode` | Firewall Mode on/off |
| `suricata-fw-mutex` | CrowdSec/Suricata mutex state — atomic writes |

### Config Files

| Path | Purpose |
|------|---------|
| `/etc/sysctl.d/99-intelshield-network.conf` | Network performance sysctls |
| `/etc/sysctl.d/97-intelshield-security.conf` | Security sysctls |
| `/etc/sysctl.d/98-intelshield-performance.conf` | Performance profile sysctls |
| `/etc/suricata/intelshield/` | Suricata drop-in overrides (6 files) |
| `/etc/crowdsec/acquis.d/suricata.yaml` | CrowdSec Suricata acquisition |
| `/etc/crowdsec/parsers/s02-enrich/00-admin-allowlist.yaml` | Admin IP allowlist |
| `/etc/audit/rules.d/99-intelshield.rules` | auditd rules |
| `/etc/cron.d/intelshield-maintenance` | Maintenance cron |
| `/etc/cron.d/intelshield-backup` | Backup cron |
| `/etc/apt/apt.conf.d/51intelshield-blacklist` | Kernel/engine upgrade guard |
| `/etc/apt/apt.conf.d/52intelshield-autoupdate` | Auto-update policy |
| `/etc/ssh/sshd_config.d/99-harden.conf` | SSH hardening drop-in |
| `/etc/ssh/sshd_config.d/` socket drop-in | SSH socket-activation port (24.04) |

### Systemd Units

| Unit | Type | Purpose |
|------|------|---------|
| `intelshield-health.service` | oneshot | Health check runner |
| `intelshield-health.timer` | timer | 5-minute health check |
| `intelshield-cpu.service` | oneshot | CPU governor persistence |
| `intelshield-suricata-ips-nft.service` | oneshot | IPS nftables sync |
| `intelshield-suricata-fw-nft.service` | oneshot | FW Mode nftables sync |
| `ufw.service.d/99-intelshield-resync.conf` | drop-in | Post-UFW nftables resync |

### Lock Files

| File | Purpose |
|------|---------|
| `/run/intelshield-global.lock` | Global entry-point flock (TUI/cron/timers) |
| `/run/intelshield-maintenance.lock` | Maintenance run flock |
| `/run/intelshield-suricata-rules.lock` | Suricata rule update flock |

---

## By The Numbers

| Metric | Value |
|--------|-------|
| Total Functions | **260+** |
| Security Modules | **21** |
| Deployment Profiles | **6** |
| Manageable Components | **14** |
| CLI Flags | **24** |
| Main Menu Options | **23** |
| Lines of Code | **4,762** |
| Target OS | Ubuntu 22.04 / 24.04 LTS |

---

## Audit Hardening (Round 2)

IntelShield v9.9 resolves **all findings** from the Round 2 blind-spot security audit:

| Severity | Count | Status |
|----------|-------|--------|
| **Critical** | 2 | All fixed |
| **High** | 7 | All fixed |
| **Medium** | 11 | All fixed |
| **Low/Info** | 10 | All addressed |

### Key Architectural Improvements

1. **`apt_do()` wrapper** — Single entry point for all apt operations, owning immutability unlock/relock + dpkg lock timeout. Fixes the "locked host can't install" failure class.

2. **Global concurrency control** — `flock`-based serialization prevents TUI/cron/timer races on shared state files.

3. **Atomic state writes** — `atomic_state_write()` uses temp-file-then-rename to prevent torn reads under concurrency.

4. **Version-aware service management** — IPS drop-ins detect Suricata engine version and set correct systemd `Type=` directive.

5. **Resource gates** — ClamAV real-time scanning gated on `MemTotal >= 2048 MB`; Suricata low-RAM tuning sets explicit memory caps.

6. **Signal handling** — HUP trap added for the most common SSH abnormal termination scenario.

---

## Contributing

IntelShield is designed as a single self-contained script. Contributions should maintain this property — no external dependencies beyond standard Ubuntu packages.

### Development Guidelines

1. All module functions follow the `m_<name>()` convention
2. State is persisted via `state_write()` after any configuration change
3. Every destructive operation has a rollback path via `restart_or_rollback()`
4. TUI dialogs use whiptail with automatic terminal size clamping
5. Headless mode (`--non-interactive`) must work for every feature
6. All apt operations **must** go through `apt_do()` — never raw `apt-get`
7. State file writes **must** use `atomic_state_write()` — never raw `echo >`

---

## License

MIT License

---

<div align="center">

**Built for production servers that cannot afford to be breached.**

*IntelShield v9.9 — Audit-Hardened . OS-Aware Immutability . Zero-Trust Hardening*

</div>
