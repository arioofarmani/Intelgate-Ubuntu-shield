<p align="center">
  <img src="https://img.shields.io/badge/version-9.9-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/platform-Ubuntu%2022.04%20%7C%2024.04-brightgreen?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/audit-Round%202%20resolved-red?style=for-the-badge" alt="Audit">
</p>

<h1 align="center">IntelShield v9.9</h1>

<p align="center">
  <b>Unified Server Hardening · Forensics · SIEM/XDR · Performance · Immutability</b><br>
  <sub>Production-grade security for Ubuntu 22.04 / 24.04 LTS servers</sub>
</p>

<p align="center">
  <i>One script. One execution. A fully hardened, forensics-ready, SIEM-integrated server.</i>
</p>

---

## Quick Start

```bash
# Download and run
curl -fsSL https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield.sh -o IntelShield.sh
sudo ./IntelShield.sh
```

| Mode | Command |
|------|---------|
| **Interactive TUI** | `sudo ./IntelShield.sh` |
| **Guided (recommended)** | `sudo ./IntelShield.sh` → option 1 |
| **Headless / CI** | `sudo ./IntelShield.sh --profile vps-high --yes --non-interactive` |
| **One-line deploy** | `sudo ./IntelShield.sh --profile vps-balanced --yes --non-interactive --lock` |

---

## Architecture

```
                    IntelShield v9.9
  ┌──────────┬──────────┬──────────┬──────────┬──────────┐
  │  Kernel  │ Network  │ Service  │ Forensic │Maintenan.│
  │ Hardening│ Firewall │Enforcem. │  Engine  │  Engine  │
  ├──────────┼──────────┼──────────┼──────────┼──────────┤
  │  sysctl  │   UFW    │ CrowdSec │  Bundle  │Auto-upd. │
  │   BBR    │nftables  │ Suricata │ Capture  │Self-upd. │
  │ Security │  IPS/FW  │  ClamAV  │ Triage   │Cron jobs │
  │   Perf   │ iptables │  auditd  │ SIEM exp │Log rotat.│
  ├──────────┴──────────┴──────────┴──────────┴──────────┤
  │           Immutability Engine (chattr +i)             │
  │  OS-aware exclusions · Filesystem-type filtering     │
  ├──────────────────────────────────────────────────────┤
  │  Atomic state writes · Global flock · apt_do wrapper │
  └──────────────────────────────────────────────────────┘
```

**nftables pipeline:** `CrowdSec@0 → Suricata@10 → IPS@100 → Kernel`

---

## What v9.9 Fixes

All **30 findings** from the Round 2 security audit resolved:

| Severity | Count | Key Fixes |
|----------|-------|-----------|
| **Critical** | 2 | `apt_do()` wrapper for all apt operations; self-update unlock |
| **High** | 7 | SSH socket-activation; ClamAV RAM gate; global flock; IPS conntrack |
| **Medium** | 11 | HUP trap; IPv6 validation; log sanitization; atomic state writes |
| **Low** | 10 | Dead code cleanup; install_self rc propagation |

---

## Profiles

| Profile | RAM | What It Installs |
|---------|-----|-----------------|
| `vps-balanced` | 512 MB+ | Kernel + UFW + CrowdSec + health |
| `vps-high` | 1 GB+ | + SSH, Suricata IDS, ClamAV, auditd, anti-rootkit |
| `baremetal-high` | 2 GB+ | + AIDE, AppArmor, high-throughput tuning |
| `vpn-performance` | 512 MB+ | Kernel network + UFW + CrowdSec (throughput-optimized) |
| `forensic-audit` | 1 GB+ | Suricata, ClamAV, auditd, AIDE, anti-rootkit |
| `minimal-safe` | 256 MB+ | Kernel security + UFW + CrowdSec (minimal footprint) |

---

## Security Stack

| Component | Role |
|-----------|------|
| **CrowdSec** | Behavioral IPS — community-sourced threat intel, nftables bouncer |
| **Suricata** | Signature IDS/IPS — inline NFQUEUE, fail-open, conntrack fast-path |
| **ClamAV** | Antivirus — on-access scanning (gated on 2 GB+ RAM), quarantine vault |
| **UFW** | Base firewall — deny incoming, SSH rate-limit, port 443 |
| **AIDE** | File integrity monitoring |
| **auditd** | System call auditing |
| **rkhunter/chkrootkit** | Anti-rootkit scanning |
| **Wazuh** | SIEM/XDR — FIM, log forwarding, safe active response |

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `--profile NAME` | Apply a hardening profile |
| `--lock` / `--unlock` | Toggle immutability |
| `--update safe\|full` | Package upgrade |
| `--maintain os\|components\|self\|all` | Run maintenance phases |
| `--suricata-ips on\|off` | Toggle IPS mode |
| `--clamav-scan full\|smart` | Run antivirus scan |
| `--antirootkit-scan` | Run rootkit scan |
| `--backup` | Create config snapshot |
| `--yes`, `--non-interactive`, `--verbose` | Global switches |

---

## Key Features

- **`apt_do()` wrapper** — single entry point for all package operations with automatic immutability unlock/relock
- **Atomic state writes** — temp-file-then-rename prevents torn reads under concurrency
- **Global flock** — serializes TUI, cron, and timers against shared state
- **SSH socket-activation** — handles Ubuntu 24.04's default `ssh.socket`
- **Version-aware IPS** — detects Suricata 6/7 vs 8+ and sets correct systemd type
- **Signal handling** — HUP trap for SSH disconnect scenarios
- **Conntrack fast-path** — established flows skip the IPS queue

---

## By The Numbers

| | |
|---|---|
| **260+** functions | **21** security modules |
| **6** profiles | **14** manageable components |
| **4,762** lines | **30** audit findings fixed |

---

## License

MIT License

---

<p align="center">
  <b>Built for production servers that cannot afford to be breached.</b><br>
  <sub>IntelShield v9.9 — Audit-Hardened · OS-Aware Immutability · Zero-Trust Hardening</sub>
</p>
