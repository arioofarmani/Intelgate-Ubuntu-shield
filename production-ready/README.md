<p align="center">
  <img src="https://img.shields.io/badge/version-9.9.1-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Ubuntu-22.04%20%7C%2024.04%20LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/shell-bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
</p>

<h1 align="center">IntelShield</h1>

<p align="center">
  <b>Hardening · Intrusion Detection · Forensics · Immutability</b><br>
  <sub>One script. One run. A hardened, monitored, forensics-ready Ubuntu server.</sub>
</p>

---

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield.sh -o IntelShield.sh
chmod +x IntelShield.sh
sudo ./IntelShield.sh
```

Run with no arguments for the interactive TUI. It re-executes itself with `sudo` if needed.

```bash
# Headless: apply a profile and lock the system down
sudo ./IntelShield.sh --profile vps-high --yes --non-interactive --lock
```

---

## Architecture

```
  ┌───────────┬──────────┬──────────┬──────────┬─────────────┐
  │  Kernel   │ Network  │ Services │ Forensics│ Maintenance │
  │ hardening │ firewall │ enforced │  engine  │   engine    │
  ├───────────┼──────────┼──────────┼──────────┼─────────────┤
  │  sysctl   │   UFW    │ CrowdSec │  auditd  │  OS updates │
  │   BBR     │ nftables │ Suricata │   AIDE   │  components │
  │  lockdown │  NFQUEUE │  ClamAV  │ rkhunter │  log rotate │
  ├───────────┴──────────┴──────────┴──────────┴─────────────┤
  │        Immutability engine  ·  chattr +i, OS-aware        │
  └───────────────────────────────────────────────────────────┘
```

**Packet path:** `CrowdSec @0` → `Suricata @10` → `IPS @100` → kernel

---

## Profiles

| Profile | Suggested RAM | Stack |
|---|---|---|
| `minimal-safe` | 256 MB+ | Kernel security · UFW · CrowdSec |
| `vps-balanced` | 512 MB+ | + kernel tuning · CPU audit · health timer |
| `vpn-performance` | 512 MB+ | Throughput-tuned (BBR) · UFW · CrowdSec |
| `vps-high` | 1 GB+ | + SSH hardening · Suricata · ClamAV · auditd · anti-rootkit |
| `forensic-audit` | 1 GB+ | Suricata · ClamAV · auditd · AIDE · anti-rootkit |
| `baremetal-high` | 2 GB+ | Everything · AppArmor · high-throughput Suricata |

Switching profiles is safe — downgrading disables heavy components rather than purging packages. Suricata can be tuned for low-RAM hosts from its menu.

---

## Security Stack

| Component | Role |
|---|---|
| **CrowdSec** | Behavioral IPS — community threat intel, nftables bouncer |
| **Suricata** | Signature IDS/IPS — inline NFQUEUE, fail-open, conntrack fast-path |
| **UFW** | Base firewall — deny inbound, SSH rate-limiting |
| **ClamAV** | Antivirus — scheduled scans, quarantine vault with restore (real-time scanning needs 2 GB+) |
| **auditd** | Syscall auditing |
| **AIDE** | File integrity monitoring |
| **rkhunter · chkrootkit** | Rootkit scanning |
| **Wazuh** | SIEM/XDR agent — FIM, log forwarding, active response |

---

## CLI Reference

| Flag | Description |
|---|---|
| `--profile NAME` | Apply a hardening profile |
| `--lock` · `--unlock` | Toggle system immutability |
| `--update safe\|full` | Package upgrade (never a release upgrade) |
| `--auto-update on\|off` | Automatic updates + auto-reboot policy |
| `--maintain os\|components\|all` | Run a maintenance phase |
| `--suricata-ips on\|off` | Switch between IDS and inline IPS |
| `--clamav-scan full\|smart` | Antivirus scan |
| `--antirootkit-scan rkhunter\|chkrootkit\|all` | Rootkit scan |
| `--backup` | Create a configuration snapshot |
| `--preflight` | Risk report |
| `--export-state` | Export state as JSON (SIEM-ready) |
| `--yes` · `--non-interactive` · `--verbose` | Global switches |

`--help` lists everything.

---

## Updating

**IntelShield does not update itself.** Earlier versions fetched a new copy over HTTPS and ran it as root from a weekly cron — but they could not verify *who* wrote it, only that it was valid bash. That is a root-code-execution path, so it was removed rather than patched.

Review the release, then install it deliberately:

```bash
sudo install -m 750 IntelShield.sh /usr/local/sbin/intelshield
```

The maintenance engine still keeps the *system* current on its own (opt-in, via the Maintenance menu):

| When | What |
|---|---|
| Daily 02:15 | OS packages — `apt update` + safe upgrade, no removals |
| Daily 03:15 | Components — Suricata rules, CrowdSec hub, ClamAV signatures, Wazuh agent |

Services restart only after an update verifies; every action is logged.

---

## Safety

- **Anti-lockout** — SSH is never queued through the IPS, and a port change is verified against the *effective* listener before it is reported as done.
- **Gated restarts** — a service is restarted only when its new config validates, and rolls back if it fails to come up.
- **Snapshots** — a config backup is taken before risky operations. Restores are checksum-verified and refused if the archive doesn't match what was written.
- **Fail-open IPS** — if Suricata dies, traffic flows; it does not black-hole the host.
- **Reversible** — `--unlock`, the uninstall menu, and restore all walk changes back.

---

## Files

| Path | Contents |
|---|---|
| `/var/log/intelshield.log` | Main log |
| `/var/log/intelshield-maintenance.log` | Maintenance audit trail |
| `/var/lib/intelshield/` | State database |
| `/var/backups/intelshield/` | Config snapshots |

---

## Requirements

Ubuntu **22.04 (jammy)** or **24.04 (noble)** LTS · root/sudo · 256 MB RAM minimum (1 GB+ for the full stack).

---

<p align="center">
  <sub>MIT License · Built for production servers that cannot afford to be breached.</sub>
</p>
