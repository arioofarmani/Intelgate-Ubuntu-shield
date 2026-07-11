# IntelShield v8.6

**Unified hardening, forensics, SIEM/XDR, and performance tuning for Ubuntu servers -- in a single Bash script with a full text UI.**

IntelShield is a menu-driven security suite for **Ubuntu 22.04 / 24.04 LTS** servers, with first-class support for **x-ui / 3x-ui + Xray (VLESS-Reality)** relays. It installs, configures, wires together, and manages a complete defensive stack -- firewall, IDS/IPS, intrusion prevention, antivirus, file-integrity, rootkit detection, audit, and a Wazuh agent -- behind one consistent `whiptail` interface, with safety rails designed so you can harden a **remote** box without locking yourself out.

**New in v8.6:** Full **dual-stack IPv6 support** (validation, HOME_NET, egress detection), **transactional rule hardening** with 5-gate atomic execution and deterministic snapshot/validate/apply/verify/rollback gates, plus all v8.3 features: Suricata 8 **Firewall Mode** (deterministic packet pipeline, default-drop), **nftables priority chain orchestration** (CrowdSec @priority 0, Suricata @priority 10), **mutex toggle** for concurrent IPS conflict prevention, and Suricata 8's 107+ new keywords (`entropy`, `luaxform`, `absent`, JSON datasets).

> **Use only on servers you own or are authorized to administer.** IntelShield makes real changes to firewall rules, SSH, kernel parameters, and system services. Always test on a throwaway VM first and keep console/out-of-band access available.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Interactive TUI](#interactive-tui)
  - [Headless / automation flags](#headless--automation-flags)
- [Production profiles](#production-profiles)
- [Suricata: IDS, IPS & Firewall Mode](#suricata-ids-ips--firewall-mode)
  - [The IDS/IPS NFQUEUE pipeline](#the-idsips-nfqueue-pipeline)
  - [Suricata 8 Firewall Mode](#suricata-8-firewall-mode)
  - [nftables priority orchestration](#nftables-priority-orchestration)
- [Transactional rule management](#transactional-rule-management)
- [Suricata configuration architecture](#suricata-configuration-architecture)
- [x-ui / Xray sandbox](#x-ui--xray-sandbox)
- [Component control & uninstall](#component-control--uninstall)
- [Update center](#update-center)
- [Intelligent maintenance engine](#intelligent-maintenance-engine)
- [Safety design](#safety-design)
- [Files & locations](#files--locations)
- [Wazuh / SIEM integration](#wazuh--siem-integration)
- [FAQ](#faq)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

| Domain | What IntelShield manages |
|---|---|
| **Firewall** | UFW with anti-lockout defaults, SSH `limit` brute-force damping, per-rule allow/deny builder, safe re-baseline |
| **Intrusion prevention** | CrowdSec engine + nftables firewall bouncer, admin allowlist, console enrollment, decision management |
| **IDS / IPS / Firewall** | Suricata as passive IDS **or** inline IPS (NFQUEUE) **or** Suricata 8 Firewall Mode (deterministic pipeline, default-drop), rule-source/category selection, drop-policy control, JA3/JA4 & encrypted-metadata monitoring |
| **Antivirus** | ClamAV with quarantine vault (with mode/owner-preserving restore), scheduled scans, on-access toggle, DLP/PUA hardening |
| **File integrity & audit** | AIDE baseline, auditd rules (with 32-bit syscall coverage), AppArmor |
| **Rootkit detection** | rkhunter + chkrootkit with safe-area whitelisting, manual protected-path quarantine, scheduled scans |
| **Kernel & network** | sysctl hardening, BBR + queue tuning, anti-spoofing, CPU microcode & platform (Secure Boot / TPM) audit |
| **Sandboxing** | systemd confinement for x-ui/Xray with an **on/off switch** for manual panel updates |
| **Forensics** | One-command "forensic bundle" -- collects CrowdSec/Suricata/ClamAV/x-ui/system/kernel/process state into one AI-ready archive |
| **Backup / restore** | Config snapshots (tar), verified archives, pruning, one-click rollback, weekly cron |
| **SIEM / XDR** | Wazuh **agent** integration: log forwarding, FIM, command collection, safe (evidence-only) active response |
| **Performance** | CPU governor + EPP profiles, latency/throughput sysctl sets, live jitter dashboard |
| **Update center** | Package/full upgrade (never a release upgrade), firmware (fwupd) + driver updates, and auto-update with an automatic **01:11 reboot** when one is required |
| **Maintenance engine** | Opt-in cron: unattended OS upgrades, sequential component updates (Suricata rules / CrowdSec hub / ClamAV sigs / Wazuh agent), secure script self-update -- restarts only on verified success, audited in `/var/log/intelshield-maintenance.log` |
| **Live console** | On by default -- every command and its real output streams to your terminal (still logged), so you always see what's happening; toggle off with `L` |
| **Fleet-friendly** | JSON state DB, preflight risk score, profiles, granular component enable/disable/remove/purge |

---

## Architecture

IntelShield is intended for an **edge relay** topology, but works on general-purpose servers too:

```
                 Internet
                    |
        +-----------v-------------+
        |  UFW (deny-in default)  |  <- anti-lockout: SSH limit + 443 tcp/udp
        +-------------------------+
        |  CrowdSec bouncer (nft)  |  <- drops known-bad IPs (reputation)  [priority 0]
        +-------------------------+
        |  Suricata FW/IPS (nftq)  |  <- deep inspection, default-drop     [priority 10]
        |    or Suricata IPS mode  |     or inline signature drop          [priority 100]
        +-------------------------+
        |  x-ui / 3x-ui + Xray     |  <- VLESS-Reality on :443 (sandboxed)
        +-------------------------+
   Suricata eve.json ------> CrowdSec (IDS->IPS feedback loop)
   All logs/state -----------> Wazuh agent -------> your Wazuh manager
```

CrowdSec and Suricata are **layered and complementary** -- cheap IP-reputation drops happen first at priority 0, deep signature inspection second at priority 10. IntelShield keeps them working together by default via **nftables priority chain orchestration**.

---

## Requirements

- **OS:** Ubuntu 22.04 or 24.04 LTS (Debian-family; `apt`)
- **Privileges:** root (the script auto-elevates via `sudo`)
- **Access:** keep a second SSH session or console open the first time you harden SSH/UFW
- Internet access for package installation and rule/signature updates

Dependencies (`whiptail`, `curl`, `jq`, `iproute2`, `nftables`, ...) are installed automatically during preflight.

---

## Installation

```bash
# Download (the repo publishes the script under the STABLE name IntelShield.sh --
# that is also what the self-updater fetches)
wget -O IntelShield.sh https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield.sh
# (or) git clone https://github.com/arioofarmani/Intelgate-Ubuntu-shield.git && cd Intelgate-Ubuntu-shield

# Inspect before running (recommended for any root script)
less IntelShield.sh

# Make executable and launch (it will re-exec via sudo if needed)
chmod +x IntelShield.sh
sudo ./IntelShield.sh
```

On first launch IntelShield installs a canonical copy at `/usr/local/sbin/intelshield`, so scheduled timers and cron jobs always call a stable path. After that you can simply run:

```bash
sudo intelshield
```

> **Publishing note (repo maintainers):** always push new releases to the repository as `IntelShield.sh` on the `main` branch. The self-update engine compares the `VERSION="..."` header at that URL against the running copy -- a version-suffixed filename would break every deployed node's self-update.

---

## Usage

### Interactive TUI

Run with no arguments for the full menu:

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
 M  Maintenance engine (scheduled updates + self-update): ENABLED/disabled
 S  x-ui / Xray sandbox control (on/off for manual updates)
 L  Live console output: ON/OFF (watch commands run in real time)
18  Uninstall / revert safely
19  Exit
```

**Start here:** run **Preflight risk engine** (4) for a readiness score, then **Guided automated hardening run** (1) or pick a **Profile** (3).

**Live Console (`L`) -- on by default:** IntelShield prints every command it runs and streams the real stdout/stderr straight to your terminal, so you always see what's happening to the system. Everything is still written to `/var/log/intelshield.log`. It stays on constantly unless you deliberately switch it off with the **`L`** toggle (remembered between runs); `--verbose`/`--live` forces it on for a single run. Secrets (Wazuh enrollment key, CrowdSec token) are never streamed.

### Headless / automation flags

Ideal for cloud-init, Ansible, or cron:

```bash
sudo intelshield --help                              # list all flags
sudo intelshield --verbose                            # TUI, but stream live command output
sudo intelshield --update safe --verbose              # watch the upgrade happen live
sudo intelshield --preflight                         # risk report path
sudo intelshield --state                             # refresh + print state.json path
sudo intelshield --backup                            # create a config snapshot
sudo intelshield --profile vps-high --non-interactive --yes
sudo intelshield --update safe                        # package upgrade (no removals, no release upgrade)
sudo intelshield --auto-update on                     # auto-update + 01:11 reboot when required
sudo intelshield --clamav-scan smart                 # used by timers
sudo intelshield --antirootkit-scan all
sudo intelshield --suricata-ips on  --non-interactive --yes
sudo intelshield --suricata-fw on  --non-interactive --yes   # Suricata 8 Firewall Mode
sudo intelshield --suricata-fw status                          # view FW mode status
sudo intelshield --sandbox off                       # before a manual x-ui update
sudo intelshield --sandbox on                        # after it
sudo intelshield --maintain os --non-interactive --yes          # cron: OS packages
sudo intelshield --maintain components --non-interactive --yes  # cron: Suricata/CrowdSec/ClamAV/Wazuh
sudo intelshield --maintain all --non-interactive --yes         # everything, sequentially
sudo intelshield --self-update                       # check GitHub, verify + install atomically
```

`--non-interactive` suppresses the TUI (dialogs become log lines); `--yes` auto-confirms prompts. Timers run non-interactively automatically (no TTY = no whiptail).

---

## Production profiles

One selection installs, enables, and wires a coherent stack. Downgrading a profile **disables heavy services cleanly** (it does not purge packages), so switching is safe.

| Profile | For | Highlights |
|---|---|---|
| `vps-balanced` | Small VPS | Baseline, kernel tuning/security, UFW, CrowdSec + bouncer, health timer |
| `vps-high` | Hardened VPS | + SSH hardening, Suricata, IDS->IPS wiring, ClamAV, auditd, anti-rootkit, sandbox |
| `baremetal-high` | Dedicated box | + AIDE, AppArmor, high-throughput Suricata |
| `vpn-performance` | VLESS relay | Baseline, BBR, UFW, CrowdSec + bouncer, sandbox, panel restriction (perf-first) |
| `forensic-audit` | Monitoring node | auditd, AIDE, Suricata, CrowdSec wiring, ClamAV, anti-rootkit |
| `minimal-safe` | Bare minimum | Baseline, kernel security, UFW, CrowdSec + bouncer |

---

## Suricata: IDS, IPS & Firewall Mode

**Menu -> Suricata IDS/IPS intelligence.**

IntelShield supports three operational modes for Suricata:

### IDS (default) -- Passive Monitoring

Suricata watches a copy of traffic and only alerts. No packets are blocked. This is the safest starting point.

### IPS (inline) -- NFQUEUE Drop Mode

Suricata sits in the packet path via **NFQUEUE** and can **drop**, with three safety rails baked in:

- **Fail-open** (`queue ... flags bypass`): if Suricata stops or crashes, the kernel accepts traffic -- **no outage, no lockout**.
- **SSH port excluded** from the queue entirely.
- Runs at nftables **priority 100**, *after* CrowdSec -- so both enforcement layers stack.

### Suricata 8 Firewall Mode -- Deterministic Packet Pipeline

**New in v8.3.** An experimental mode that replaces traditional IDS/IPS with a **deterministic packet pipeline** and **default-drop policy**. Unlike traditional IPS where the default is pass, in Firewall Mode every packet NOT explicitly accepted is **dropped**.

Key concepts:

- **Action Scopes**: Suricata 8 introduces explicit action scopes for rules:
  - `accept:packet` -- immediately accept this packet (no further inspection)
  - `accept:flow` -- accept all future packets in this TCP/UDP flow
  - `drop:packet` -- immediately drop this packet
  - `drop:flow` -- drop all future packets in this flow
  - `reject:packet` -- drop + send ICMP unreachable / TCP RST

- **Rule Hooks**: Two inspection points in the pipeline:
  - `packet:filter` -- runs on every packet before flow reassembly (fast path)
  - `app:filter` -- runs after protocol detection (deep inspection path)

- **Default Policy**: DROP (if no rule explicitly accepts, the packet is dropped)

### The IDS/IPS NFQUEUE Pipeline

```
              inbound packet
                    |
      nftables hook input, priority < 0
      +-----------------------------+
      | CrowdSec firewall bouncer   |  known-bad IP?  --> DROP (cheap, reputation)
      +-------------+---------------+
                    | survivors
      nftables hook input, priority 10   (table inet intelshield_suricata_fw)
      +-----------------------------+
      | queue num 0-N flags         |  SSH port: accept (never queued -- no lockout)
      |   bypass,fanout             |  Suricata down? bypass --> ACCEPT (fail-open)
      +-------------+---------------+
                    | NFQUEUE verdict
      +-----------------------------+
      | Suricata 8 (inline, -q 0-N) |  drop.conf rule match --> DROP
      +-------------+---------------+   everything else      --> ACCEPT + eve.json alert
                    |
             x-ui / Xray :443            eve.json --> CrowdSec (IDS->IPS feedback)
```

One queue per CPU core (max 4) with `fanout` load-balancing; the same pipeline mirrors on the output hook.

### nftables Priority Orchestration

**New in v8.3.** IntelShield uses explicit nftables priority levels to layer CrowdSec and Suricata without conflicts:

| Component | Priority | Role |
|---|---|---|
| CrowdSec firewall bouncer | **0** | Edge -- cheap IP-reputation drops |
| Suricata Firewall Mode | **10** | Deep inspection, deterministic pipeline |
| Suricata IPS (legacy) | **100** | Inline signature drop (backward compatible) |

The **mutex toggle** (`/var/lib/intelshield/suricata-fw-mutex`) prevents enabling both CrowdSec bouncer and Suricata Firewall Mode when concurrent execution constraints exist. When CrowdSec is active and you enable Suricata FW mode, IntelShield configures them with separate priorities so both layers stack.

**Coexistence flow:**

1. Packet arrives at nftables
2. CrowdSec bouncer evaluates at priority 0 (IP reputation check)
3. If the IP is allowed, packet passes to Suricata NFQUEUE chain at priority 10
4. Suricata runs the deterministic pipeline (packet:filter -> protocol detection -> app:filter)
5. Default policy: DROP unless an explicit accept rule matched

---

## Transactional Rule Management

**New in v8.3.** Suricata 8 introduces transactional rules that combine request and response logic into single rule definitions, saving CPU cycles. IntelShield provides a dynamic CLI to manage rule states via `enable.conf`, `disable.conf`, and `drop.conf`.

### Suricata 8 New Keywords

Suricata 8 adds 107+ new keywords. IntelShield tracks and supports:

| Keyword | Purpose |
|---|---|
| `entropy` | Measures payload entropy (detects encrypted tunnels, DNS tunneling) |
| `luaxform` | Lua-based packet transforms (custom detection logic) |
| `absent` | Matches when a protocol field is absent |
| `dataset` | IP/domain/hash datasets from threat intelligence feeds |
| `http2` | HTTP/2 protocol inspection |
| `ja4` | JA4+ TLS fingerprinting |

### Transactional Rule Example

```
# Suricata 8 transactional rule: single rule matches both request AND response
alert http any any -> any any (msg:"Transaction"; \
  http.method; content:"POST"; \
  http.response_body; content:"error"; \
  sid:1234567; rev:1;)
```

This single rule replaces two separate rules (one for request, one for response).

### Rule State Management

From the Suricata menu, access **Transactional rule management** to:

- **View** current disable.conf / enable.conf / drop.conf
- **Add/Remove SIDs** from disable.conf (mute rules) or drop.conf (force drop in IPS)
- **View rule statistics** including keyword usage counts
- **Parse JSON datasets** for IoC context from threat intelligence feeds

### Atomic Rule Toggle

```bash
# Internal function for atomic SID management
suricata_rule_state_toggle "disable" "1234567" "add"    # mute SID 1234567
suricata_rule_state_toggle "disable" "1234567" "remove" # re-enable SID 1234567
suricata_rule_state_toggle "drop" "9999999" "add"       # force drop in IPS mode
```

---

## Suricata Configuration Architecture

**v8.0+ removes every `sed` edit of `suricata.yaml`.** All IntelShield overrides are named drop-in files under `/etc/suricata/intelshield/`, pulled in by **one marker-guarded `include:` block** appended to `suricata.yaml`:

```yaml
# --- IntelShield managed includes (BEGIN) ---
include:
  - /etc/suricata/intelshield/10-vars.yaml
  - /etc/suricata/intelshield/20-capture.yaml
  - /etc/suricata/intelshield/30-tuning.yaml
  - /etc/suricata/intelshield/60-firewall.yaml   # v8.3: Firewall Mode config
# --- IntelShield managed includes (END) ---
```

| Drop-in | Owns | Written by |
|---|---|---|
| `10-vars.yaml` | `HOME_NET` (egress IP + RFC1918) | Install / repair |
| `20-capture.yaml` | af-packet capture interface | Install / repair |
| `30-tuning.yaml` | `max-pending-packets`, detect profile | Low-RAM / high-throughput tuning |
| `40-app-layer.yaml` | JA3/JA4 TLS fingerprinting | JA3/JA4 menu |
| `50-rules.yaml` | rule path + local TLS/QUIC metadata rules | Encrypted-metadata menu |
| `60-firewall.yaml` | Suricata 8 Firewall Mode config | Firewall Mode enable |

Why it matters:

- **Package-upgrade safe:** a Suricata package upgrade can replace `suricata.yaml` without destroying your settings.
- **Atomic:** every drop-in write is validated with `suricata -T`; on failure both the drop-in **and** `suricata.yaml` are restored.
- **Transparent:** you can read (or hand-edit) each override in isolation.
- **Suricata 8 ready:** Firewall Mode drop-in is added/removed cleanly when toggling modes.

### SID-Based Self-Healing (v8.0+)

When a fetched rule uses a keyword your engine build doesn't support, the failing SIDs are parsed from the engine's own error output and registered in an IntelShield-managed block of `/etc/suricata/disable.conf`. `suricata-update` then re-merges the set with them cleanly omitted -- so the bypass **survives every future rule update**.

---

## x-ui / Xray sandbox

**Menu -> `S` (x-ui / Xray sandbox control)**, or `--sandbox on|off`.

Applies a hardened systemd sandbox (`ProtectSystem=strict`, `NoNewPrivileges`, capability bounding, `@system-service` syscall filter, and more) to the x-ui/Xray units, while guaranteeing the panel can still **read its files, write its DB/logs/config/bin, and make the syscalls it needs**. Key points:

- **Enable / Disable toggle** -- turn the sandbox **off before a manual panel/Xray update**, then back on afterward.
- **Per-unit auto-rollback** -- if a unit won't start with the sandbox, it's reverted automatically (the proxy never stays down).
- **`MemoryDenyWriteExecute` off by default** for maximum x-ui compatibility (toggle on for extra hardening).
- Optional extra net capabilities for 3x-ui IP-limit/fail2ban and Xray tproxy.

---

## Component control & uninstall

**Menu -> Component control center (17)** gives every module a lifecycle:

- **Enable** / **Disable** (stop, keep config) / **Remove** (delete IntelShield config, keep packages) / **Purge** (uninstall packages).
- Disabling one module **never breaks another** -- cross-wiring is cleaned automatically (e.g. muting Suricata unhooks the CrowdSec acquis; disabling CrowdSec stops its bouncer first; disabling Firewall Mode tears down nftables chains; Wazuh keeps forwarding throughout).

**Menu -> Uninstall / revert (18)** offers snapshot restore, config-only removal, selective package purge, or a full revert -- always taking a backup first.

---

## Update center

**Menu -> `U` (Update center)**, or the `--update` / `--auto-update` flags.

- **Package upgrade (safe):** `apt upgrade` with no package removals.
- **Full upgrade:** `apt full-upgrade` (allows dependency changes) -- still **within the same Ubuntu release**. IntelShield **never** performs a release/distro upgrade (`do-release-upgrade` is never invoked).
- **Firmware update:** `fwupd` -- refreshes metadata and applies device firmware (gracefully reports "nothing to do" on VMs/VPS).
- **Driver update:** `ubuntu-drivers autoinstall` + refreshed `linux-firmware`.
- **Automatic updates:** one toggle enables unattended security updates and, **when an update requires a reboot, automatically reboots the server at `01:11`** (`Automatic-Reboot-Time`). You choose whether kernel/firmware are included:
  - **No (recommended for relays):** auto-patch everything **except** the kernel and live security engines.
  - **Yes:** fully patched including the kernel, applied at the 01:11 reboot.
- **Reboot control:** check reboot-required status, schedule the 01:11 reboot on demand, cancel a pending reboot, or reboot now.

> **Update Center vs Maintenance Engine:** the Update Center's auto-update toggle drives Ubuntu's own `unattended-upgrades` (security patches + the 01:11 reboot policy). The Maintenance Engine below is a *superset* you enable explicitly: full safe upgrades on a schedule you can see, plus the security components and the script itself.

---

## Intelligent maintenance engine

**Menu -> `M` (Maintenance engine)**, or the `--maintain` / `--self-update` flags. **Opt-in only** -- the cron file is written exclusively from the menu, never behind your back.

Enabling it writes `/etc/cron.d/intelshield-maintenance`:

| Schedule | Job | What it does |
|---|---|---|
| 02:15 daily | `--maintain os` | `apt update` -> **safe** upgrade -> autoremove |
| 03:15 daily | `--maintain components` | Sequentially: **Suricata rules** -> **CrowdSec hub** -> **ClamAV** -> **Wazuh agent** |
| 04:30 Sunday | `--maintain self` | Script self-update: fetch -> verify -> atomic install |

**Design contract (what makes it safe to leave unattended):**

- **Strict exit-code gating.** Every step's *real* exit code is captured. A service is restarted **only** after its update verifiably succeeded.
- **Atomic rollbacks.** Suricata rule updates keep a pre-update snapshot: if the post-update restart fails, the snapshot is restored and the old engine restarted.
- **Single-flight.** Every run takes an exclusive `flock` -- overlapping cron fires become a logged no-op.
- **Dedicated audit trail.** Everything lands in **`/var/log/intelshield-maintenance.log`**.
- **Reboot-safe.** The OS job *reports* a required reboot but never takes one.
- **Disabled components are respected.** If you stopped Suricata or CrowdSec deliberately, the engine skips them.

### Script self-updating

`--self-update` (or menu -> `U`) checks the GitHub repo for a newer version:

1. **Fetch** over HTTPS only (`--proto '=https' --tlsv1.2`).
2. **Verify**: non-empty, identity header present, `VERSION="..."` marker parsed, `bash -n` syntax validation. Never executed during verification.
3. **Install atomically:** staged next to `/usr/local/sbin/intelshield`, then `mv` over it.
4. **Hot-reload (interactive only):** after an update, IntelShield offers to `exec` into the new version immediately.

---

## Safety design

- **Backups before changes:** a config snapshot is taken before restores, profile switches, and Wazuh/uninstall operations, plus a once-a-day startup snapshot.
- **Validate before apply:** `sshd -t` before reloading SSH, `suricata -T` before restart, UFW port validation *before* `--force enable`, sandbox verify-and-rollback.
- **Anti-lockout:** SSH port is `limit`-ed and always re-allowed before enabling/resetting UFW; the IPS/Firewall queue excludes SSH and fails open.
- **Least surprise:** destructive prompts default to **No**; secrets are entered masked and never written to logs.
- **Hardened defaults:** private `mktemp` scratch dir, atomic state writes, `600` backups/state, `sudo` env stripped to `DEBIAN_FRONTEND`.
- **Mutex safety (v8.3):** the nftables priority orchestration and mutex toggle prevent CrowdSec and Suricata Firewall Mode from conflicting when both are active.

---

## Files & locations

| Path | Purpose |
|---|---|
| `/usr/local/sbin/intelshield` | Canonical installed copy (used by timers/cron; self-update target) |
| `/var/log/intelshield.log` | Operations log |
| `/var/log/intelshield-maintenance.log` | Maintenance engine audit trail |
| `/etc/cron.d/intelshield-maintenance` | Maintenance engine schedule (exists only while enabled) |
| `/etc/intelshield/update.conf` | Optional `UPDATE_URL=` self-update source override |
| `/etc/suricata/intelshield/*.yaml` | Suricata config override drop-ins (see architecture section) |
| `/etc/nftables.d/intelshield-suricata-*.nft` | Suricata IPS/Firewall nftables rules |
| `/etc/suricata/enable.conf` | Rules forced ON (managed by transactional rules CLI) |
| `/etc/suricata/disable.conf` | Rules muted (SID-based self-heal + user entries) |
| `/etc/suricata/drop.conf` | Rules that DROP in IPS/Firewall mode |
| `/var/lib/intelshield/state.json` | Machine-readable state (Wazuh-ingestable) |
| `/var/lib/intelshield/suricata-fw-mode` | Firewall mode state: `on` / `off` |
| `/var/lib/intelshield/suricata-fw-mutex` | Mutex owner: `crowdsec` / `suricata` / `none` |
| `/var/lib/intelshield/preflight-risk.{txt,json}` | Risk report |
| `/var/backups/intelshield/` | Config snapshots |
| `/var/log/intelshield/forensics/` | Forensic bundles |
| `/var/clamav/quarantine/` | ClamAV quarantine vault |
| `/var/lib/intelshield/anti-rootkit/quarantine/` | Anti-rootkit quarantine |
| `/etc/sysctl.d/9*-intelshield-*.conf` | Kernel/network/security/perf drop-ins |

---

## Wazuh / SIEM integration

IntelShield integrates as a **Wazuh agent only** (installing a Wazuh *manager* is intentionally out of scope). It configures:

- **Log forwarding** for IntelShield, Suricata (`eve.json`), CrowdSec, UFW, auth, audit, ClamAV, and anti-rootkit logs
- **FIM** (syscheck) over the security-relevant config directories
- **Command/status collection** (a JSON status helper polled every 5 min)
- **Safe active response** -- evidence-collection only (sockets, decisions, failed units, state)

Point it at your manager with **Menu -> Wazuh (11) -> Install Wazuh Agent**.

---

## FAQ

**Will this lock me out of SSH?**
It's designed not to: SSH config is tested before reload, the port is re-allowed and rate-limited before UFW is enabled, and the IPS/Firewall layer excludes SSH and fails open. Still -- keep a second session open the first time.

**Does the Suricata IPS decrypt my VLESS traffic?**
No. Reality/TLS on :443 is encrypted end-to-end. IPS protects the host/management plane and blocks scanning/exploit attempts; it does not (and cannot) inspect proxy payloads.

**What is Suricata 8 Firewall Mode?**
An experimental mode that replaces traditional IDS/IPS with a deterministic packet pipeline and default-drop policy. Every packet NOT explicitly accepted by a rule is dropped. It uses Suricata 8's explicit action scopes (`accept:packet`, `drop:flow`, etc.) and rule hooks (`packet:filter`, `app:filter`). Requires Suricata 8+.

**How does CrowdSec coexist with Suricata Firewall Mode?**
Via nftables priority chain orchestration: CrowdSec evaluates at priority 0 (edge, IP reputation), survivors pass to Suricata at priority 10 (deep inspection). A mutex toggle prevents conflicts.

**Does IntelShield support IPv6?**
Yes. v8.6 adds full dual-stack support: `valid_ip()` validates IPv4, IPv6 (compressed/full/mixed), and CIDR notation (0-32 for v4, 0-128 for v6). HOME_NET auto-detects IPv6 egress and includes `::1/128` and `fd00::/8` ULA ranges. The allowlist injects IPv6 records into CrowdSec without breaking YAML parsers.

**Can I run just one component?**
Yes -- use **Select individual modules (2)** or the **Component control center (17)**.

**How do I update x-ui manually?**
Menu -> `S` -> **Disable sandbox** (or `--sandbox off`), run your update, then **Enable** it again.

**Is it idempotent?**
Re-running modules re-applies the managed config safely. Package installs are skipped when already present, and the Suricata include block / disable.conf managed block regenerate in place instead of duplicating.

**Does enabling the maintenance engine auto-reboot my relay?**
No. The OS maintenance job logs that a reboot is required and stops there. Automated reboots remain exclusively the Update Center's 01:11 policy, which you enable separately.

**A component update failed overnight -- what happened to the service?**
Nothing. Restarts only follow verified successes; failures are logged as `ALERT:` lines in `/var/log/intelshield-maintenance.log` and the component keeps running its previous working state (Suricata additionally rolls back to its pre-update ruleset snapshot).

---

## Disclaimer

IntelShield is provided **as-is, without warranty of any kind**. It modifies firewall, SSH, kernel, and service configuration and can affect connectivity. You are responsible for testing it in a non-production environment first and for ensuring you have authorization to modify the target system. The authors are not liable for lockouts, downtime, or data loss.

This is a **defensive** hardening tool. Use it only on infrastructure you own or are explicitly permitted to administer.

---

## License

Released under the **MIT License** -- see [`LICENSE`](LICENSE). If no license file is present yet, add one before publishing.

---

<p align="center"><em>IntelShield v8.6 -- harden fast, break nothing, revert anytime.</em></p>
