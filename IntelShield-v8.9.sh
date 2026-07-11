#!/usr/bin/env bash
#==============================================================================
#  IntelShield v8.9  —  Unified Hardening · Forensics · SIEM/XDR · Performance
#  Target : Ubuntu 22.04 / 24.04 LTS server + x-ui/3x-ui + Xray VLESS-Reality
#  Lineage: intelshield v2.5 (rich UI base) + IntelShield-AllInOne v1.3.1 (extras)
#           v3.0 adds Suricata inline IPS (+ CrowdSec coexistence), rule selection,
#           a toggleable x-ui/Xray sandbox, and a granular component control center.
#           v4.0 adds atomic self-healing Suricata rule updates and kernel/engine
#           unattended-upgrade isolation.
#           v5.0 reverts v4.0's hand-built CrowdSec repo (which could break apt-get
#           update) back to the safe official fetched-installer method.
#           v6.0 adds an Update Center: package/full upgrade (no release upgrade),
#           firmware (fwupd) + driver updates, and an auto-update toggle that reboots
#           at 01:11 when a reboot is required; plus a Live Console mode that streams
#           real command output to the terminal (toggle in-menu or --verbose).
#           v6.0.1 fixes Suricata rule updates: the install now force-upgrades the
#           engine to the OISF PPA build, and a surgical self-heal disables only the
#           handful of engine-incompatible rules (keeping ~40k good ones) instead of
#           rejecting the whole set.
#           v7.0 makes the Live Console CONSTANT (on by default): every command and
#           its real output stream to the terminal (apt, freshclam, upgrades and all
#           run() actions), so the user always sees what is happening. Still logged;
#           can be silenced per-user via the in-menu toggle.
#           v8.0 — Suricata 7 / Ubuntu 24.04 overhaul + Maintenance Engine:
#             • suricata.yaml is never sed-edited again: every override lives in
#               /etc/suricata/intelshield/*.yaml drop-ins pulled in by ONE
#               marker-guarded include: block (Suricata 7 native include list).
#             • Rule self-heal is SID-based via suricata-update's own disable.conf
#               (no more line-number surgery on the merged rules file).
#             • Ubuntu 24.04 (noble) install fixes: PPA availability is verified
#               before trusting it, and the libhtp1→libhtp2 upgrade conflict is
#               auto-remediated.
#             • NEW Maintenance & Auto-Update Engine (opt-in, cron-based):
#               unattended OS upgrades, sequential component updates (Suricata
#               rules / CrowdSec hub / ClamAV sigs / Wazuh agent), secure script
#               self-update from GitHub, service restarts ONLY on verified update
#               success, everything audited in /var/log/intelshield-maintenance.log.
#           v8.3 — Suricata 8 Firewall Mode + nftables Orchestration overhaul:
#             • Experimental Firewall Mode: deterministic packet pipeline with
#               default-drop policy, explicit action scopes (accept:packet,
#               drop:flow) and rule hooks (packet:filter, app:filter).
#             • LibHTP C library dependency removed (moved to Rust in Suricata 8);
#               vendored Lua 5.4 engine accommodated.
#             • nftables priority chain orchestration: CrowdSec bouncer evaluates
#               at priority 0 (edge), survivors passed to Suricata NFQUEUE chain
#               at priority 10 (deep inspection). Mutex toggle prevents concurrent
#               IPS conflicts.
#             • Transactional rules: bidirectional rule definitions combining
#               request+response logic, 107 new keywords (entropy, luaxform,
#               absent), JSON dataset IoC context parsing.
#             • Dynamic rule state CLI: manages enable.conf / disable.conf /
#               drop.conf with atomic validation gates.
#             • CPU affinity auto-configuration, granular exception-policy
#               statistics, and self-healing rule compilation rollback.
#           v8.6 — Dual-stack IPv6 + transactional rule hardening:
#             • valid_ip() rewritten for full dual-stack: IPv4, IPv6
#               (compressed/full/mixed), zone IDs, CIDR (0-32 v4, 0-128 v6).
#             • PUB_IP detection includes IPv6 egress fallback.
#             • HOME_NET auto-detects IPv6 egress and generates bracket-
#               notation with ::1/128 and fd00::/8 ULA ranges.
#             • suricata_rule_state_toggle() upgraded to 5-gate atomic
#               execution: validate, backup, atomic write, verify, cleanup.
#             • suricata_apply_transactional_rules() implements deterministic
#               snapshot -> validate -> apply -> verify -> restart-or-rollback.
#           v8.9 — IPv6 validation fix + YAML allowlist hardening:
#             • valid_ip() IPv6 tokenization fixed: replaced fragile
#               ${addr//::/ } word-split with sentinel-based IFS=':' read
#               tokenization that correctly handles ::1, 2001:db8::1, etc.
#             • allowlist_add() rewritten: atomic line-by-line YAML insertion,
#               duplicate detection (cscli + grep), preserves exact indentation,
#               no more fragile sed -i line-appending.
#             • sandbox_apply() verified complete with per-unit atomic gate,
#               restart_or_rollback integration, and single-unit fallback.
#==============================================================================
set -o pipefail
export DEBIAN_FRONTEND=noninteractive

APP="IntelShield"; VERSION="8.9"
LOG="/var/log/intelshield.log"
BT="IntelShield v${VERSION} | Hardening · Forensics · SIEM/XDR · Performance"

# --- state / profiles / risk -------------------------------------------------
STATE_DIR="/var/lib/intelshield"
STATE_DB="${STATE_DIR}/state.json"
PROFILE_FILE="${STATE_DIR}/active-profile"
RISK_REPORT="${STATE_DIR}/preflight-risk.txt"
RISK_JSON="${STATE_DIR}/preflight-risk.json"
STARTUP_BACKUP_STAMP="${STATE_DIR}/last-startup-backup"

# --- crowdsec / suricata -----------------------------------------------------
ALLOWLIST_FILE="/etc/crowdsec/parsers/s02-enrich/00-admin-allowlist.yaml"
ACQUIS_FILE="/etc/crowdsec/acquis.d/suricata.yaml"
SURICATA_YAML="/etc/suricata/suricata.yaml"
SURICATA_THRESHOLD="/etc/suricata/threshold.config"
SURICATA_LOCAL_RULES="/etc/suricata/rules/intelshield-tls-metadata.rules"
# Suricata 7 drop-in override directory: every IntelShield tweak to the engine
# config is a named yaml here, wired in by ONE marker-guarded `include:` block
# appended to suricata.yaml. suricata.yaml itself is never sed-edited.
SURICATA_INCLUDE_DIR="/etc/suricata/intelshield"
# suricata-update reads these from /etc/suricata automatically on the next run
SURICATA_ENABLE_CONF="/etc/suricata/enable.conf"
SURICATA_DISABLE_CONF="/etc/suricata/disable.conf"
SURICATA_DROP_CONF="/etc/suricata/drop.conf"
# IPS (inline / NFQUEUE) state, managed by IntelShield only
SURICATA_MODE_FILE="${STATE_DIR}/suricata-mode"           # 'ids' | 'ips'
SURICATA_IPS_DROPIN="/etc/systemd/system/suricata.service.d/99-intelshield-ips.conf"
SURICATA_IPS_NFT="/etc/nftables.d/intelshield-suricata-ips.nft"
SURICATA_IPS_SVC="/etc/systemd/system/intelshield-suricata-ips-nft.service"

# --- Suricata 8 Firewall Mode (v8.3) ----------------------------------------
# Suricata 8's experimental firewall mode uses a deterministic packet pipeline
# with a default-drop policy. Unlike traditional IDS/IPS modes, the firewall
# mode operates as a full stateful firewall engine with explicit action scopes.
SURICATA_FW_MODE_FILE="${STATE_DIR}/suricata-fw-mode"     # 'off' | 'on'
SURICATA_FW_DROPIN="/etc/systemd/system/suricata.service.d/99-intelshield-fw.conf"
SURICATA_FW_NFT="/etc/nftables.d/intelshield-suricata-fw.nft"
SURICATA_FW_SVC="/etc/systemd/system/intelshield-suricata-fw-nft.service"
SURICATA_FW_CHAIN="intelshield_suricata_fw"
# nftables priority orchestration:
#   CrowdSec bouncer:  priority 0   (edge — cheap IP-reputation drops)
#   Suricata FW mode:  priority 10  (deep packet inspection, deterministic pipeline)
#   Suricata IPS mode: priority 100 (legacy inline NFQUEUE, kept for compat)
SURICATA_FW_PRIORITY=10
SURICATA_CROWDSEC_PRIORITY=0
# Mutex state: prevents enabling both CrowdSec bouncer AND Suricata FW mode
# when concurrent execution constraints exist (only one can own the packet path)
SURICATA_MUTEX_FILE="${STATE_DIR}/suricata-fw-mutex"     # 'crowdsec' | 'suricata' | 'none'
# Suricata 8 rule management: transactional rules + new keywords
SURICATA_DATASETS_DIR="/var/lib/suricata/datasets"

# --- x-ui / Xray systemd sandbox --------------------------------------------
SANDBOX_DROPIN_NAME="99-intelshield-sandbox.conf"
SANDBOX_MDWE_FILE="${STATE_DIR}/sandbox-mdwe"             # 'on' | 'off' (default off for x-ui compatibility)

# --- update center -----------------------------------------------------------
UPGRADE_BLACKLIST="/etc/apt/apt.conf.d/51intelshield-blacklist"   # kernel/engine auto-upgrade guard
UPDATE_AUTOCONF="/etc/apt/apt.conf.d/52intelshield-autoupdate"    # auto-update + 01:11 reboot policy
AUTO_REBOOT_TIME="01:11"

# --- maintenance & auto-update engine (v8.0) ----------------------------------
MAINT_LOG="/var/log/intelshield-maintenance.log"       # dedicated cron audit trail
MAINT_CRON="/etc/cron.d/intelshield-maintenance"       # opt-in; written ONLY from the menu
MAINT_LOCK="/run/intelshield-maintenance.lock"         # flock guard: one run at a time
MAINT_LOGROTATE="/etc/logrotate.d/intelshield-maintenance"
UPDATE_CONF="/etc/intelshield/update.conf"             # optional UPDATE_URL= override
UPDATE_URL_DEFAULT="https://raw.githubusercontent.com/arioofarmani/Intelgate-Ubuntu-shield/main/IntelShield.sh"
# apt calls made from cron wait for a busy dpkg lock instead of failing instantly
# (used as: apt-get -o "$APT_LOCK_OPT" ...)
APT_LOCK_OPT="DPkg::Lock::Timeout=600"

# --- live console ------------------------------------------------------------
LIVE_FILE="${STATE_DIR}/live-console"     # 'on' | 'off' — stream command output to the terminal

# --- sysctl drop-ins ---------------------------------------------------------
SYSCTL_NET="/etc/sysctl.d/99-intelshield-network.conf"
SYSCTL_SEC="/etc/sysctl.d/97-intelshield-security.conf"
PERF_SYSCTL="/etc/sysctl.d/98-intelshield-performance.conf"

# --- backup / forensics ------------------------------------------------------
BACKUP_DIR="/var/backups/intelshield"
FORENSIC_DIR="/var/log/intelshield/forensics"
CRON_FILE="/etc/cron.d/intelshield-backup"
KEEP_BACKUPS=10

# --- ClamAV ------------------------------------------------------------------
CLAMAV_LOG="/var/log/clamav/custom_suite.log"
CLAM_QUAR="/var/clamav/quarantine"
CLAM_MANIFEST="${CLAM_QUAR}/.manifest.tsv"
CLAMD_CONF="/etc/clamav/clamd.conf"
FRESHCLAM_CONF="/etc/clamav/freshclam.conf"
CLAM_MAXSIZE="300M"
CLAM_EXCLUDE='^/(proc|sys|dev|run|mnt|media|snap|var/lib/clamav|var/clamav/quarantine|var/lib/docker|var/lib/containerd|var/lib/lxcfs)(/|$)'
CLAM_PROTECT='^/(usr|bin|sbin|lib|lib64|boot|etc|opt/3x-ui|var/lib)(/|$)'

# --- anti-rootkit ------------------------------------------------------------
ARK_DIR="${STATE_DIR}/anti-rootkit"
ARK_LOG_DIR="/var/log/intelshield/anti-rootkit"
ARK_QUAR="${ARK_DIR}/quarantine"
ARK_MANIFEST="${ARK_QUAR}/manifest.tsv"
ARK_CONF="/etc/intelshield/anti-rootkit.conf"

# --- Wazuh agent integration -------------------------------------------------
WAZUH_OSSEC="/var/ossec/etc/ossec.conf"
WAZUH_LOG="/var/log/intelshield-wazuh.log"
WAZUH_HELPER="/usr/local/bin/intelshieldctl-wazuh"
WAZUH_AR_SCRIPT="/var/ossec/active-response/bin/intelshield-safe-response.sh"

# --- runtime discovery (populated by preflight) ------------------------------
OS_DESC=""; OS_CODENAME=""; NIC=""; PUB_IP=""; SSH_PORT="22"; SSH_CLIENT_IP=""; PANEL_PORT=""

declare -A RESULT
declare -a TARGETS
COUNTER=0
TOTAL=0

# --- early --help (works without root) ---------------------------------------
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
cat <<EOF
IntelShield v${VERSION} — headless controller flags:
  --backup                                     Create a configuration snapshot
  --preflight                                  Run risk engine, print report path
  --state                                      Refresh state DB, print path
  --profile NAME                               Apply a profile:
                                               vps-balanced | vps-high | baremetal-high
                                               vpn-performance | forensic-audit | minimal-safe
  --clamav-scan full|smart                     Headless ClamAV scan (used by timers)
  --antirootkit-scan rkhunter|chkrootkit|all   Headless anti-rootkit scan (used by timers)
  --suricata-summary                           Export an eve.json summary
  --suricata-ips on|off                        Switch Suricata to inline IPS / back to IDS
                                               (pair with --non-interactive --yes)
  --suricata-fw on|off                         Toggle Suricata 8 Firewall Mode (deterministic
                                               pipeline, default-drop) — requires Suricata 8+
  --sandbox on|off                             Apply / remove the x-ui/Xray systemd sandbox
                                               (use --sandbox off before a manual panel update)
  --update safe|full                           Package upgrade (safe = no removals; never a
                                               release/distro upgrade)
  --auto-update on|off                         Enable/disable automatic updates + auto-reboot
                                               at 01:11 when a reboot is required
  --maintain os|components|self|all            Maintenance engine (used by the cron jobs):
                                               os = apt update+safe upgrade, components =
                                               Suricata rules / CrowdSec hub / ClamAV sigs /
                                               Wazuh agent, self = script self-update.
                                               Logs to /var/log/intelshield-maintenance.log
  --self-update                                Check the GitHub repo for a newer IntelShield,
                                               verify it and install it atomically
  --wazuh-menu                                 Open the Wazuh agent integration menu
  --uninstall                                  Open the uninstall / revert menu
  --yes, -y                                    Assume "yes" for confirmations (headless)
  --non-interactive                            No TUI; dialogs degrade to log lines
  --verbose, --live, -V                        Live console: print each command and stream
                                               its real output to the terminal (still logged)
  --help, -h                                   Show this help
Run with no arguments for the interactive TUI.
EOF
exit 0
fi

# --- auto-elevate ------------------------------------------------------------
# Only DEBIAN_FRONTEND is carried into the root shell (was -E: full env passthrough).
if [[ ${EUID:-999} -ne 0 ]]; then exec sudo --preserve-env=DEBIAN_FRONTEND bash "$(readlink -f "$0" 2>/dev/null || echo "$0")" "$@"; fi

# --- flag parsing (strip global switches before dispatch) --------------------
ASSUME_YES=0; NONINTERACTIVE=0
_is_args=()
for _is_arg in "$@"; do
  case "$_is_arg" in
    --yes|-y) ASSUME_YES=1 ;;
    --non-interactive|--noninteractive) ASSUME_YES=1; NONINTERACTIVE=1 ;;
    --verbose|--live|-V) LIVE_OUTPUT_FLAG=1 ;;
    *) _is_args+=("$_is_arg") ;;
  esac
done
set -- "${_is_args[@]}"
export ASSUME_YES NONINTERACTIVE

# --- directory + permission scaffolding --------------------------------------
mkdir -p "$(dirname "$LOG")" "$STATE_DIR" "$BACKUP_DIR" "$FORENSIC_DIR" \
         "$CLAM_QUAR" "$ARK_DIR" "$ARK_LOG_DIR" "$ARK_QUAR" "$(dirname "$ARK_CONF")"
touch "$LOG" "$WAZUH_LOG" "$MAINT_LOG" 2>/dev/null || true
chmod 750 /var/log/intelshield 2>/dev/null || true
chmod 700 "$STATE_DIR" "$BACKUP_DIR" "$FORENSIC_DIR" "$CLAM_QUAR" "$ARK_DIR" "$ARK_QUAR" "$ARK_LOG_DIR" 2>/dev/null || true
chmod 600 "$LOG" "$WAZUH_LOG" "$MAINT_LOG" 2>/dev/null || true

# --- private scratch dir (replaces predictable /tmp/.ea_* report files) -------
IS_TMP="$(mktemp -d /run/intelshield.XXXXXX 2>/dev/null || mktemp -d "${TMPDIR:-/tmp}/intelshield.XXXXXX")"
chmod 700 "$IS_TMP" 2>/dev/null || true
trap 'rm -rf "$IS_TMP" 2>/dev/null' EXIT


# ---------- core helpers -----------------------------------------------------
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }
# EXECUTION-WRAPPER CONTRACT (relied on by every install/update/rollback path):
# run() and run_capture() ALWAYS merge stderr into the captured/streamed output
# and ALWAYS return the wrapped command's REAL exit code — in live mode via
# PIPESTATUS[0] (tee would otherwise mask it), in quiet mode directly. Callers
# may therefore gate restarts/rollbacks on `run ...` without losing failures.
run(){
  log "+ $*"
  if (( ${LIVE_OUTPUT:-0} )) && [[ -t 1 ]]; then
    # echo the command, then stream combined stdout+stderr to BOTH the terminal and
    # the log. </dev/null keeps commands non-interactive; PIPESTATUS preserves rc.
    printf '\033[1;36m$ %s\033[0m\n' "$*"
    "$@" </dev/null 2>&1 | tee -a "$LOG"
    return "${PIPESTATUS[0]}"
  fi
  "$@" </dev/null >>"$LOG" 2>&1
}
# like run(), but captures combined output into a FILE ($1) for a later summary,
# while STILL streaming live to the terminal when the live console is on.
run_capture(){
  local out="$1"; shift; log "+ $*"
  if (( ${LIVE_OUTPUT:-0} )) && [[ -t 1 ]]; then
    printf '\033[1;36m$ %s\033[0m\n' "$*"
    "$@" </dev/null 2>&1 | tee "$out"
    return "${PIPESTATUS[0]}"
  fi
  "$@" </dev/null >"$out" 2>&1
}
have(){ command -v "$1" >/dev/null 2>&1; }
have_cs(){ command -v cscli >/dev/null 2>&1; }
rkhunter_present(){ have rkhunter; }
chkrootkit_present(){ have chkrootkit; }
wazuh_agent_present(){ [[ -x /var/ossec/bin/wazuh-control || -x /var/ossec/bin/agent-auth ]] || dpkg -s wazuh-agent >/dev/null 2>&1; }
# newline/tab/CR-safe JSON string escaper — a stray newline used to produce invalid
# state.json, which the Wazuh json logcollector then rejected.
json_escape(){ local s="${1:-}"; s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/ }; s=${s//$'\t'/ }; s=${s//$'\r'/ }; printf '%s' "$s"; }
# service-state helpers: `systemctl is-active` prints its state AND returns non-zero,
# so `$(... || echo missing)` used to capture TWO lines ("inactive\nmissing").
# These always emit exactly one token.
svc_exists(){ systemctl cat "$1" >/dev/null 2>&1; }
svc_state(){ svc_exists "$1" || { printf 'missing'; return 0; }; local s; s="$(systemctl is-active "$1" 2>/dev/null)"; printf '%s' "${s:-unknown}"; }
svc_enabled(){ local s; s="$(systemctl is-enabled "$1" 2>/dev/null)"; printf '%s' "${s:-disabled}"; }
# Atomic post-update gate: restart a unit and VERIFY it comes back. If it does
# not, run the supplied rollback function (restores the previous working state),
# restart again, and return 1. Used by the maintenance engine, Suricata rule
# updates and the config drop-in writers so a bad update can never leave a
# critical service down.
restart_or_rollback(){
  local unit="$1" rollback="${2:-}"
  run systemctl restart "$unit"; sleep 2
  systemctl is-active --quiet "$unit" && return 0
  log "ALERT: $unit failed to restart after update — rolling back to previous state"
  [[ -n "$rollback" ]] && "$rollback"
  run systemctl restart "$unit" || true
  if systemctl is-active --quiet "$unit"; then log "$unit recovered after rollback"
  else log "ALERT: $unit is STILL down after rollback — manual intervention required"; fi
  return 1
}
# canonical self-install so timers/cron never reference a moved or space-laden path
install_self(){ local dst=/usr/local/sbin/intelshield src; src="$(readlink -f "$0" 2>/dev/null || echo "$0")"; if [[ "$src" != "$dst" ]]; then install -m 750 "$src" "$dst" 2>/dev/null || { printf '%s' "$src"; return 0; }; fi; printf '%s' "$dst"; }

# ---------- TUI helpers (terminal-aware + headless-safe) ---------------------
# UI=0 when there is no usable TTY, or when --non-interactive was passed. In that
# mode dialogs degrade to log lines / default answers so systemd timers and scripted
# runs never block on whiptail (fixes the dead --yes/--non-interactive switches).
UI=1; { [[ -t 0 && -t 1 ]] && (( ${NONINTERACTIVE:-0} == 0 )); } || UI=0
# Live console is ON BY DEFAULT (constant): run() prints each command and streams its
# real output to the terminal (still tee'd to the log) so the user always sees what is
# happening. It only turns off if the user explicitly saved 'off' via the toggle.
# --verbose/--live forces it on regardless.
LIVE_OUTPUT=1
[[ "$(cat "$LIVE_FILE" 2>/dev/null)" == off ]] && LIVE_OUTPUT=0
(( ${LIVE_OUTPUT_FLAG:-0} )) && LIVE_OUTPUT=1
declare -A MENU_LAST
# clamp requested height/width to the live terminal so whiptail can't error out on
# small consoles; also floor the values so tiny terminals still render.
ui_size(){ local th=24 tw=80 h="$1" w="$2"; read -r th tw < <(stty size 2>/dev/null || echo "24 80"); (( th<10 )) && th=24; (( tw<40 )) && tw=80; (( h>th-1 )) && h=$((th-1)); (( w>tw-2 )) && w=$((tw-2)); (( h<8 )) && h=8; (( w<40 )) && w=40; printf '%s %s' "$h" "$w"; }
msg(){      (( UI )) || { log "MSG [$1] ${2//$'\n'/ }"; return 0; }; local h w; read -r h w < <(ui_size "${3:-16}" "${4:-78}"); whiptail --backtitle "$BT" --title " i  $1 " --msgbox "\n$2" "$h" "$w"; }
yesno(){    (( UI )) || { (( ${ASSUME_YES:-0} )) && return 0 || return 1; }; local h w; read -r h w < <(ui_size "${3:-15}" "${4:-78}"); whiptail --backtitle "$BT" --title " ?  $1 " --yesno "\n$2" "$h" "$w"; }
# destructive confirmations default to "No" so an Enter-mash can't wipe state
yesno_danger(){ (( UI )) || { (( ${ASSUME_YES:-0} )) && return 0 || return 1; }; local h w; read -r h w < <(ui_size "${3:-15}" "${4:-78}"); whiptail --backtitle "$BT" --title " !  $1 " --defaultno --yesno "\n$2" "$h" "$w"; }
infobox(){  (( UI )) || { log "INFO [$1] ${2//$'\n'/ }"; return 0; }
            # in live mode, print a plain banner so it doesn't fight the streamed output
            if (( ${LIVE_OUTPUT:-0} )) && [[ -t 1 ]]; then printf '\n\033[1;33m==> %s\033[0m\n' "$1"; printf '%b\n' "$2"; return 0; fi
            local h w; read -r h w < <(ui_size "${3:-10}" "${4:-72}"); whiptail --backtitle "$BT" --title " *  $1 " --infobox "\n$2" "$h" "$w"; }
showfile(){ (( UI )) || { log "REPORT [$1] -> $2"; return 0; }; local h w; read -r h w < <(ui_size "${3:-30}" "${4:-105}"); whiptail --backtitle "$BT" --title " =  $1 " --scrolltext --textbox "$2" "$h" "$w"; }
input(){    (( UI )) || { printf '%s' "${3:-}"; return 0; }; local h w; read -r h w < <(ui_size "${4:-12}" "${5:-78}"); whiptail --backtitle "$BT" --title " >  $1 " --inputbox "\n$2" "$h" "$w" "${3:-}" 3>&1 1>&2 2>&3; }
# masked entry for secrets (enrollment tokens, passwords) — never echoed on screen
secret_input(){ (( UI )) || { printf ''; return 0; }; local h w; read -r h w < <(ui_size "${3:-12}" "${4:-78}"); whiptail --backtitle "$BT" --title " >  $1 " --passwordbox "\n$2" "$h" "$w" 3>&1 1>&2 2>&3; }
# menu auto-remembers the last chosen tag per title (--default-item) with no caller changes
menu(){ (( UI )) || return 1; local t="$1" p="$2" h w lh out rc; shift 2; read -r h w < <(ui_size 24 96); lh=$((h-10)); (( lh<3 )) && lh=3; out=$(whiptail --backtitle "$BT" --title " + $t " --default-item "${MENU_LAST[$t]:-}" --menu "\n$p" "$h" "$w" "$lh" "$@" 3>&1 1>&2 2>&3); rc=$?; [[ $rc -eq 0 ]] && MENU_LAST["$t"]="$out"; printf '%s' "$out"; return $rc; }
checklist(){ (( UI )) || return 1; local t="$1" p="$2" h w lh; shift 2; read -r h w < <(ui_size 26 100); lh=$((h-10)); (( lh<3 )) && lh=3; whiptail --backtitle "$BT" --title " + $t " --checklist "\n$p" "$h" "$w" "$lh" "$@" 3>&1 1>&2 2>&3; }
need_cs(){ have_cs || { msg "CrowdSec" "CrowdSec infrastructure not detected. Install the engine module first."; return 1; }; }

# Dual-stack IP/CIDR validator: accepts IPv4, IPv6, and CIDR notation.
# Returns 0 for valid, 1 for invalid. Supports compressed IPv6 (::), mixed
# notation (::ffff:192.168.1.1), and link-local with zone IDs (%eth0).
# Pure bash tokenization — no word-splitting hacks, no sed, no external tools.
valid_ip(){
  local addr="${1%%/*}" cidr="" stripped
  [[ "$1" == */* ]] && cidr="${1#*/}"
  # Strip zone ID (e.g. fe80::1%eth0) — valid in addresses but not in nftables
  addr="${addr%%\%*}"
  # --- IPv4 (with optional dotted-quad CIDR) ---
  if [[ "$addr" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    local a b c d o
    IFS=. read -r a b c d <<<"$addr"
    for o in "$a" "$b" "$c" "$d"; do
      [[ "$o" =~ ^[0-9]+$ ]] || return 1
      (( 10#"$o" >= 0 && 10#"$o" <= 255 )) || return 1
    done
    [[ -z "$cidr" ]] && return 0
    [[ "$cidr" =~ ^[0-9]+$ ]] || return 1
    (( 10#"$cidr" >= 0 && 10#"$cidr" <= 32 )) || return 1
    return 0
  fi
  # --- IPv6 (compressed, full, or mixed) ---
  # Strip all colons and hex digits; what remains must be only dots (mixed)
  # or empty (pure IPv6). Then validate the hex groups.
  stripped="${addr//:/}"            # remove all colons
  stripped="${stripped//[0-9a-fA-F]/}"  # remove all hex
  if [[ -z "$stripped" ]]; then
    # Pure IPv6: count colon-separated groups (compressed :: counts as one or more)
    local ngroups="${addr//[^:]}"
    ngroups="${#ngroups}"
    # A valid IPv6 has 7 colons (8 groups) or 1-6 colons if :: is present
    if [[ "$addr" == *"::"* ]]; then
      # With :: — must have <= 6 colons (at least 2 groups implied by ::)
      (( ngroups <= 6 )) || return 1
    else
      # Without :: — must have exactly 7 colons (8 groups)
      (( ngroups == 7 )) || return 1
    fi
    # Validate each group: replace :: with a sentinel, then split on colons.
    # Use read IFS=: to tokenize — this handles empty groups from :: correctly
    # without word-splitting or space substitution.
    local expanded="$addr" grp
    # Expand :: to a known sentinel (unique string that can't be a hex group)
    expanded="${expanded//::/:__COMPRESSED__:}"
    # Split the expanded string on colons and validate each token
    local IFS=':'
    set -- $expanded   # word-split on IFS=: into positional params
    for grp in "$@"; do
      [[ -z "$grp" || "$grp" == "__COMPRESSED__" ]] && continue
      [[ "$grp" =~ ^[0-9a-fA-F]{1,4}$ ]] || return 1
    done
    set --              # clear positional params
  elif [[ "$stripped" == *"."* ]]; then
    # Mixed notation (e.g. ::ffff:192.168.1.1) — validate the trailing IPv4 part
    local ipv4="${addr##*:}"
    [[ "$ipv4" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
    local a b c d o
    IFS=. read -r a b c d <<<"$ipv4"
    for o in "$a" "$b" "$c" "$d"; do
      [[ "$o" =~ ^[0-9]+$ ]] || return 1
      (( 10#"$o" >= 0 && 10#"$o" <= 255 )) || return 1
    done
  else
    return 1
  fi
  # CIDR validation for IPv6 (0-128)
  [[ -z "$cidr" ]] && return 0
  [[ "$cidr" =~ ^[0-9]+$ ]] || return 1
  (( 10#"$cidr" >= 0 && 10#"$cidr" <= 128 )) || return 1
  return 0
}
valid_port(){ local p="$1" a b; if [[ "$p" =~ ^[0-9]{1,5}$ ]]; then (( p>=1 && p<=65535 )); return $?; fi; if [[ "$p" =~ ^([0-9]{1,5}):([0-9]{1,5})$ ]]; then a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}; (( a>=1 && a<=65535 && b>=1 && b<=65535 && a<b )); return $?; fi; return 1; }

# ---------- preflight environment + architecture discovery -------------------
preflight(){
  command -v whiptail >/dev/null 2>&1 || { apt-get update -y >>"$LOG" 2>&1; apt-get install -y whiptail >>"$LOG" 2>&1; }
  local p
  for p in curl ca-certificates gnupg lsb-release tar gzip iproute2 procps util-linux jq; do
    dpkg -s "$p" >/dev/null 2>&1 || apt-get install -y "$p" >>"$LOG" 2>&1
  done
  OS_DESC="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  OS_CODENAME="$(. /etc/os-release 2>/dev/null; echo "${VERSION_CODENAME:-}")"
  case "$OS_CODENAME" in
    jammy|noble) : ;;   # 22.04 / 24.04 LTS — fully supported
    *) log "WARN: untested distro codename '${OS_CODENAME:-unknown}' — IntelShield targets Ubuntu 22.04 (jammy) / 24.04 (noble)" ;;
  esac
  SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  [[ -z "$SSH_PORT" ]] && SSH_PORT="$(awk '/^[Pp]ort /{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"
  [[ -z "$SSH_PORT" ]] && SSH_PORT=22
  NIC="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  [[ -z "$NIC" ]] && NIC="$(ip -o link show up 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}')"
  # Dual-stack: prefer IPv4 egress (Suricata HOME_NET is simpler), but detect IPv6 too
  PUB_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ -z "$PUB_IP" ]] && PUB_IP="$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null)"
  # If no IPv4, try IPv6
  if [[ -z "$PUB_IP" ]]; then
    PUB_IP="$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    [[ -z "$PUB_IP" ]] && PUB_IP="$(curl -s6 --max-time 5 ifconfig.me 2>/dev/null)"
  fi
  SSH_CLIENT_IP="${SSH_CONNECTION%% *}"
  [[ -z "$SSH_CLIENT_IP" ]] && SSH_CLIENT_IP="$(who am i 2>/dev/null | sed -n 's/.*(\(.*\)).*/\1/p')"
  PANEL_PORT="$(ss -tlnp 2>/dev/null | awk '/x-ui|3x-ui/{n=split($4,a,":"); print a[n]}' | head -1)"
}


# ---------- shared allowlist controls -----------------------------------------
# CrowdSec YAML allowlist injector — safe, duplicate-aware, preserves YAML structure.
# Writes to the parser-level allowlist file (s02-enrich/00-admin-allowlist.yaml)
# or uses cscli allowlists when available. Duplicate entries are skipped.
allowlist_add(){
  local ip="$1" ok=1
  # --- Path 1: cscli native allowlists (preferred) ---
  if have_cs && cscli allowlists list >/dev/null 2>&1; then
    cscli allowlists create harden -d "intelshield managed" >>"$LOG" 2>&1 || true
    # Check for duplicate before adding
    if cscli allowlists list harden -o raw 2>/dev/null | grep -qF "$ip"; then
      log "allowlist_add: $ip already in cscli allowlist 'harden'"
      ok=0
    elif cscli allowlists add harden "$ip" >>"$LOG" 2>&1; then
      ok=0
    fi
  fi
  # --- Path 2: YAML file fallback (parser-level allowlist) ---
  if [[ $ok -ne 0 ]]; then
    mkdir -p "$(dirname "$ALLOWLIST_FILE")"
    # Scaffold the file if it doesn't exist
    if [[ ! -f "$ALLOWLIST_FILE" ]]; then
      cat >"$ALLOWLIST_FILE" <<'YAML'
name: crowdsecurity/harden-allowlist
description: "intelshield managed allowlist"
whitelist:
  reason: "trusted admin configurations"
  ip:
  cidr:
YAML
    fi
    # Determine target section (ip vs cidr) and check for duplicate
    local section="ip" tmp="$IS_TMP/allowlist.yaml.tmp"
    [[ "$ip" == */* ]] && section="cidr"
    # Check if this exact entry already exists in the file
    if grep -qF "\"$ip\"" "$ALLOWLIST_FILE" 2>/dev/null; then
      log "allowlist_add: $ip already in $ALLOWLIST_FILE ($section section)"
      ok=0
    else
      # Atomically insert after the section header line.
      # Strategy: read line-by-line, insert after the "  section:" line.
      # This preserves exact YAML indentation and doesn't rely on fragile sed ranges.
      local found=0 wrote=0
      while IFS= read -r line; do
        printf '%s\n' "$line"
        # Insert after the section header (e.g. "  ip:" or "  cidr:")
        if [[ "$wrote" -eq 0 && "$line" =~ ^[[:space:]]${section}:$ ]]; then
          printf '    - "%s"\n' "$ip"
          found=1; wrote=1
        fi
      done < "$ALLOWLIST_FILE" > "$tmp"
      if [[ "$found" -eq 1 && -s "$tmp" ]]; then
        mv -f "$tmp" "$ALLOWLIST_FILE"
        log "allowlist_add: inserted $ip into $ALLOWLIST_FILE ($section section)"
        ok=0
      else
        rm -f "$tmp"
        log "allowlist_add: WARN — section '$section' not found in $ALLOWLIST_FILE; appending"
        # Fallback: append to the correct section at end of file
        printf '  %s:\n    - "%s"\n' "$section" "$ip" >> "$ALLOWLIST_FILE"
        ok=0
      fi
    fi
  fi
  run systemctl reload crowdsec || run systemctl restart crowdsec
  return $ok
}


# ---------- JSON state database ---------------------------------------------
state_write(){
  mkdir -p "$STATE_DIR"
  local virt sb lock app ufwst profile suri suri_mode crowd bouncer clam audit ark mem disk mitig port443 panel_public xray xui wazuh_active wazuh_manager wazuh_block wazuh_ar maintcron
  virt=$(systemd-detect-virt 2>/dev/null || echo none); sb=$(mokutil --sb-state 2>/dev/null | tr '\n' ' ' || echo unknown); lock=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo unavailable); app=$(svc_state apparmor)
  ufwst=$(ufw status 2>/dev/null | head -1 | sed 's/Status: //'); [[ -z "$ufwst" ]] && ufwst=missing; profile=$(cat "$PROFILE_FILE" 2>/dev/null || echo none)
  suri=$(svc_state suricata); crowd=$(svc_state crowdsec); bouncer=$(svc_state crowdsec-firewall-bouncer); clam=$(svc_state clamav-freshclam); audit=$(svc_state auditd); xui=$(svc_state x-ui); xray=$(svc_state xray); suri_mode=$(cat "$SURICATA_MODE_FILE" 2>/dev/null || echo ids); suri_fw=$(cat "$SURICATA_FW_MODE_FILE" 2>/dev/null || echo off); suri_mutex=$(cat "$SURICATA_MUTEX_FILE" 2>/dev/null || echo none)
  mem=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0); disk=$(df -Pm / | awk 'NR==2{print $4}' 2>/dev/null || echo 0); grep -qw mitigations=off /proc/cmdline && mitig=true || mitig=false
  ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\])443$' && port443=true || port443=false; panel_public=false; [[ -n "${PANEL_PORT:-}" ]] && ss -tln 2>/dev/null | grep -E "(0\.0\.0\.0|\[::\]|\*)[:.]${PANEL_PORT}\b" >/dev/null && panel_public=true
  ark="rkhunter=$(rkhunter_present&&echo installed||echo missing), chkrootkit=$(chkrootkit_present&&echo installed||echo missing)"
  wazuh_active=$(svc_state wazuh-agent); wazuh_manager=$(grep -m1 '<address>' "$WAZUH_OSSEC" 2>/dev/null | sed -E 's/.*<address>([^<]+)<\/address>.*/\1/' || true); grep -q 'INTELSHIELD-WAZUH-MANAGED-START' "$WAZUH_OSSEC" 2>/dev/null && wazuh_block=true || wazuh_block=false; [[ -x "$WAZUH_AR_SCRIPT" ]] && wazuh_ar=true || wazuh_ar=false
  maintcron=disabled; [[ -f "$MAINT_CRON" ]] && maintcron=enabled
  # write atomically so a Wazuh json tail never reads a half-written file
  cat >"${STATE_DB}.tmp" <<EOF
{"version":"$VERSION","updated_at":"$(date -Is)","profile":"$(json_escape "$profile")","host":{"os":"$(json_escape "${OS_DESC:-}")","virt":"$(json_escape "$virt")","nic":"$(json_escape "${NIC:-}")","public_ip":"$(json_escape "${PUB_IP:-}")","ssh_port":"$(json_escape "${SSH_PORT:-}")","admin_ssh":$([[ -n "${SSH_CONNECTION:-}" ]] && echo true || echo false)},"security":{"secure_boot":"$(json_escape "$sb")","kernel_lockdown":"$(json_escape "$lock")","apparmor":"$(json_escape "$app")","ufw":"$(json_escape "$ufwst")","mitigations_off":$mitig},"services":{"crowdsec":"$(json_escape "$crowd")","bouncer":"$(json_escape "$bouncer")","suricata":"$(json_escape "$suri")","suricata_mode":"$(json_escape "$suri_mode")","suricata_fw_mode":"$(json_escape "$suri_fw")","suricata_mutex":"$(json_escape "$suri_mutex")","clamav_freshclam":"$(json_escape "$clam")","auditd":"$(json_escape "$audit")","xui":"$(json_escape "$xui")","xray":"$(json_escape "$xray")","maintenance_cron":"$(json_escape "$maintcron")"},"anti_rootkit":"$(json_escape "$ark")","wazuh":{"mode":"agent","agent_status":"$(json_escape "$wazuh_active")","manager":"$(json_escape "$wazuh_manager")","intelshield_log_forwarding":$wazuh_block,"active_response_safe_mode":$wazuh_ar},"resources":{"memory_mb":$mem,"root_free_mb":$disk},"vpn":{"port_443_listening":$port443,"panel_port":"$(json_escape "${PANEL_PORT:-}")","panel_public":$panel_public}}
EOF
  chmod 600 "${STATE_DB}.tmp" 2>/dev/null || true
  mv -f "${STATE_DB}.tmp" "$STATE_DB" 2>/dev/null || true
}
state_view(){ state_write; showfile "State Database" "$STATE_DB" 36 120; }


# ---------- preflight risk engine -------------------------------------------
preflight_risk_engine(){ local score=100 risk=() warn=() virt sb lock app ufw_active custom_ssh admin_ssh port443 panel_public mitig_off disk mem virt_note; virt=$(systemd-detect-virt 2>/dev/null || echo none); [[ "$virt" == none ]] && virt_note="bare metal or unknown" || virt_note="$virt"; sb=$(mokutil --sb-state 2>/dev/null || echo "unknown / mokutil unavailable"); lock=$(cat /sys/kernel/security/lockdown 2>/dev/null || echo unavailable); app=$(svc_state apparmor); ufw status 2>/dev/null | grep -q active && ufw_active=yes || ufw_active=no; [[ "${SSH_PORT:-22}" != 22 ]] && custom_ssh=yes || custom_ssh=no; [[ -n "${SSH_CONNECTION:-}" ]] && admin_ssh=yes || admin_ssh=no; ss -tln 2>/dev/null | awk '{print $4}' | grep -Eq '(:|\])443$' && port443=yes || port443=no; panel_public=no; [[ -n "${PANEL_PORT:-}" ]] && ss -tln 2>/dev/null | grep -E "(0\.0\.0\.0|\[::\]|\*)[:.]${PANEL_PORT}\b" >/dev/null && panel_public=yes; grep -qw mitigations=off /proc/cmdline && mitig_off=yes || mitig_off=no; disk=$(df -Pm / | awk 'NR==2{print $4}' 2>/dev/null || echo 0); mem=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0); [[ "$ufw_active" == no ]] && { risk+=("UFW firewall is not active"); score=$((score-15)); }; [[ "$admin_ssh" == no ]] && warn+=("Admin SSH session not detected; source detection less reliable"); [[ "$port443" == no ]] && warn+=("No listener on port 443; verify x-ui/Xray inbound"); [[ "$panel_public" == yes ]] && { risk+=("x-ui/3x-ui panel appears publicly bound on port ${PANEL_PORT}"); score=$((score-20)); }; [[ "$mitig_off" == yes ]] && { risk+=("CPU mitigations disabled with mitigations=off"); score=$((score-25)); }; [[ "$app" != active ]] && { warn+=("AppArmor is not active"); score=$((score-5)); }; [[ "$lock" == unavailable ]] && warn+=("Kernel lockdown unavailable/disabled"); [[ "$sb" != *enabled* && "$sb" != *Enabled* ]] && warn+=("Secure Boot not enabled or not verifiable"); (( disk < 2048 )) && { risk+=("Root filesystem has less than 2GB free (${disk} MB)"); score=$((score-15)); }; (( mem < 1500 )) && warn+=("RAM below 1.5GB; keep heavy components lightweight"); (( score < 0 )) && score=0; { echo "IntelShield Preflight Risk Report - $(date -Is)"; echo "Security readiness score: $score/100"; echo; echo "Virtualization/container: $virt_note"; echo "Secure Boot: $sb"; echo "Kernel lockdown: $lock"; echo "AppArmor: $app"; echo "UFW active: $ufw_active"; echo "SSH port: ${SSH_PORT:-?} (custom: $custom_ssh)"; echo "Admin over SSH: $admin_ssh"; echo "443 listener: $port443"; echo "Panel public exposure: $panel_public (port: ${PANEL_PORT:-unknown})"; echo "CPU mitigations disabled: $mitig_off"; echo "Root free MB: $disk"; echo "RAM MB: $mem"; echo; echo "High-risk findings:"; printf ' - %s\n' "${risk[@]:-None}"; echo; echo "Warnings:"; printf ' - %s\n' "${warn[@]:-None}"; } >"$RISK_REPORT"; cat >"$RISK_JSON" <<EOF
{"score":$score,"virt":"$(json_escape "$virt_note")","ufw_active":"$ufw_active","admin_ssh":"$admin_ssh","port443":"$port443","panel_public":"$panel_public","mitigations_off":"$mitig_off","root_free_mb":$disk,"memory_mb":$mem,"updated_at":"$(date -Is)"}
EOF
state_write; { [[ -t 1 ]] && showfile "Preflight Risk Engine" "$RISK_REPORT" 36 120 || true; }; }


# ---------- backup / restore snapshot system --------------------------------
collect_backup_targets(){
  TARGETS=()
  local p
  for p in /etc/ssh /etc/ufw /etc/sysctl.conf /etc/sysctl.d /etc/crowdsec \
           /etc/suricata /etc/default/suricata /etc/modules-load.d \
           /etc/apt/apt.conf.d/20auto-upgrades /etc/apt/apt.conf.d/51intelshield-blacklist \
           /etc/apt/apt.conf.d/52intelshield-autoupdate /etc/nftables.conf \
           /etc/audit /etc/aide /etc/rkhunter.conf /etc/rkhunter.conf.local /etc/chkrootkit \
           /etc/intelshield \
           /etc/systemd/system/x-ui.service.d /etc/systemd/system/xray.service.d \
           /etc/x-ui /etc/xray /usr/local/etc/xray \
           "$STATE_DB" "$PROFILE_FILE" "$WAZUH_OSSEC" "$WAZUH_HELPER" "$WAZUH_AR_SCRIPT" \
           "$MAINT_CRON" "$UPDATE_CONF" \
           /usr/local/x-ui/x-ui.db /opt/3x-ui/x-ui.db; do
    [[ -e "$p" ]] && TARGETS+=("$p")
  done
}


prune_backups(){
  local keep="${1:-$KEEP_BACKUPS}" old
  ls -1t "$BACKUP_DIR"/config_snapshot_*.tar.gz 2>/dev/null | tail -n +"$((keep+1))" | while read -r old; do
    rm -f "$old" "${old}.txt"; log "Pruned archaic snapshot: $old"
  done
}

do_backup(){
  collect_backup_targets
  [[ ${#TARGETS[@]} -eq 0 ]] && { log "Backup failure: target arrays empty"; return 1; }
  local tag archive
  tag="$(date +%Y%m%d_%H%M%S)"
  archive="${BACKUP_DIR}/config_snapshot_${tag}.tar.gz"
  {
    echo "INTELSHIELD ENVIRONMENT SNAPSHOT RESOURCE"
    echo "Timestamp : $(date)"
    echo "Hostname  : $(hostname)"
    echo "Kernel    : $(uname -r)"
    echo "Paths     :"
    printf '  - %s\n' "${TARGETS[@]}"
  } >"${archive}.txt" 2>/dev/null
  if tar -czpf "$archive" "${TARGETS[@]}" >>"$LOG" 2>&1 && tar -tzf "$archive" >/dev/null 2>&1; then
    chmod 600 "$archive" "${archive}.txt" 2>/dev/null || true  # archives hold host keys + x-ui.db
    prune_backups
    echo "$archive"
    return 0
  fi
  rm -f "$archive" "${archive}.txt" 2>/dev/null
  return 1
}

m_backup_system(){
  infobox "Backup Engine" "Compiling and verifying compressed state configurations..."
  local a
  if a="$(do_backup)"; then
    msg "Backup Matrix" "Snapshot successfully archived:\n  $a\n\nManifest structural details mapping saved to standard text log file. Retaining latest $KEEP_BACKUPS entries."
    return 0
  else
    msg "Backup Failure" "An unhandled error occurred during archival packaging. View $LOG for details."
    return 1
  fi
}

inspect_snapshot(){
  local archives a args=() chosen
  mapfile -t archives < <(find "$BACKUP_DIR" -name 'config_snapshot_*.tar.gz' -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)
  [[ ${#archives[@]} -eq 0 ]] && { msg "Snapshot Inventory" "No archive configurations found inside workspace target directories."; return; }
  for a in "${archives[@]}"; do args+=("$a" "$(basename "$a")"); done
  chosen=$(menu "Archive Inspection" "Select target snapshot to inspect file properties:" "${args[@]}") || return
  { echo "=== MANIFEST ==="; cat "${chosen}.txt" 2>/dev/null || echo "(No structural metadata raw text metadata properties)"; echo; echo "=== COMPRESSED INTERNAL ARRAYS ==="; tar -tzf "$chosen" 2>&1; } >"$IS_TMP/inspect"
  showfile "Snapshot Layout: $(basename "$chosen")" "$IS_TMP/inspect"
}

m_restore_interface(){
  local archives a args=() chosen
  mapfile -t archives < <(find "$BACKUP_DIR" -name 'config_snapshot_*.tar.gz' -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)
  [[ ${#archives[@]} -eq 0 ]] && { msg "Restore Pipeline" "No restorable snapshots populated."; return; }
  for a in "${archives[@]}"; do args+=("$a" "$(basename "$a")"); done
  chosen=$(menu "Restore Engine" "Select system baseline configuration target state:" "${args[@]}") || return
  yesno "Confirm System Rollback" "Are you sure you want to extract state archives over active configurations?\n\nAn automated pre-restore safety fallback snapshot will be run." || return
  infobox "Rollback Active" "Executing configuration extraction and target subsystem reloads..."
  do_backup >/dev/null 2>&1 || true
  if tar -xzpf "$chosen" -C / >>"$LOG" 2>&1; then
    run sysctl --system
    [[ -d /etc/ufw ]] && run ufw reload
    run systemctl daemon-reload
    run systemctl reload ssh || run systemctl restart ssh || true
    systemctl is-active --quiet crowdsec && run systemctl restart crowdsec
    systemctl is-active --quiet crowdsec-firewall-bouncer && run systemctl restart crowdsec-firewall-bouncer
    systemctl is-active --quiet suricata && run systemctl restart suricata
    msg "Rollback Complete" "Configurations restored. Active system tracking rules re-applied."
    return 0
  else
    msg "Extraction Failure" "Critical failure occurred during archive mapping overrides. View $LOG for details."
    return 1
  fi
}

backup_menu(){
  local c cs cnt
  while :; do
    cs="Inactive"; [[ -f "$CRON_FILE" ]] && cs="Active"
    cnt="$(find "$BACKUP_DIR" -name 'config_snapshot_*.tar.gz' 2>/dev/null | wc -l)"
    c=$(menu "Backup & Configuration Snapshots" "Archives: $cnt   Automated Cron Cycle: $cs" \
      B "Create System Configuration Snapshot" \
      R "Execute State Restoration from Archive" \
      I "Inspect Archive File Manifest Layout" \
      S "Enable Automated Weekly Backup Strategy" \
      X "Purge Automated Cron Task Schedules" \
      b "Return to Main Context")
    case "$?" in
      1|255) break ;;
    esac
    case "$c" in
      B) RESULT=(); COUNTER=0; TOTAL=1; run_module backup "Config snapshot" m_backup_system; summary ;;
      R) m_restore_interface ;;
      I) inspect_snapshot ;;
      S) local self; self="$(install_self)"
         printf '0 3 * * 0 root %s --backup >/dev/null 2>&1\n' "$self" >"$CRON_FILE" && chmod 644 "$CRON_FILE"
         msg "Cron Added" "Weekly task scheduled for Sunday at 03:00 execution." ;;
      X) rm -f "$CRON_FILE"; msg "Cron Removed" "Automated pipeline destroyed." ;;
      b) break ;;
    esac
  done
}


# ---------- once-a-day startup safety snapshot ------------------------------
auto_startup_backup(){ local today; today="$(date +%F)"; [[ "$(cat "$STARTUP_BACKUP_STAMP" 2>/dev/null || true)" == "$today" ]] && return 0; local out; out=$(do_backup 2>/dev/null || true); [[ -n "$out" ]] && { echo "$today" >"$STARTUP_BACKUP_STAMP"; log "Startup auto-backup: $out"; }; }


# ---------- system hardening core modules -----------------------------------
m_baseline(){
  infobox "Base Synchronization" "Updating repositories, time sync, and core dependencies..."
  run apt-get update
  run apt-get -y upgrade
  run apt-get install -y jq curl ca-certificates gnupg lsb-release software-properties-common \
      chrony unattended-upgrades nftables lsof tcpdump conntrack debsums needrestart apt-listchanges ethtool
  systemctl enable --now chrony >>"$LOG" 2>&1 || systemctl enable --now chronyd >>"$LOG" 2>&1 || true
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  # Keep unattended security patches ON, but never let them auto-bounce the kernel,
  # network drivers, or the live security engines — an unexpected reboot/restart can
  # tear down an active VLESS tunnel. These stay on a MANUAL maintenance cadence.
  write_kernel_upgrade_blacklist
  run systemctl enable --now unattended-upgrades || true
  state_write
  return 0
}


m_kernel_network(){ modprobe tcp_bbr 2>>"$LOG" || true; echo tcp_bbr >/etc/modules-load.d/intelshield-bbr.conf 2>/dev/null || true; cat >"$SYSCTL_NET" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
# rp_filter=2 (loose) keeps anti-spoof protection but, unlike strict(1), does not
# drop legitimate asymmetric/policy-routed return traffic on multi-homed relays.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.core.somaxconn = 16384
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
fs.file-max = 2097152
EOF
run sysctl --system; state_write; }
m_kernel_security(){ cat >"$SYSCTL_SEC" <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.kexec_load_disabled = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
run sysctl --system; state_write; }


m_ufw(){
  run apt-get install -y ufw
  local port
  port=$(input "Firewall Setup" "Define target processing inbound authentication port rules:\n- SSH traffic targeting validation\n- 443 TCP/UDP standard tunneling allocations\n\nVerify operational SSH target interface port:" "$SSH_PORT") || return 3
  [[ -z "$port" ]] && port="$SSH_PORT"
  # validate BEFORE 'ufw --force enable' — a typo'd port here = remote lockout
  valid_port "$port" || { msg "Firewall Setup" "'$port' is not a valid port. Aborting before enabling UFW to avoid an SSH lockout."; return 1; }
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw limit "${port}"/tcp
  run ufw allow "${port}"/tcp
  run ufw allow 443/tcp
  run ufw allow 443/udp
  run ufw --force enable
  msg "Firewall Initialized" "UFW rules processing cleanly. Port inbound drops enabled across all non-explicit vectors."
  ufw status 2>/dev/null | grep -q "Status: active"
}

m_ssh(){
  local keyfound=0 f dropin="/etc/ssh/sshd_config.d/99-harden.conf" disable_pw="no" port
  for f in /root/.ssh/authorized_keys "/home/${SUDO_USER:-__none__}/.ssh/authorized_keys"; do
    [[ -s "$f" ]] && keyfound=1
  done
  port=$(input "SSH Optimization" "Specify terminal connectivity listening port context:" "$SSH_PORT") || return 3
  [[ -z "$port" ]] && port="$SSH_PORT"
  if [[ $keyfound -eq 1 ]]; then
    if yesno "Cryptographic Policy" "Cryptographic keys detected.\n\nDisable standard cleartext password authentication mechanisms?"; then disable_pw="yes"; fi
  else
    msg "Fallback Mode Enabled" "No authorization files discovered. Password login preserved to prevent loss of remote access."
  fi
  # sshd is first-match-wins: the Include must sit ABOVE any Port/PasswordAuthentication
  # already present in the main file, or the drop-in is silently overridden.
  grep -q '^Include /etc/ssh/sshd_config.d/\*.conf' /etc/ssh/sshd_config 2>/dev/null || \
    sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
  cat >"$dropin" <<EOF
# IntelShield high-security access parameters
Port $port
PermitRootLogin prohibit-password
PubkeyAuthentication yes
KbdInteractiveAuthentication no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha256-etm@openssh.com,hmac-sha512-etm@openssh.com,umac-128-etm@openssh.com
EOF
  [[ "$disable_pw" == "yes" ]] && echo "PasswordAuthentication no" >>"$dropin"
  if sshd -t 2>>"$LOG"; then
    # 'limit' adds kernel-level brute-force damping that survives CrowdSec being down
    [[ "$port" != "$SSH_PORT" ]] && { run ufw limit "${port}"/tcp; run ufw allow "${port}"/tcp; }
    run systemctl reload ssh || run systemctl reload sshd
    local eff_pw eff_port warn=""
    eff_pw="$(sshd -T 2>/dev/null | awk '/^passwordauthentication /{print $2; exit}')"
    eff_port="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
    [[ "$disable_pw" == "yes" && "$eff_pw" != "no" ]] && warn+="\n\n⚠ PasswordAuthentication is still '$eff_pw' — a directive earlier in /etc/ssh/sshd_config overrides the drop-in. Move or remove it."
    [[ -n "$eff_port" && "$eff_port" != "$port" ]] && warn+="\n\n⚠ Effective SSH port is '$eff_port', not '$port' — check for a conflicting Port line."
    msg "SSH Hardened" "Configuration written to $dropin.\nEffective port: ${eff_port:-$port}   Password auth: ${eff_pw:-unknown}${warn}"
    return 0
  else
    rm -f "$dropin"
    msg "SSH Test Failure" "Validation parameters rejected structural drop-in. Modifications dumped to prevent access lockout."
    return 1
  fi
}

m_crowdsec(){
  infobox "CrowdSec Hub" "Deploying core intelligence engines, security models, and foundational parsers..."
  if ! have_cs; then
    # Fetch CrowdSec's OFFICIAL repo installer to a file, then run it — this is safe
    # (not `curl | sh`) and always tracks CrowdSec's current, correct packagecloud
    # repo layout. (v4.0 tried to hand-build a pinned packagecloud repo line, but a
    # wrong path there breaks `apt-get update` system-wide, so v5.0 reverts to this.)
    run apt-get install -y curl gnupg ca-certificates
    local inst="$IS_TMP/crowdsec-repo.sh"
    if curl -fsSL --proto '=https' --tlsv1.2 https://install.crowdsec.net -o "$inst" 2>>"$LOG" && [[ -s "$inst" ]]; then
      run sh "$inst"
    else
      log "crowdsec repo installer fetch failed; falling back to whatever the distro provides"
    fi
    run apt-get install -y crowdsec
  fi
  have_cs || { msg "Dependency Error" "Engine deployment trace exited unexpectedly. Check $LOG."; return 1; }
  run cscli hub update || true   # fresh hub index before resolving collections
  run cscli collections install crowdsecurity/linux
  run cscli collections install crowdsecurity/sshd
  run systemctl reload crowdsec || run systemctl restart crowdsec
  msg "CrowdSec Active" "Brute-force models loaded. Base signature telemetry processing actively streaming."
  have_cs
}

m_allowlist(){
  need_cs || return 1
  local ip
  ip=$(input "Administrative Trust" "Input the tracking criteria (IP or subnetwork mask block) exempt from blocklist bans:\n\nDetected current interface inbound address:" "${SSH_CLIENT_IP:-}") || return 3
  [[ -z "$ip" ]] && return 3
  valid_ip "$ip" || { msg "Syntax Violation" "Input pattern failed structural verification metrics."; return 1; }
  allowlist_add "$ip"
  msg "Trust Matrix Mutated" "Address [$ip] securely white-listed against automated banning structures."
  return 0
}

m_bouncer(){
  need_cs || return 1
  infobox "Enforcement Architecture" "Injecting CrowdSec nftables kernel-level filtering bouncers..."
  run apt-get install -y crowdsec-firewall-bouncer-nftables
  run systemctl enable --now crowdsec-firewall-bouncer
  msg "Bouncer Operational" "Netfilter tracking layer linked directly to CrowdSec database updates. Malicious scans are dropped natively at the kernel level."
  systemctl is-active --quiet crowdsec-firewall-bouncer
}

# Known 6.x→7.x upgrade failure (jammy distro/older PPA → current PPA): apt holds
# suricata back because the old libhtp1 conflicts with the PPA's libhtp2 and plain
# `apt-get install suricata` refuses the swap. Resolve it surgically, never with a
# blanket full-upgrade.
suricata_fix_libhtp_conflict(){
  log "suricata: attempting libhtp1 -> libhtp2 conflict remediation"
  if apt-cache show libhtp2 >/dev/null 2>&1; then
    # naming libhtp2 explicitly lets apt plan the libhtp1 -> libhtp2 swap itself
    run apt-get install -y suricata suricata-update libhtp2 && return 0
  fi
  # last resort: drop the stale bindings and retry once
  local p
  for p in libhtp1 libhtp0; do dpkg -s "$p" >/dev/null 2>&1 && run apt-get purge -y "$p"; done
  run apt-get -y -f install || true
  run apt-get install -y suricata suricata-update
}

m_suricata(){
  infobox "IDS Framework" "Provisioning Suricata 8: OISF stable engine, signatures and configuration..."
  # add-apt-repository lives in software-properties-common; ensure it before using it
  have add-apt-repository || run apt-get install -y software-properties-common
  # The OISF PPA ships Suricata 8 for BOTH jammy (22.04) and noble (24.04).
  run add-apt-repository -y ppa:oisf/suricata-stable || log "add-apt-repository failed — continuing with the Ubuntu archive"
  run apt-get update
  # Trust the PPA only if it actually serves a candidate for this codename (noble
  # had a gap until Aug 2024; a future series could regress the same way). The
  # Ubuntu archive still ships Suricata on noble, so this is informational —
  # the install proceeds either way instead of failing on a dead PPA.
  if apt-cache policy suricata 2>/dev/null | grep -q 'launchpadcontent.net/oisf'; then
    log "suricata: OISF PPA candidate available for ${OS_CODENAME:-?}"
  else
    log "suricata: OISF PPA has no candidate for ${OS_CODENAME:-?} — using the Ubuntu archive build"
  fi
  # Suricata 8 dependency notes:
  #   - LibHTP C library is REMOVED (moved to Rust in Suricata 8)
  #   - Vendored Lua 5.4 engine is bundled (no external Lua dependency needed)
  #   - libhtp2 may still be a transition package; handle gracefully
  # suricata-update is its own package — always name it explicitly (on noble it is
  # NOT pulled in automatically in every path).
  if ! run apt-get install -y suricata suricata-update jq; then
    suricata_fix_libhtp_conflict || { msg "Signature Error" "Suricata failed to install (dependency conflict could not be auto-resolved) — see $LOG."; return 1; }
    run apt-get install -y jq || true
  fi
  # ROOT-CAUSE FIX for "engine/keyword mismatch": if a distro Suricata (6.x/7.x)
  # was already present, `install` won't move it to the PPA's 8.x — force the
  # upgrade so the engine is new enough for the current ET/open ruleset keywords
  # and supports Suricata 8's new firewall mode, transactional rules, and 107+ new
  # keywords (entropy, luaxform, absent, etc.).
  run apt-get install -y --only-upgrade suricata || suricata_fix_libhtp_conflict || true
  command -v suricata >/dev/null 2>&1 || { msg "Signature Error" "Suricata failed to install — see $LOG."; return 1; }
  log "Suricata engine: $(suricata -V 2>/dev/null | tr -d '\n')"
  # /etc/default/suricata is plain KEY=VALUE (not yaml) — edited directly.
  # sed exits 0 even when nothing matched, so append when no IFACE= line exists.
  if [[ -n "$NIC" ]]; then
    if [[ -f /etc/default/suricata ]] && grep -q '^IFACE=' /etc/default/suricata; then
      sed -i "s/^IFACE=.*/IFACE=$NIC/" /etc/default/suricata
    else
      echo "IFACE=$NIC" >>/etc/default/suricata
    fi
  fi
  # v8.0: suricata.yaml is NOT sed-edited. HOME_NET and the capture NIC land in
  # /etc/suricata/intelshield/ drop-ins wired in by one managed include: block.
  local bak; bak="$(suricata_yaml_backup)" || true
  suricata_write_base_dropins
  # first fetch of the ruleset, then SID-based self-heal (disable.conf, not sed)
  run suricata-update update-sources 2>>"$LOG" || true
  run suricata-update --no-test --no-reload
  SURI_SANITIZED=0
  if suricata_sanitize_rules; then
    run systemctl enable --now suricata && run systemctl restart suricata
    if systemctl is-active --quiet suricata; then
      state_write
      msg "IDS Functional" "Suricata is running.\nInterface: ${NIC:-?}   HOME_NET egress: ${PUB_IP:-?}\nEngine: $(suricata -V 2>/dev/null | grep -oE 'version [0-9.]+' || echo '?')\nConfig overrides: ${SURICATA_INCLUDE_DIR}/*.yaml (drop-in include architecture)$( (( ${SURI_SANITIZED:-0} > 0 )) && echo "\n\n${SURI_SANITIZED} engine-incompatible rule(s) were bypassed via disable.conf; the rest loaded cleanly." )"
      return 0
    fi
    [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"
    msg "Signature Error" "Config validated but the service didn't come up — see $LOG."
    return 1
  else
    # SID-disable couldn't fix it → the problem is config-level, not a bad rule
    [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"
    msg "Signature Error" "Suricata config failed validation at the config level (not a single rule). Restored the previous suricata.yaml. See $LOG."
    return 1
  fi
}

m_wiring(){
  have_cs || { msg "Pipeline Error" "CrowdSec tracking engine not present."; return 1; }
  command -v suricata >/dev/null 2>&1 || { msg "Pipeline Error" "Suricata capture mechanisms missing."; return 1; }
  infobox "Subsystem Linkage" "Mapping threat outputs directly to active reactive intelligence blocks..."
  # refresh the hub index first so the collection resolves to its current version
  run cscli hub update || true
  run cscli collections install crowdsecurity/suricata
  mkdir -p "$(dirname "$ACQUIS_FILE")"
  # labels.type MUST stay 'suricata-evelogs' — it is pinned to the hub parser
  # crowdsecurity/suricata-logs filter (evt.Parsed.program == "suricata-evelogs").
  # eve.json is the preferred acquisition; never also tail fast.log (double bans).
  cat >"$ACQUIS_FILE" <<'EOF'
source: file
filenames:
  - /var/log/suricata/eve.json
labels:
  type: suricata-evelogs
poll_without_inotify: true
EOF
  # eve.json grows fast on a busy relay; guarantee rotation exists. The Suricata
  # packages usually ship /etc/logrotate.d/suricata — only fill the gap if absent.
  # HUP makes Suricata reopen its logs, which CrowdSec's file tailer follows fine.
  if [[ ! -f /etc/logrotate.d/suricata ]]; then
    cat >/etc/logrotate.d/intelshield-suricata <<'EOF'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        systemctl kill -s HUP suricata >/dev/null 2>&1 || true
    endscript
}
EOF
    log "wiring: installed /etc/logrotate.d/intelshield-suricata (no packaged rotation found)"
  fi
  run systemctl reload crowdsec || run systemctl restart crowdsec
  msg "Pipeline Wired" "Suricata alert logs (eve.json) are now integrated with the CrowdSec real-time processing stream.\n\nAcquisition label: suricata-evelogs (matches the current hub parser)\nLog rotation: $( [[ -f /etc/logrotate.d/suricata ]] && echo 'packaged /etc/logrotate.d/suricata' || echo 'IntelShield-managed (daily, keep 7)' )"
}


# ---------- x-ui/Xray systemd sandbox (hardened, toggleable) -----------------
# Which x-ui/xray units actually exist on this host (space-separated full names).
sandbox_target_units(){ local u out=""; for u in x-ui xray; do systemctl list-unit-files "$u.service" >/dev/null 2>&1 && out+="$u.service "; done; printf '%s' "${out% }"; }
# True if the IntelShield sandbox drop-in is present on any target unit.
sandbox_is_applied(){ local u; for u in x-ui xray; do [[ -f "/etc/systemd/system/${u}.service.d/${SANDBOX_DROPIN_NAME}" ]] && return 0; done; return 1; }
sandbox_mdwe_get(){ cat "$SANDBOX_MDWE_FILE" 2>/dev/null || echo off; }

# Write the sandbox drop-in for ONE unit. $1=unit  $2=caps  $3=mdwe(on|off)
sandbox_write_dropin(){
  local unit="$1" caps="$2" mdwe="$3" d="/etc/systemd/system/${1}.d" mdwe_line="# MemoryDenyWriteExecute disabled (off) for x-ui/Xray self-update compatibility"
  [[ "$mdwe" == on ]] && mdwe_line="MemoryDenyWriteExecute=true"
  mkdir -p "$d"
  cat >"$d/${SANDBOX_DROPIN_NAME}" <<EOF
[Service]
# IntelShield systemd sandbox for x-ui/Xray — blast-radius containment that still
# lets the panel READ every file it needs, WRITE its own db/logs/config/bin, and
# make the SYSTEM CALLS a network service requires (@system-service allowlist).
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
${mdwe_line}
RemoveIPC=true
UMask=0077
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=${caps}
AmbientCapabilities=CAP_NET_BIND_SERVICE
# syscall policy: allow the standard system-service set (covers Go runtime, epoll,
# sockets, threads, file IO) and turn anything else into EPERM rather than a kill —
# so a stray syscall can't crash the panel. Rollback below catches any real break.
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
# ProtectSystem=strict only makes the FS READ-ONLY (reads still work everywhere);
# these are the paths x-ui/Xray must be able to WRITE (db, logs, config, bin, geo).
# '-' prefix = ignore a path that does not exist (a missing path used to abort the
# whole unit at namespace-setup). /etc/x-ui included: 3x-ui keeps x-ui.db there.
ReadWritePaths=-/usr/local/x-ui -/opt/3x-ui -/etc/x-ui -/var/log/x-ui -/var/log/xray -/usr/local/etc/xray -/etc/xray -/var/lib/x-ui
EOF
}

# Apply the sandbox to every present x-ui/xray unit, verifying each and rolling
# back per-unit on failure. Reused by profiles, guided run and the sandbox menu.
# rollback hook for restart_or_rollback: drop the failing unit's sandbox drop-in
SANDBOX_RB_UNIT=""
sandbox_rollback_unit(){ rm -f "/etc/systemd/system/${SANDBOX_RB_UNIT}.d/${SANDBOX_DROPIN_NAME}"; run systemctl daemon-reload; }
sandbox_apply(){
  local units caps mdwe u ok=() bad=()
  units="$(sandbox_target_units)"
  [[ -z "$units" ]] && { msg Sandbox "No x-ui/xray service found on this host."; return 3; }
  caps="CAP_NET_BIND_SERVICE"
  # 3x-ui IP-limit/fail2ban and Xray tproxy need extra net caps — offer them so the
  # sandbox never silently breaks panel features (default assumes yes when headless).
  if yesno "Sandbox Capabilities" "Grant extra network capabilities?\n\nRecommended YES if this node uses:\n • 3x-ui IP-limit / fail2ban\n • Xray tproxy / transparent-proxy inbounds\n\nYes = CAP_NET_BIND_SERVICE + CAP_NET_ADMIN + CAP_NET_RAW\nNo  = bind-only (tighter, but disables those features)"; then
    caps="CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW"
  fi
  mdwe="$(sandbox_mdwe_get)"
  for u in $units; do sandbox_write_dropin "$u" "$caps" "$mdwe"; done
  run systemctl daemon-reload
  # v8.0: per-unit atomic gate — if a unit fails WITH the sandbox, the drop-in
  # is removed and the unit restarted unconfined (restart_or_rollback contract).
  for u in $units; do
    SANDBOX_RB_UNIT="$u"
    if restart_or_rollback "$u" sandbox_rollback_unit; then ok+=("$u"); else bad+=("$u"); fi
  done
  state_write
  if [[ ${#bad[@]} -eq 0 ]]; then
    msg Sandbox "Sandbox APPLIED to: ${ok[*]}\n\nCapabilities: $caps\nMemoryDenyWriteExecute: $mdwe\nSyscall policy: @system-service (EPERM on others)\n\nTip: turn the sandbox OFF from this menu before a MANUAL panel update, then back on."
    return 0
  fi
  msg Sandbox "Some units failed WITH the sandbox and were rolled back automatically:\n  failed : ${bad[*]}\n  ok     : ${ok[*]:-none}\n\nTry toggling MemoryDenyWriteExecute OFF (Sandbox menu) and re-applying. See $LOG."
  return 1
}
# Registry / profile entry point.
m_sandbox(){ sandbox_apply; }

# Remove the sandbox from x-ui/Xray and restart them UNCONFINED. This is what you
# run before manually updating the panel; nothing is purged, just un-sandboxed.
sandbox_off(){
  local u touched=0 restarted=()
  for u in x-ui xray; do
    local f="/etc/systemd/system/${u}.service.d/${SANDBOX_DROPIN_NAME}"
    [[ -f "$f" ]] && { rm -f "$f"; rmdir "/etc/systemd/system/${u}.service.d" 2>/dev/null || true; touched=1; }
  done
  run systemctl daemon-reload
  for u in x-ui xray; do svc_exists "$u.service" && systemctl is-active --quiet "$u" && { run systemctl restart "$u"; restarted+=("$u"); }; done
  state_write
  return 0
}

sandbox_toggle_mdwe(){
  local cur; cur="$(sandbox_mdwe_get)"
  if [[ "$cur" == on ]]; then echo off >"$SANDBOX_MDWE_FILE"; else echo on >"$SANDBOX_MDWE_FILE"; fi
  msg "MDWE Hardening" "MemoryDenyWriteExecute is now: $(sandbox_mdwe_get)\n\nON  = harder (blocks writable+executable memory) — extra protection, but can\n      break x-ui/Xray self-update or some transports.\nOFF = maximum compatibility (recommended default).\n\nRe-apply the sandbox for this to take effect."
  sandbox_is_applied && yesno "Re-apply Now?" "Re-apply the sandbox with MemoryDenyWriteExecute=$(sandbox_mdwe_get)?" && sandbox_apply
}

sandbox_status_view(){
  local u f
  { echo "x-ui / Xray systemd sandbox status  —  $(date -Is)"
    echo "MemoryDenyWriteExecute hardening preference: $(sandbox_mdwe_get)"
    echo "Detected units: $(sandbox_target_units | sed 's/\.service//g' || echo none)"
    echo
    for u in x-ui xray; do
      svc_exists "$u.service" || { echo "== $u ==  (service not installed)"; echo; continue; }
      f="/etc/systemd/system/${u}.service.d/${SANDBOX_DROPIN_NAME}"
      echo "== $u =="
      echo "  service : $(svc_state "$u.service")"
      [[ -f "$f" ]] && echo "  sandbox : APPLIED" || echo "  sandbox : not applied"
      echo "  effective systemd confinement:"
      systemctl show "$u" -p ProtectSystem -p MemoryDenyWriteExecute -p CapabilityBoundingSet \
                          -p SystemCallFilter -p ReadWritePaths -p RestrictAddressFamilies 2>/dev/null \
        | sed 's/^/    /'
      echo
    done
    echo "Files/logs the panel can still WRITE (ReadWritePaths):"
    echo "  /usr/local/x-ui /opt/3x-ui /etc/x-ui /var/log/x-ui /var/log/xray /usr/local/etc/xray /etc/xray /var/lib/x-ui"
  } >"$IS_TMP/sandbox-status"
  showfile "Sandbox Status" "$IS_TMP/sandbox-status" 34 118
}

sandbox_menu(){
  local c st mdwe units
  while :; do
    st="not applied"; sandbox_is_applied && st="APPLIED"
    mdwe="$(sandbox_mdwe_get)"; units="$(sandbox_target_units | sed 's/\.service//g')"
    c=$(menu "x-ui / Xray Sandbox Control" "Sandbox: ${st}   |   MDWE hardening: ${mdwe}   |   units: ${units:-none found}" \
      E "Enable / (re)apply sandbox" \
      D "Disable sandbox — run BEFORE a manual x-ui panel update" \
      T "Toggle MemoryDenyWriteExecute hardening (now: ${mdwe})" \
      V "View sandbox status + effective confinement" \
      b "Back") || return
    case "$c" in
      E) sandbox_apply ;;
      D) yesno "Disable Sandbox" "Remove the systemd sandbox from x-ui/Xray and restart them UNCONFINED?\n\nDo this before a MANUAL panel/Xray update so nothing interferes, then re-enable (E) when the update is done." \
           && { sandbox_off; msg Sandbox "Sandbox DISABLED. x-ui/Xray now run unconfined — safe to update the panel.\n\nRe-enable it from this menu (Enable) once your update is finished."; } ;;
      T) sandbox_toggle_mdwe ;;
      V) sandbox_status_view ;;
      b) return ;;
    esac
  done
}


m_console(){
  need_cs || return 1
  local key
  key=$(secret_input "Cloud Synchronization" "Input target token generated via central monitoring console:") || return 3
  [[ -z "$key" ]] && return 3
  # do NOT route the token through run() — that would write it verbatim into the log
  log "+ cscli console enroll *** (token redacted)"
  cscli console enroll "$key" >>"$LOG" 2>&1
  run systemctl reload crowdsec || run systemctl restart crowdsec
  msg "Console Enrolled" "Engine paired to web instances. Validate parameters from terminal dashboards."
  return 0
}

m_panel(){
  local p="$PANEL_PORT"
  if [[ -z "$p" ]]; then
    p=$(input "Interface Shielding" "Input structural port indexing used by active interface dashboards:" "") || return 3
  fi
  [[ -z "$p" ]] && return 3
  local choice
  choice=$(menu "Interface Access Topology" "Dashboard binding discovered on interface port: $p" \
    R "Restrict connectivity strictly to isolated network address" \
    G "Review infrastructural deployment guidelines") || return 3
  if [[ "$choice" == "R" ]]; then
     local src
     src=$(input "Network Scoping" "Input target administrative host vector allowed context accessibility:" "$SSH_CLIENT_IP") || return 3
     valid_ip "$src" || { msg "Error" "Syntax verification failed."; return 1; }
     run ufw allow from "$src" to any port "$p" proto tcp
     run ufw delete allow "${p}"/tcp
     run ufw delete allow "${p}"
     msg "Access Scoped" "Inbound firewall definitions reconfigured explicitly."
  elif [[ "$choice" == "G" ]]; then
     msg "Architecture Best Practices" "For optimal protection, bind your panel listener locally to 127.0.0.1 and route connections securely through an encrypted overlay network (such as Headscale/WireGuard) or via an authenticated SSH tunnel, completely eliminating public vector exposure."
  fi
}


# ---------- CPU microcode + platform security audit -------------------------
cpu_vendor(){ lscpu 2>/dev/null|awk -F: '/Vendor ID/{gsub(/^[ \t]+/,"",$2); print tolower($2); exit}'; }
cpu_model(){ lscpu 2>/dev/null|awk -F: '/Model name/{gsub(/^[ \t]+/,"",$2); print $2; exit}'; }
m_cpu_microcode(){ local v m pkg report; v=$(cpu_vendor); m=$(cpu_model); [[ "$v" == *intel* ]] && pkg=intel-microcode || { [[ "$v" == *amd* || "$v" == *advanced* ]] && pkg=amd64-microcode || pkg=""; }; [[ -n "$pkg" ]] && { run apt-get update; run apt-get install -y "$pkg"; }; report=/var/log/intelshield/cpu-mitigations.txt; mkdir -p /var/log/intelshield; { echo "CPU: $m"; echo "Vendor: $v"; echo "Microcode package: ${pkg:-none}"; echo; cat /proc/cmdline; echo; for f in /sys/devices/system/cpu/vulnerabilities/*; do [[ -r "$f" ]] && echo "$(basename "$f"): $(cat "$f")"; done; } >"$report"; state_write; grep -qw mitigations=off /proc/cmdline && { msg CPU "CRITICAL: mitigations=off found. Report: $report"; return 1; }; msg CPU "Detected: ${m:-unknown}\nPackage: ${pkg:-none}\nReboot recommended if package installed.\nReport: $report"; }
m_platform_security(){ run apt-get install -y mokutil tpm2-tools cryptsetup-bin dmsetup || true; local r=/var/log/intelshield/platform-security.txt; mkdir -p /var/log/intelshield; { echo SecureBoot; mokutil --sb-state 2>/dev/null || true; echo; echo Lockdown; cat /sys/kernel/security/lockdown 2>/dev/null || true; echo; echo TPM; tpm2_getcap properties-fixed 2>/dev/null || true; echo; lsblk -f; dmsetup ls --target crypt 2>/dev/null || true; } >"$r"; state_write; }


# ---------- auditd / AIDE / AppArmor / USG / health timer --------------------
m_auditd(){ run apt-get install -y auditd audispd-plugins; cat >/etc/audit/rules.d/99-intelshield.rules <<'EOF'
-b 8192
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /etc/sysctl.d/ -p wa -k sysctl
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/local/x-ui/ -p wa -k xui
-w /etc/x-ui/ -p wa -k xui
-w /usr/local/etc/xray/ -p wa -k xray
-w /etc/xray/ -p wa -k xray
-a always,exit -F arch=b64 -S execve -F euid=0 -k root-commands
-a always,exit -F arch=b32 -S execve -F euid=0 -k root-commands
EOF
run augenrules --load || true; run systemctl enable --now auditd; state_write; }
m_aide(){ run apt-get install -y aide aide-common; aideinit >>"$LOG" 2>&1 || true; [[ -f /var/lib/aide/aide.db.new ]] && cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db; state_write; }
m_apparmor(){ run apt-get install -y apparmor apparmor-utils; run systemctl enable --now apparmor || true; state_write; }
m_usg_audit(){
  run apt-get install -y ubuntu-advantage-tools || true
  have usg || { msg USG "USG not available. Enable it first: 'pro enable usg'."; return 3; }
  mkdir -p /var/log/intelshield/usg
  # flag names are --html-file / --results-file (the old --report/--results silently failed)
  if usg audit --html-file /var/log/intelshield/usg/report.html \
               --results-file /var/log/intelshield/usg/results.xml \
               cis_level1_server >>"$LOG" 2>&1; then
    msg USG "CIS Level 1 audit complete.\nReport: /var/log/intelshield/usg/report.html"
  else
    msg USG "usg audit failed — flag names/profiles vary by USG version. Check 'usg audit --help' and $LOG."
    return 1
  fi
}
m_health_timer(){ cat >/usr/local/sbin/intelshield-health <<'EOF'
#!/usr/bin/env bash
# report per-service state to the journal (collected by Wazuh journald); the old
# version evaluated every check and threw the result away.
fail=0
for svc in x-ui xray crowdsec crowdsec-firewall-bouncer suricata clamav-freshclam auditd wazuh-agent; do
  systemctl cat "$svc.service" >/dev/null 2>&1 || continue
  if systemctl is-active --quiet "$svc"; then echo "OK   $svc active"
  else echo "FAIL $svc is NOT active"; fail=1; fi
done
df -h /
exit $fail
EOF
chmod 750 /usr/local/sbin/intelshield-health; cat >/etc/systemd/system/intelshield-health.service <<'EOF'
[Unit]
Description=IntelShield health check
[Service]
Type=oneshot
RuntimeMaxSec=120
ExecStart=/usr/local/sbin/intelshield-health
EOF
cat >/etc/systemd/system/intelshield-health.timer <<'EOF'
[Unit]
Description=Run IntelShield health check
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Persistent=true
[Install]
WantedBy=timers.target
EOF
run systemctl daemon-reload; run systemctl enable --now intelshield-health.timer; state_write; }


#----------------------------- Anti-rootkit -----------------------------------
ark_init(){ mkdir -p "$ARK_DIR" "$ARK_LOG_DIR" "$ARK_QUAR" "$(dirname "$ARK_CONF")"; chmod 700 "$ARK_DIR" "$ARK_QUAR"; [[ -f "$ARK_CONF" ]] || cat >"$ARK_CONF" <<'EOF'
CHKROOTKIT_EXCLUDES="/run /run/systemd /var/lib/lxcfs /snap /var/lib/docker /var/lib/containerd /var/clamav/quarantine /var/lib/intelshield/anti-rootkit/quarantine"
EOF
}
ark_config_set(){ local f="$1" k="$2" v="$3"; touch "$f"; grep -qE "^[#[:space:]]*$k=" "$f" && sed -i -E "s|^[#[:space:]]*$k=.*|$k=$v|" "$f" || echo "$k=$v" >>"$f"; }
ark_whitelist_safe_areas(){ ark_init; local quiet="${1:-}"; if [[ -f /etc/rkhunter.conf ]] || rkhunter_present; then cat >/etc/rkhunter.conf.local <<'EOF'
ALLOWHIDDENDIR=/dev/.udev
ALLOWHIDDENDIR=/dev/.static
ALLOWHIDDENDIR=/dev/.initramfs
ALLOWHIDDENDIR=/run/systemd
ALLOWHIDDENDIR=/run/udev
ALLOWHIDDENFILE=/dev/.initramfs
ALLOWHIDDENFILE=/etc/.java
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/ldd
EOF
# PORT_WHITELIST must be proto:port pairs (a bare '*' either fails config validation
# or whitelists everything). Set it dynamically so a custom SSH port is honoured.
ark_config_set /etc/rkhunter.conf.local PORT_WHITELIST "\"TCP:${SSH_PORT:-22} TCP:80 TCP:443 UDP:443\""
ark_config_set /etc/rkhunter.conf UPDATE_MIRRORS 1; ark_config_set /etc/rkhunter.conf MIRRORS_MODE 0; ark_config_set /etc/rkhunter.conf WEB_CMD '""'; [[ -f /etc/default/rkhunter ]] && { ark_config_set /etc/default/rkhunter CRON_DAILY_RUN '"false"'; ark_config_set /etc/default/rkhunter CRON_DB_UPDATE '"false"'; ark_config_set /etc/default/rkhunter APT_AUTOGEN '"yes"'; }; fi; [[ "$quiet" == silent ]] || msg "Whitelist Safe Areas" "Safe-area whitelist applied."; }
m_ark_install(){ ark_init; run apt-get update; run apt-get install -y rkhunter chkrootkit; ark_whitelist_safe_areas silent; rkhunter_present && { run rkhunter --update || true; run rkhunter --propupd || true; }; state_write; }
ark_extract_paths(){ local logf="$1" outf="$2"; : >"$outf"; grep -Eo '(/[A-Za-z0-9._@%+=:,/ -]+)' "$logf" 2>/dev/null | sed 's/[[:space:]]*$//' | while read -r x; do [[ -e "$x" ]] && printf '%s\n' "$x"; done | sort -u >>"$outf" || true; }
ark_scan_rkhunter(){ ark_init; rkhunter_present || return 1; local ts logf paths; ts=$(date +%Y%m%d_%H%M%S); logf="$ARK_LOG_DIR/rkhunter_${ts}.log"; paths="$ARK_DIR/rkhunter_${ts}.paths"; run rkhunter --update || true; rkhunter --check --sk --rwo --append-log --logfile "$logf" >>"$logf" 2>&1 || true; ark_extract_paths "$logf" "$paths"; ln -sfn "$logf" "$ARK_LOG_DIR/rkhunter_latest.log"; ln -sfn "$paths" "$ARK_DIR/rkhunter_latest.paths"; state_write; }
ark_scan_chkrootkit(){ ark_init; chkrootkit_present || return 1; local ts logf paths opts=(); ts=$(date +%Y%m%d_%H%M%S); logf="$ARK_LOG_DIR/chkrootkit_${ts}.log"; paths="$ARK_DIR/chkrootkit_${ts}.paths"; source "$ARK_CONF" 2>/dev/null || true; [[ -n "${CHKROOTKIT_EXCLUDES:-}" ]] && opts=(-e "$CHKROOTKIT_EXCLUDES"); chkrootkit -q "${opts[@]}" >"$logf" 2>&1 || true; ark_extract_paths "$logf" "$paths"; ln -sfn "$logf" "$ARK_LOG_DIR/chkrootkit_latest.log"; ln -sfn "$paths" "$ARK_DIR/chkrootkit_latest.paths"; state_write; }
ark_scan_all(){ rkhunter_present && ark_scan_rkhunter || true; chkrootkit_present && ark_scan_chkrootkit || true; msg "Anti Rootkit" "Scans complete. View Detection Monitor for results."; }
ark_set_schedule(){ local tool="$1" time self; time=$(input "Schedule $tool" "Daily time HH:MM. Default midnight:" "00:00") || return 3; [[ "$time" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || { msg Time "Invalid HH:MM"; return 1; }; self=$(install_self); cat >/etc/systemd/system/intelshield-antirootkit-${tool}.service <<EOF
[Unit]
Description=IntelShield Anti Rootkit ${tool} scan
Wants=network-online.target
After=network-online.target
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
RuntimeMaxSec=2h
ExecStart=$self --antirootkit-scan $tool
EOF
cat >/etc/systemd/system/intelshield-antirootkit-${tool}.timer <<EOF
[Unit]
Description=Daily IntelShield Anti Rootkit ${tool} scan
[Timer]
OnCalendar=*-*-* $time:00
Persistent=true
[Install]
WantedBy=timers.target
EOF
run systemctl daemon-reload; run systemctl enable --now intelshield-antirootkit-${tool}.timer; state_write; }
ark_disable_schedule(){ local tool="$1"; run systemctl disable --now intelshield-antirootkit-${tool}.timer || true; rm -f /etc/systemd/system/intelshield-antirootkit-${tool}.service /etc/systemd/system/intelshield-antirootkit-${tool}.timer; run systemctl daemon-reload; state_write; }
ark_detections_view(){ local f="$IS_TMP/ark-detections" logf; { echo "IntelShield Anti Rootkit Detection Monitor - $(date -Is)"; echo; for logf in "$ARK_LOG_DIR"/*.log; do [[ -f "$logf" ]] || continue; echo "===== $(basename "$logf") ====="; grep -Ei 'warning|infected|suspicious|possible|rootkit|trojan|backdoor|found|vulnerable' "$logf" | tail -80 || echo "No high-signal findings."; echo; done; } >"$f"; showfile "Anti Rootkit Detection Monitor" "$f" 36 120; }
ark_logs_menu(){ local files=() args=() f c; mapfile -t files < <(find "$ARK_LOG_DIR" -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null|sort -rn|cut -d' ' -f2-); [[ ${#files[@]} -gt 0 ]] || { msg Logs "No logs."; return 3; }; for f in "${files[@]}"; do args+=("$f" "$(basename "$f")"); done; c=$(menu Logs "Select log:" "${args[@]}") || return; showfile "$(basename "$c")" "$c" 36 120; }
ark_safe_path(){ local x="${1:-}"; [[ -n "$x" && -e "$x" ]] || return 1; case "$x" in /proc/*|/sys/*|/dev/*|/run/*|/boot/*|/lib/*|/lib64/*|/bin/*|/sbin/*|/usr/*|/etc/*|/var/lib/*|/opt/3x-ui/*) return 2;; esac; return 0; }
ark_quarantine_detected(){ local paths=() args=() pf p c qf; for pf in "$ARK_DIR"/*.paths; do [[ -f "$pf" ]] || continue; while read -r p; do [[ -e "$p" ]] && paths+=("$p"); done <"$pf"; done; [[ ${#paths[@]} -gt 0 ]] && mapfile -t paths < <(printf '%s\n' "${paths[@]}"|sort -u); [[ ${#paths[@]} -gt 0 ]] || { msg Quarantine "No path candidates found."; return 3; }; for p in "${paths[@]}"; do args+=("$p" "$p"); done; c=$(menu Quarantine "Manual only. Protected OS paths are blocked." "${args[@]}") || return; ark_safe_path "$c" || { msg Protected "Refusing protected path: $c"; return 1; }; yesno Confirm "Move to quarantine?\n$c" || return; qf="$ARK_QUAR/$(date +%s)_$$_$(basename "$c")"; local fmeta; fmeta="$(stat -c '%a:%u:%g' "$c" 2>/dev/null || echo '600:0:0')"; mv -f "$c" "$qf" >>"$LOG" 2>&1 && { chmod 000 "$qf"; printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u '+%F %T')" "$qf" "$c" "manual anti-rootkit quarantine" "$fmeta" >>"$ARK_MANIFEST"; msg Quarantine "Moved to $qf"; } || msg Quarantine "Failed."; }
ark_restore_quarantine(){ [[ -s "$ARK_MANIFEST" ]] || { msg Restore "No quarantined items."; return 3; }; local args=() ts qf orig reason fmeta pick meta fmode fuid fgid; while IFS=$'\t' read -r ts qf orig reason fmeta; do [[ -e "$qf" ]] && args+=("$qf" "$(basename "$orig") -> $orig"); done <"$ARK_MANIFEST"; [[ ${#args[@]} -gt 0 ]] || return 3; pick=$(menu "Restore False Positive" "Select item:" "${args[@]}") || return; meta=$(awk -F'\t' -v q="$pick" '$2==q{print; exit}' "$ARK_MANIFEST"); IFS=$'\t' read -r ts qf orig reason fmeta <<<"$meta"; yesno Restore "Restore to $orig?" || return; mkdir -p "$(dirname "$orig")"; IFS=: read -r fmode fuid fgid <<<"${fmeta:-600:0:0}"; if mv -f "$qf" "$orig" >>"$LOG" 2>&1; then chmod "${fmode:-600}" "$orig" 2>/dev/null || true; chown "${fuid:-0}:${fgid:-0}" "$orig" 2>/dev/null || true; awk -F'\t' -v q="$pick" '$2!=q' "$ARK_MANIFEST" >"$ARK_MANIFEST.tmp" 2>/dev/null && mv -f "$ARK_MANIFEST.tmp" "$ARK_MANIFEST"; msg Restore "Restored with original mode/owner ($fmode $fuid:$fgid)."; else msg Restore "Failed."; fi; }
rkhunter_menu(){ local c; while :; do c=$(menu "rkhunter Management" "Status: $(rkhunter_present&&echo installed||echo missing)" I "Install/update" U "Update DB + propupd" S "Run scan" W "Whitelist Safe Areas" L "View logs" D "Detection monitor" Q "Quarantine detected item" R "Restore false positive" T "Set schedule" X "Disable schedule" b Back) || break; case "$c" in I) run apt-get update; run apt-get install -y rkhunter; ark_whitelist_safe_areas silent; run rkhunter --update || true; run rkhunter --propupd || true; state_write;; U) run rkhunter --update || true; run rkhunter --propupd || true; msg rkhunter Updated;; S) ark_scan_rkhunter; msg rkhunter "Scan complete.";; W) ark_whitelist_safe_areas;; L) ark_logs_menu;; D) ark_detections_view;; Q) ark_quarantine_detected;; R) ark_restore_quarantine;; T) ark_set_schedule rkhunter;; X) ark_disable_schedule rkhunter;; b) break;; esac; done; }
chkrootkit_menu(){ local c; while :; do c=$(menu "chkrootkit Management" "Status: $(chkrootkit_present&&echo installed||echo missing)" I "Install/update" S "Run scan" W "Whitelist Safe Areas" L "View logs" D "Detection monitor" Q "Quarantine detected item" R "Restore false positive" T "Set schedule" X "Disable schedule" b Back) || break; case "$c" in I) run apt-get update; run apt-get install -y chkrootkit; ark_whitelist_safe_areas silent; state_write;; S) ark_scan_chkrootkit; msg chkrootkit "Scan complete.";; W) ark_whitelist_safe_areas;; L) ark_logs_menu;; D) ark_detections_view;; Q) ark_quarantine_detected;; R) ark_restore_quarantine;; T) ark_set_schedule chkrootkit;; X) ark_disable_schedule chkrootkit;; b) break;; esac; done; }
anti_rootkit_menu(){ ark_init; local c; while :; do c=$(menu "Anti Rootkit Defense" "rkhunter + chkrootkit. Default: report-only. Quarantine is manual and protected." A "Install both" R "Manage rkhunter separately" C "Manage chkrootkit separately" S "Run both scans" W "Whitelist Safe Areas" M "Intelligent detection monitor" Q "Quarantine detected item" F "Restore false positive" T "Set both schedules" X "Disable both schedules" b Back) || break; case "$c" in A) m_ark_install;; R) rkhunter_menu;; C) chkrootkit_menu;; S) ark_scan_all;; W) ark_whitelist_safe_areas;; M) ark_detections_view;; Q) ark_quarantine_detected;; F) ark_restore_quarantine;; T) ark_set_schedule rkhunter; ark_set_schedule chkrootkit;; X) ark_disable_schedule rkhunter; ark_disable_schedule chkrootkit;; b) break;; esac; done; }


#----------------------------- Suricata Intelligence --------------------------
# ---- shared safe-apply helpers ----------------------------------------------
suricata_yaml_backup(){ local b="${SURICATA_YAML}.intelshield.$(date +%s)"; cp -a "$SURICATA_YAML" "$b" 2>/dev/null && printf '%s' "$b"; }
# test the config; on success restart; on failure restore the given backup and fail.
suricata_validate_restart(){ local bak="${1:-}"; if suricata -T -c "$SURICATA_YAML" >>"$LOG" 2>&1; then run systemctl restart suricata; return 0; fi; [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"; return 1; }
suri_mode_get(){ cat "$SURICATA_MODE_FILE" 2>/dev/null || echo ids; }

# ---- Suricata 7 drop-in configuration architecture (v8.0) --------------------
# Every IntelShield override to the engine config is a named yaml file in
# $SURICATA_INCLUDE_DIR, pulled in by ONE marker-guarded `include:` block appended
# to suricata.yaml (Suricata 7 native include list — contents are inlined and
# later keys override earlier ones). suricata.yaml itself is never sed-edited;
# the only mutation we ever make to it is regenerating this block.
SURI_INC_BEGIN="# --- IntelShield managed includes (BEGIN) — do not edit between markers ---"
SURI_INC_END="# --- IntelShield managed includes (END) ---"

# (Re)generate the include block from the drop-ins that actually exist.
# Idempotent: strips any previous managed block, then appends a fresh one.
suricata_write_include_block(){
  [[ -f "$SURICATA_YAML" ]] || return 1
  mkdir -p "$SURICATA_INCLUDE_DIR"
  local tmp="$IS_TMP/suricata.yaml.new" f files=()
  for f in "$SURICATA_INCLUDE_DIR"/*.yaml; do [[ -f "$f" ]] && files+=("$f"); done
  awk -v b="$SURI_INC_BEGIN" -v e="$SURI_INC_END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip{print}' \
      "$SURICATA_YAML" >"$tmp" || return 1
  [[ -s "$tmp" ]] || return 1     # refuse to install an obviously truncated result
  if [[ ${#files[@]} -gt 0 ]]; then
    { echo "$SURI_INC_BEGIN"
      echo "include:"
      for f in "${files[@]}"; do echo "  - $f"; done
      echo "$SURI_INC_END"
    } >>"$tmp"
  fi
  cp -f "$tmp" "$SURICATA_YAML"
}

# Write the two baseline drop-ins every install needs (HOME_NET + capture NIC),
# then rewire the include block. Validation happens in the caller's -T pass.
# Dual-stack: detects IPv6 egress IPs and builds the correct HOME_NET format.
suricata_write_base_dropins(){
  mkdir -p "$SURICATA_INCLUDE_DIR"
  if [[ -n "$PUB_IP" ]]; then
    # Build HOME_NET based on whether the egress IP is IPv4 or IPv6
    local home_net
    if [[ "$PUB_IP" == *":"* ]]; then
      # IPv6 egress — use bracket notation for Suricata
      home_net="[$PUB_IP/128,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8]"
    else
      # IPv4 egress
      home_net="[$PUB_IP/32,127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    fi
    cat >"$SURICATA_INCLUDE_DIR/10-vars.yaml" <<EOF
# IntelShield override — HOME_NET pinned to this relay's egress IP + RFC1918/ULA
# Generated: $(date -u '+%F %T') — egress: $PUB_IP
vars:
  address-groups:
    HOME_NET: "$home_net"
    EXTERNAL_NET: "!\\$HOME_NET"
EOF
  fi
  if [[ -n "$NIC" ]]; then
    cat >"$SURICATA_INCLUDE_DIR/20-capture.yaml" <<EOF
# IntelShield override — capture on the default-route NIC (passive IDS af-packet)
af-packet:
  - interface: $NIC
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
EOF
  fi
  suricata_write_include_block
}

# Atomically apply ONE drop-in override: write it (content on stdin), rewire the
# include block, validate with `suricata -T` and restart. On ANY failure both the
# drop-in AND suricata.yaml are restored to their previous state, so a bad
# override can never take the sensor down. $1 = drop-in basename.
suricata_apply_dropin(){
  # two `local` statements on purpose: in `local a="$1" b="$a"`, $a expands
  # BEFORE the assignment takes effect and b would see the outer scope's value
  local name="$1" bak dropbak=""
  local f="$SURICATA_INCLUDE_DIR/$name"
  mkdir -p "$SURICATA_INCLUDE_DIR"
  bak="$(suricata_yaml_backup)" || true
  [[ -f "$f" ]] && { dropbak="$IS_TMP/dropin.$name.prev"; cp -a "$f" "$dropbak"; }
  cat >"$f"
  suricata_write_include_block
  if suricata_validate_restart "$bak"; then return 0; fi
  # validate_restart already restored suricata.yaml; also restore the drop-in
  # itself, otherwise the OLD include block would reference the NEW bad content.
  if [[ -n "$dropbak" ]]; then cp -a "$dropbak" "$f"; else rm -f "$f"; fi
  suricata_write_include_block
  return 1
}

# ---- SID-based rule self-heal (v8.0) ------------------------------------------
# A single engine-incompatible rule fails the WHOLE `suricata -T`, which used to
# make us reject ~40k good rules; v6-v7 then commented lines out of the MERGED
# rules file by line number — fragile, because suricata-update rewrites that file
# on every run and the line numbers shift. v8.0 uses suricata-update's own native
# mechanism instead: the failing SIDs (parsed from the engine's error output) are
# registered in an IntelShield-managed block of /etc/suricata/disable.conf, and
# suricata-update re-merges the ruleset with them cleanly omitted. The bypass
# therefore SURVIVES every future rule update instead of being overwritten by it.
SURI_DISABLE_BEGIN="# IntelShield auto-disabled (engine-incompatible) BEGIN — managed block, do not edit"
SURI_DISABLE_END="# IntelShield auto-disabled END"

# print the SIDs currently inside the managed block (one per line)
suricata_disabled_sids(){
  [[ -f "$SURICATA_DISABLE_CONF" ]] || return 0
  awk -v b="$SURI_DISABLE_BEGIN" -v e="$SURI_DISABLE_END" '$0==b{f=1;next} $0==e{f=0;next} f' "$SURICATA_DISABLE_CONF" | grep -E '^[0-9]+$' || true
}
# rewrite the managed block from stdin (one SID per line); user entries outside
# the markers — group: mutes, manual sids — are preserved untouched.
suricata_write_disabled_sids(){
  local tmp="$IS_TMP/disable.conf.new"
  touch "$SURICATA_DISABLE_CONF"
  awk -v b="$SURI_DISABLE_BEGIN" -v e="$SURI_DISABLE_END" '$0==b{f=1;next} $0==e{f=0;next} !f' "$SURICATA_DISABLE_CONF" >"$tmp"
  { echo "$SURI_DISABLE_BEGIN"; grep -E '^[0-9]+$' || true; echo "$SURI_DISABLE_END"; } >>"$tmp"
  mv -f "$tmp" "$SURICATA_DISABLE_CONF"
}

suricata_sanitize_rules(){
  local rules="/var/lib/suricata/rules/suricata.rules" err new_sids prior merged n iter=0 max=10 start_cnt
  [[ -f "$rules" ]] || return 1
  start_cnt="$(suricata_disabled_sids | grep -c . || true)"
  while (( iter++ < max )); do
    err="$IS_TMP/suri-T"
    if suricata -T -c "$SURICATA_YAML" >"$err" 2>&1; then
      cat "$err" >>"$LOG"
      SURI_SANITIZED=$(( $(suricata_disabled_sids | grep -c . || true) - start_cnt ))
      (( SURI_SANITIZED < 0 )) && SURI_SANITIZED=0
      (( SURI_SANITIZED > 0 )) && log "suricata_sanitize_rules: bypassed $SURI_SANITIZED engine-incompatible rule(s) via disable.conf; ruleset is now valid"
      return 0
    fi
    cat "$err" >>"$LOG"
    # 1st choice: the engine's error lines quote the failing rule — read its sid:
    new_sids="$(grep -iE 'error|fail' "$err" | grep -oE 'sid[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | sort -un)"
    # fallback: resolve "at line N" references against the merged rules file
    if [[ -z "$new_sids" ]]; then
      new_sids="$(grep -oE 'at line [0-9]+' "$err" | grep -oE '[0-9]+' | sort -un | while read -r n; do
        sed -n "${n}p" "$rules" | grep -oE 'sid[[:space:]]*:[[:space:]]*[0-9]+' | grep -oE '[0-9]+'
      done | sort -un)"
    fi
    [[ -z "$new_sids" ]] && { log "suricata_sanitize_rules: -T failed with no resolvable SID (config-level error, not a signature)"; return 1; }
    prior="$(suricata_disabled_sids)"
    merged="$(printf '%s\n%s\n' "$prior" "$new_sids" | grep -E '^[0-9]+$' | sort -un)"
    if [[ "$merged" == "$prior" ]]; then
      log "suricata_sanitize_rules: engine still rejects already-disabled SIDs — treating as config-level"; return 1
    fi
    printf '%s\n' "$merged" | suricata_write_disabled_sids
    log "suricata_sanitize_rules: pass $iter — disabling SID(s): $(tr '\n' ' ' <<<"$new_sids")"
    # re-merge so the disabled SIDs are cleanly omitted; our -T stays the arbiter
    run suricata-update --no-test --no-reload || { log "suricata_sanitize_rules: suricata-update re-merge failed"; return 1; }
  done
  log "suricata_sanitize_rules: still failing after $max repair passes"
  return 1
}

suricata_repair(){ m_suricata; }
suricata_tune_lowram(){
  have suricata || m_suricata
  if suricata_apply_dropin 30-tuning.yaml <<'EOF'
# IntelShield override — low-RAM VPS tuning
max-pending-packets: 1024
detect:
  profile: low
EOF
  then state_write; msg Suricata "Low-RAM VPS tuning applied (drop-in: ${SURICATA_INCLUDE_DIR}/30-tuning.yaml)."
  else msg Suricata "Tuning failed validation — previous config restored. See $LOG."; return 1; fi
}
suricata_tune_highthroughput(){
  have suricata || m_suricata
  if suricata_apply_dropin 30-tuning.yaml <<'EOF'
# IntelShield override — high-throughput server tuning
max-pending-packets: 8192
detect:
  profile: high
EOF
  then state_write; msg Suricata "High-throughput tuning applied (drop-in: ${SURICATA_INCLUDE_DIR}/30-tuning.yaml)."
  else msg Suricata "Tuning failed validation — previous config restored. See $LOG."; return 1; fi
}
suricata_enable_tls_metadata(){
  have suricata || m_suricata
  mkdir -p /etc/suricata/rules
  cat >"$SURICATA_LOCAL_RULES" <<'EOF'
alert tls any any -> any any (msg:"IntelShield TLS metadata observed"; tls.sni; content:"."; sid:9900001; rev:1; threshold:type limit, track by_src, count 1, seconds 3600;)
alert quic any any -> any any (msg:"IntelShield QUIC traffic observed"; sid:9900002; rev:1; threshold:type limit, track by_src, count 1, seconds 3600;)
EOF
  # ABSOLUTE rule path so it resolves regardless of default-rule-path; the list
  # deliberately re-states suricata.rules — an include overrides the whole set.
  if suricata_apply_dropin 50-rules.yaml <<EOF
# IntelShield override — merged ruleset + local TLS/QUIC metadata rules
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - $SURICATA_LOCAL_RULES
EOF
  then state_write; msg Suricata "Encrypted metadata rules enabled. No payload decryption."
  else rm -f "$SURICATA_LOCAL_RULES"; msg Suricata "Rule validation failed (the QUIC keyword needs Suricata 7+). Rolled back cleanly."; return 1; fi
}
suricata_enable_ja(){
  have suricata || m_suricata
  # ja4-fingerprints is accepted (and used) by builds that support JA4; engines
  # without it ignore the unknown key — -T validates either way.
  if suricata_apply_dropin 40-app-layer.yaml <<'EOF'
# IntelShield override — TLS client fingerprinting for encrypted-traffic metadata
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes
EOF
  then state_write; msg Suricata "JA3/JA4 fingerprinting enabled (drop-in: ${SURICATA_INCLUDE_DIR}/40-app-layer.yaml)."
  else msg Suricata "JA3/JA4 not supported by this Suricata build — rolled back."; return 1; fi
}
suricata_packet_drops(){ local f="$IS_TMP/suricata-drops"; { echo "Suricata packet/drop counters"; date -Is; echo; grep -Ei 'drop|capture.kernel|decoder.pkts|tcp.reassembly_gap|memcap' /var/log/suricata/stats.log 2>/dev/null | tail -120 || true; echo; have ethtool && ethtool -S "${NIC:-}" 2>/dev/null | grep -Ei 'drop|error|miss|timeout|crc' || true; } >"$f"; showfile "Suricata Packet Drops" "$f" 34 118; }
suricata_top_alerts(){ local f="$IS_TMP/suricata-top-alerts"; if [[ -f /var/log/suricata/eve.json ]] && have jq; then jq -r 'select(.event_type=="alert") | [.alert.severity,.alert.signature_id,.alert.signature] | @tsv' /var/log/suricata/eve.json 2>/dev/null | sort | uniq -c | sort -rn | head -50 >"$f"; else echo "eve.json or jq not available" >"$f"; fi; showfile "Top Suricata Alerts" "$f" 34 118; }
suricata_suppress_signature(){ local sid ip line; sid=$(input "Suppress Signature" "Suricata signature ID to suppress:" "") || return; [[ "$sid" =~ ^[0-9]+$ ]] || { msg Suricata "Invalid SID"; return 1; }; ip=$(input "Suppress Signature" "Optional IP/CIDR. Leave blank for global suppress:" "") || return; touch "$SURICATA_THRESHOLD"; if [[ -n "$ip" ]]; then valid_ip "$ip" || { msg Suricata "Invalid IP/CIDR"; return 1; }; line="suppress gen_id 1, sig_id $sid, track by_either, ip $ip"; else line="suppress gen_id 1, sig_id $sid"; fi; grep -Fxq "$line" "$SURICATA_THRESHOLD" || echo "$line" >>"$SURICATA_THRESHOLD"; if suricata -T -c "$SURICATA_YAML" >>"$LOG" 2>&1; then run systemctl restart suricata; msg Suricata "Suppression added:\n$line"; else grep -vFx "$line" "$SURICATA_THRESHOLD" >"$SURICATA_THRESHOLD.tmp" 2>/dev/null && mv -f "$SURICATA_THRESHOLD.tmp" "$SURICATA_THRESHOLD"; msg Suricata "Suppression rejected by validator — removed. See $LOG."; return 1; fi; }
# Atomic, self-healing rule update. suricata-update can pull rules whose keywords
# don't match the installed engine, which corrupts the live rule file and makes the
# NEXT restart/reboot crash Suricata. We snapshot the current good ruleset first,
# let suricata-update write, validate the whole config with `suricata -T`, and on
# failure ROLL BACK to the snapshot so a bad fetch can never take the sensor down.
# v8.0: the restart itself is also gated — if the daemon does not come back after
# an otherwise-valid update, the snapshot is restored and the old engine restarted.
SURI_RULES_LIVE="/var/lib/suricata/rules/suricata.rules"
SURI_RULES_SNAP=""
suricata_rules_rollback(){   # restore the pre-update ruleset (restart_or_rollback hook)
  [[ -n "$SURI_RULES_SNAP" && -f "$SURI_RULES_SNAP" ]] && cp -a "$SURI_RULES_SNAP" "$SURI_RULES_LIVE" 2>/dev/null
}
suricata_update_rules(){
  have suricata || { msg Suricata "Install Suricata first."; return 1; }
  have suricata-update || { msg Suricata "suricata-update not installed."; return 1; }
  SURI_RULES_SNAP="$IS_TMP/suricata.rules.snapshot"
  [[ -f "$SURI_RULES_LIVE" ]] && cp -a "$SURI_RULES_LIVE" "$SURI_RULES_SNAP" 2>/dev/null
  infobox "Suricata Rules" "Fetching + validating rules (honouring enable.conf / disable.conf / drop.conf).\n\nEngine-incompatible rules are bypassed via disable.conf; the good rules still load. A truly broken set is rolled back — the sensor is never left down."
  run suricata-update update-sources 2>>"$LOG" || true
  # --no-test/--no-reload: OUR `suricata -T` + gated restart are the arbiters
  run suricata-update --no-test --no-reload
  SURI_SANITIZED=0
  # keep the ~40k good rules: bypass only the SIDs the engine rejects.
  if suricata_sanitize_rules; then
    # reload first (cheap, no packet-loss window); verify; else gated restart
    if run systemctl reload suricata && systemctl is-active --quiet suricata; then :
    else restart_or_rollback suricata suricata_rules_rollback || { state_write; msg Suricata "Rules validated but the daemon failed to come back — rolled back to the previous ruleset. See $LOG."; return 1; }
    fi
    state_write
    if (( ${SURI_SANITIZED:-0} > 0 )); then
      msg Suricata "Rules updated and applied.\n\n${SURI_SANITIZED} rule(s) used keywords your Suricata build doesn't support and were bypassed via disable.conf — the remaining ruleset loaded cleanly (no outage).\n\nTip: the OISF PPA engine is installed by 'Install / repair Suricata'; a newer engine reduces these. See $LOG."
    else
      msg Suricata "Rules updated, validated and applied cleanly."
    fi
    return 0
  fi
  # sanitize couldn't produce a valid set (config-level problem) — revert to snapshot
  local healed="reverted to the previous known-good ruleset"
  if [[ -f "$SURI_RULES_SNAP" ]]; then cp -a "$SURI_RULES_SNAP" "$SURI_RULES_LIVE" 2>/dev/null
  else : >"$SURI_RULES_LIVE" 2>/dev/null; healed="no prior snapshot — wrote an empty safe ruleset to keep the engine startable"; fi
  if suricata -T -c "$SURICATA_YAML" >>"$LOG" 2>&1; then run systemctl reload suricata 2>>"$LOG" || true; fi
  log "suricata_update_rules: ruleset unrepairable via rule-disable; $healed"
  msg Suricata "The ruleset failed validation at the CONFIG level (not a single bad rule), so surgical repair couldn't help.\n\nSelf-heal: $healed.\nSuricata keeps running — no outage. See $LOG for the exact error."
  return 1
}
suricata_export_eve_summary(){ local out="/var/log/intelshield/suricata-eve-summary-$(date +%Y%m%d_%H%M%S).txt"; mkdir -p /var/log/intelshield; if [[ -f /var/log/suricata/eve.json ]] && have jq; then { echo "EVE event type counts"; jq -r '.event_type' /var/log/suricata/eve.json | sort | uniq -c | sort -rn; echo; echo "Top source IPs in alerts"; jq -r 'select(.event_type=="alert") | .src_ip' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -30; echo; echo "Top signatures"; jq -r 'select(.event_type=="alert") | .alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -rn | head -30; } >"$out"; chmod 600 "$out" 2>/dev/null || true; else echo "eve.json or jq not available" >"$out"; fi; showfile "EVE Summary Export" "$out" 34 118; }

#----------------------------- Suricata Rule Selection ------------------------
# Enable/disable whole rule SOURCES (ET open, etc.) via suricata-update.
suricata_rule_sources_menu(){
  have suricata-update || { msg Suricata "suricata-update not installed."; return 1; }
  infobox "Rule Sources" "Refreshing the rule-source index from the Internet..."
  run suricata-update update-sources
  local avail=() enabled name args=() sel
  mapfile -t avail < <(suricata-update list-sources 2>/dev/null | awk -F': ' '/^Name:/{print $2}' | sort -u)
  [[ ${#avail[@]} -gt 0 ]] || { msg Suricata "Could not fetch the source index (network?). See $LOG."; return 1; }
  enabled=" $(suricata-update list-enabled-sources 2>/dev/null | awk -F': ' '/^Name:/{print $2}' | tr '\n' ' ') "
  for name in "${avail[@]}"; do
    if [[ "$enabled" == *" $name "* ]]; then args+=("$name" "$name" ON); else args+=("$name" "$name" OFF); fi
  done
  sel=" $(checklist "Suricata Rule Sources" "Space=toggle. Paid sources that need a code are skipped automatically if they prompt." "${args[@]}" | tr -d '"') "
  [[ "$sel" =~ [^[:space:]] ]] || return   # cancelled / nothing chosen -> no change
  for name in "${avail[@]}"; do
    if [[ "$sel" == *" $name "* ]]; then run suricata-update enable-source "$name"; else run suricata-update disable-source "$name" || true; fi
  done
  suricata_update_rules
}
# Mute noisy/low-value ET categories via disable.conf (IntelShield-managed group: lines).
suricata_rule_categories_menu(){
  local cats=(emerging-info emerging-policy emerging-games emerging-p2p emerging-chat emerging-icmp_info emerging-misc emerging-dns emerging-user_agents) cat args=() sel
  touch "$SURICATA_DISABLE_CONF"
  for cat in "${cats[@]}"; do
    if grep -qxF "group:${cat}.rules" "$SURICATA_DISABLE_CONF"; then args+=("$cat" "currently DISABLED" ON); else args+=("$cat" "currently enabled" OFF); fi
  done
  sel=" $(checklist "Mute Noisy Rule Categories" "Checked = MUTED (disabled). These are high-noise / low-value on an encrypted relay." "${args[@]}" | tr -d '"') "
  # rebuild only the IntelShield-managed 'group:*.rules' lines, preserving other entries
  grep -v '^group:.*\.rules$' "$SURICATA_DISABLE_CONF" 2>/dev/null >"$SURICATA_DISABLE_CONF.tmp" || true; mv -f "$SURICATA_DISABLE_CONF.tmp" "$SURICATA_DISABLE_CONF"
  for cat in "${cats[@]}"; do [[ "$sel" == *" $cat "* ]] && echo "group:${cat}.rules" >>"$SURICATA_DISABLE_CONF"; done
  suricata_update_rules
}
# IPS blocking policy: which rules are converted from alert -> drop (drop.conf).
suricata_drop_policy_menu(){
  local c cur sid
  while :; do
    cur="alert-only"; [[ -s "$SURICATA_DROP_CONF" ]] && cur="active-drop ($(grep -c . "$SURICATA_DROP_CONF" 2>/dev/null) entr(y/ies))"
    c=$(menu "IPS Blocking Policy" "In IPS mode ONLY rules converted to 'drop' actually block. Current: $cur" \
      P "Apply conservative high-confidence DROP set (exploit/malware/trojan/shellcode/worm)" \
      A "Alert-only (clear the drop list — inline but never blocks)" \
      S "Add ONE specific SID to the drop list" \
      V "View current drop list" \
      b "Back") || return
    case "$c" in
      P) cat >"$SURICATA_DROP_CONF" <<'EOF'
# IntelShield conservative IPS drop policy — convert these categories to DROP.
group:emerging-exploit.rules
group:emerging-malware.rules
group:emerging-trojan.rules
group:emerging-shellcode.rules
group:emerging-attack_response.rules
group:emerging-worm.rules
EOF
         suricata_update_rules; msg Suricata "High-confidence DROP policy applied (in effect only while in IPS mode)." ;;
      A) : >"$SURICATA_DROP_CONF"; suricata_update_rules; msg Suricata "Drop list cleared — IPS is now alert-only (inline, non-blocking)." ;;
      S) sid=$(input "Drop SID" "Signature ID to convert to DROP:" "") || continue; [[ "$sid" =~ ^[0-9]+$ ]] || { msg Suricata "Invalid SID"; continue; }; touch "$SURICATA_DROP_CONF"; grep -qxF "$sid" "$SURICATA_DROP_CONF" || echo "$sid" >>"$SURICATA_DROP_CONF"; suricata_update_rules; msg Suricata "SID $sid will DROP in IPS mode." ;;
      V) { echo "drop.conf ($SURICATA_DROP_CONF):"; echo; cat "$SURICATA_DROP_CONF" 2>/dev/null || echo "(empty = alert-only)"; } >"$IS_TMP/dropconf"; showfile "IPS Drop List" "$IS_TMP/dropconf" ;;
      b) return ;;
    esac
  done
}
suricata_rules_menu(){
  have suricata || { msg Suricata "Install Suricata first."; return 1; }
  local c cnt
  while :; do
    cnt=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo '?')
    c=$(menu "Suricata Rule Management" "Loaded rules: ${cnt}. Pick sources, mute categories, set IPS drop policy." \
      S "Enable / disable rule SOURCES" \
      C "Mute noisy rule CATEGORIES" \
      D "IPS blocking policy (which rules DROP)" \
      U "Update + apply rules now" \
      P "Show current rule stats" \
      b "Back") || return
    case "$c" in
      S) suricata_rule_sources_menu ;;
      C) suricata_rule_categories_menu ;;
      D) suricata_drop_policy_menu ;;
      U) suricata_update_rules ;;
      P) { echo "== Enabled sources =="; suricata-update list-enabled-sources 2>/dev/null || echo "(suricata-update unavailable)"; echo; echo "Loaded rule count: $cnt"; echo; echo "== Muted categories (disable.conf) =="; grep '^group:' "$SURICATA_DISABLE_CONF" 2>/dev/null || echo "(none)"; echo; echo "== IPS drop policy (drop.conf) =="; cat "$SURICATA_DROP_CONF" 2>/dev/null || echo "(none = alert-only)"; } >"$IS_TMP/rulestats"; showfile "Suricata Rule Stats" "$IS_TMP/rulestats" ;;
      b) return ;;
    esac
  done
}

#----------------------------- Suricata IPS (inline) --------------------------
# Switch Suricata between passive IDS and inline IPS via NFQUEUE.
# Safety rails baked in: fail-open bypass (Suricata down => kernel accepts), the SSH
# port is never queued, and the queue table runs AFTER CrowdSec so both layers stack.
suricata_ips_enable(){
  have suricata || { m_suricata || return 1; }
  # Mutex check: Suricata FW mode and IPS cannot both be active
  if [[ "$(suricata_fw_mode_get)" == on ]]; then
    msg "Suricata IPS" "Suricata 8 Firewall Mode is currently active.\n\nDisable Firewall Mode first before enabling traditional IPS mode.\nThe two modes are mutually exclusive."
    return 1
  fi
  yesno "Enable Suricata IPS" "Switch Suricata to INLINE IPS (NFQUEUE)?\n\n• Fail-open: if Suricata stops, traffic still flows (no outage)\n• Your SSH port ($SSH_PORT) is excluded from inspection (no lockout)\n• :443 VLESS-Reality is encrypted — IPS can't read its payload; value is\n  blocking scans/exploits against the host + management plane\n\nProceed?" 20 92 || return
  local suri_bin nftbin ncpu qmax i qargs="" qspec
  suri_bin=$(command -v suricata || echo /usr/bin/suricata)
  have nft || run apt-get install -y nftables
  nftbin=$(command -v nft || echo /usr/sbin/nft)
  ncpu=$(nproc 2>/dev/null || echo 1); qmax=$((ncpu-1)); (( qmax>3 )) && qmax=3; (( qmax<0 )) && qmax=0
  for ((i=0;i<=qmax;i++)); do qargs+=" -q $i"; done
  if (( qmax==0 )); then qspec="queue num 0 flags bypass"; else qspec="queue num 0-$qmax flags bypass,fanout"; fi
  # ---- CrowdSec coexistence choice ----
  if have_cs; then
    if yesno "IPS + CrowdSec (recommended)" "RECOMMENDED: keep CrowdSec AND run Suricata IPS together.\n\nThey are complementary and layered:\n • CrowdSec bouncer drops known-bad IPs first (cheap, reputation-based)\n • Suricata then inspects survivors inline and drops on signature match\n • Suricata keeps feeding eve.json back to CrowdSec\n\nKeep CrowdSec enabled?\n\n(No = use Suricata IPS as the ONLY inline enforcer — the CrowdSec firewall\n bouncer is stopped. Not recommended: you lose crowd-sourced IP reputation.)" 22 96; then
      log "IPS: coexisting with CrowdSec (recommended layered mode)"
    else
      run systemctl disable --now crowdsec-firewall-bouncer || true
      suricata_mutex_set "suricata"
      msg "CrowdSec Bouncer Stopped" "Suricata IPS is now the sole inline enforcer.\nThe CrowdSec engine can stay for telemetry; re-enable the bouncer any time from the CrowdSec menu."
    fi
  fi
  mkdir -p /etc/nftables.d "$(dirname "$SURICATA_IPS_DROPIN")"
  cat >"$SURICATA_IPS_NFT" <<EOF
#!/usr/sbin/nft -f
# IntelShield · Suricata inline IPS (NFQUEUE).
# 'flags bypass' => if nothing is reading the queue (Suricata stopped/crashed/
# restarting) the kernel ACCEPTS the packet — fail-open, so no outage or lockout.
# SSH ($SSH_PORT) is excluded entirely. Priority 100 runs AFTER CrowdSec's drop
# table, so banned IPs are dropped cheaply first and only survivors are inspected.
table inet intelshield_ips {
    chain input {
        type filter hook input priority 100; policy accept;
        iif "lo" accept
        tcp dport $SSH_PORT accept
        meta l4proto { tcp, udp } $qspec
    }
    chain output {
        type filter hook output priority 100; policy accept;
        oif "lo" accept
        tcp sport $SSH_PORT accept
        meta l4proto { tcp, udp } $qspec
    }
}
EOF
  cat >"$SURICATA_IPS_SVC" <<EOF
[Unit]
Description=IntelShield Suricata IPS nftables (NFQUEUE) rules
After=nftables.service crowdsec-firewall-bouncer.service network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nftbin -f $SURICATA_IPS_NFT
ExecStop=-$nftbin delete table inet intelshield_ips
[Install]
WantedBy=multi-user.target
EOF
  cat >"$SURICATA_IPS_DROPIN" <<EOF
[Service]
# override the packaged af-packet command with an inline NFQUEUE command
Type=simple
ExecStartPre=
ExecStart=
ExecStart=$suri_bin -c $SURICATA_YAML --pidfile /run/suricata.pid$qargs
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_NICE CAP_IPC_LOCK CAP_SYS_RESOURCE
Restart=on-failure
RestartSec=3
EOF
  run systemctl daemon-reload
  run systemctl enable "$(basename "$SURICATA_IPS_SVC")"
  if ! "$nftbin" -f "$SURICATA_IPS_NFT" >>"$LOG" 2>&1; then
    rm -f "$SURICATA_IPS_NFT" "$SURICATA_IPS_SVC" "$SURICATA_IPS_DROPIN"; run systemctl daemon-reload
    msg Suricata "nftables IPS ruleset failed to load — aborted with NO change to Suricata. See $LOG."
    return 1
  fi
  run systemctl restart suricata
  sleep 3
  if systemctl is-active --quiet suricata; then
    echo ips >"$SURICATA_MODE_FILE"; state_write
    msg "Suricata IPS Active" "Suricata is now INLINE (NFQUEUE${qargs}).\n\nBlocking policy: $([[ -s "$SURICATA_DROP_CONF" ]] && echo 'active-drop' || echo 'alert-only — inline but NOT yet blocking; set drops via IPS blocking policy').\n\nFail-open and SSH-exclusion are enforced at the kernel level." 20 92
    return 0
  fi
  # ---- automatic rollback to IDS: traffic never blocked (fail-open) ----
  rm -f "$SURICATA_IPS_DROPIN"
  "$nftbin" delete table inet intelshield_ips 2>/dev/null || true
  run systemctl disable --now "$(basename "$SURICATA_IPS_SVC")" || true
  rm -f "$SURICATA_IPS_SVC" "$SURICATA_IPS_NFT"
  run systemctl daemon-reload; run systemctl restart suricata || true
  echo ids >"$SURICATA_MODE_FILE"; state_write
  msg Suricata "IPS failed to start — auto-reverted to IDS. Traffic was never blocked (fail-open). See $LOG."
  return 1
}
# quiet, promptless teardown of all IPS plumbing — reused by profile downgrades,
# the component control center and the uninstaller so no orphan NFQUEUE rules linger.
suricata_ips_teardown(){
  local nftbin; nftbin=$(command -v nft || echo /usr/sbin/nft)
  rm -f "$SURICATA_IPS_DROPIN"
  systemctl disable --now "$(basename "$SURICATA_IPS_SVC")" >>"$LOG" 2>&1 || true
  "$nftbin" delete table inet intelshield_ips 2>/dev/null || true
  rm -f "$SURICATA_IPS_SVC" "$SURICATA_IPS_NFT"
  systemctl daemon-reload >>"$LOG" 2>&1 || true
  echo ids >"$SURICATA_MODE_FILE" 2>/dev/null || true
  echo none >"$SURICATA_MUTEX_FILE" 2>/dev/null || true
}
suricata_ips_disable(){
  [[ "$(suri_mode_get)" == ips ]] || { msg Suricata "Suricata is already in IDS (passive) mode."; return 3; }
  [[ "$(suricata_fw_mode_get)" == on ]] && { msg Suricata "Suricata 8 Firewall Mode is active — disable that first."; return 1; }
  suricata_ips_teardown
  run systemctl restart suricata || true
  state_write
  if have_cs && ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
    yesno "Re-enable CrowdSec Bouncer?" "Suricata is back in passive IDS mode. The CrowdSec firewall bouncer is currently stopped — re-enable it so you keep inline enforcement?" && run systemctl enable --now crowdsec-firewall-bouncer
  fi
  msg Suricata "Reverted to IDS (passive) mode. NFQUEUE plumbing removed."
}
suricata_ips_menu(){
  have suricata || { msg Suricata "Install Suricata first (Install / repair)."; return 1; }
  local c m cs
  while :; do
    m=$(suri_mode_get); cs=$(svc_state crowdsec-firewall-bouncer)
    c=$(menu "Suricata IPS (inline) Mode" "Mode: ${m^^}   |   CrowdSec bouncer: ${cs}   |   drop policy: $([[ -s "$SURICATA_DROP_CONF" ]] && echo active-drop || echo alert-only)" \
      W "What is IPS mode? (read this first)" \
      E "Enable IPS (inline NFQUEUE — fail-open, SSH-safe)" \
      D "Disable IPS — revert to passive IDS" \
      B "IPS blocking policy (which rules DROP)" \
      b "Back") || return
    case "$c" in
      W) msg "About Suricata IPS" "IDS (default) = PASSIVE: Suricata watches a copy of traffic and only ALERTS.\n\nIPS (inline) = Suricata sits in the packet path (NFQUEUE) and can DROP.\n\nSafety rails IntelShield enforces:\n • fail-open — if Suricata stops, the kernel lets traffic through (no outage)\n • your SSH port is never queued (no lockout)\n • runs AFTER CrowdSec, so the two enforcement layers stack\n\nEncrypted-relay note: :443 VLESS-Reality is encrypted, so IPS can't inspect its\npayload — the win is blocking scans/exploits against the host + panel. Start with\nthe alert-only policy, then turn on drops for high-confidence categories." 24 96 ;;
      E) suricata_ips_enable ;;
      D) suricata_ips_disable ;;
      B) suricata_drop_policy_menu ;;
      b) return ;;
    esac
  done
}

suricata_intel_menu(){ local c m; while :; do m=$(suri_mode_get); c=$(menu "Suricata IDS/IPS Management" "Mode: ${m^^}. Install, go inline, choose rules, tune and monitor." I "Install / repair Suricata" M "IDS <-> IPS inline mode (NFQUEUE)" F "Suricata 8 Firewall Mode (default-drop pipeline)" R "Rule management (sources / categories / drops)" T "Transaction rule management (enable/disable/drop.conf)" L "Tune for low-RAM VPS" H "Tune for high-throughput server" E "Enable encrypted-traffic metadata rules" J "Enable JA3/JA4/SNI/certificate monitoring" D "View packet drops" A "View top alerting signatures" S "Suppress noisy signatures" U "Update rules" X "Export eve.json summary" b Back) || break; case "$c" in I) suricata_repair;; M) suricata_ips_menu;; F) suricata_fw_menu;; R) suricata_rules_menu;; T) suricata_transactional_rules_menu;; L) suricata_tune_lowram;; H) suricata_tune_highthroughput;; E) suricata_enable_tls_metadata;; J) suricata_enable_ja;; D) suricata_packet_drops;; A) suricata_top_alerts;; S) suricata_suppress_signature;; U) suricata_update_rules;; X) suricata_export_eve_summary;; b) break;; esac; done; }


#==============================================================================
#  SURICATA 8 FIREWALL MODE  (v8.3 — deterministic packet pipeline, default-drop)
#==============================================================================
# Suricata 8 introduces an experimental Firewall Mode that operates as a full
# stateful firewall engine rather than a traditional IDS/IPS sensor. Key differences:
#
# PACKET PIPELINE:
#   Traditional IDS:    af-packet capture → inspect → alert (passive copy)
#   Traditional IPS:    NFQUEUE → inspect → alert/drop (inline, fail-open)
#   Suricata 8 FW:      nfqueue → deterministic pipeline → default DROP
#                        ↑ every packet that isn't explicitly accepted is dropped
#
# ACTION SCOPES (Suricata 8 explicit actions):
#   accept:packet  — immediately accept this packet (no further inspection)
#   accept:flow    — accept all future packets in this flow
#   drop:packet    — immediately drop this packet
#   drop:flow      — drop all future packets in this flow
#   reject:packet  — drop + send ICMP unreachable / TCP RST
#
# RULE HOOKS:
#   packet:filter  — runs on every packet before flow reassembly (fast path)
#   app:filter     — runs after protocol detection (deep inspection path)
#
# DEFAULT POLICY: drop (if no rule accepts, the packet is dropped)
# This is the opposite of traditional IPS where the default is pass.

# Check if Suricata 8 firewall mode is available
suricata_fw_check_version(){
  local ver
  ver="$(suricata -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  [[ -z "$ver" ]] && return 1
  # Suricata 8.x+ required for firewall mode
  local major minor
  major="$(echo "$ver" | cut -d. -f1)"
  minor="$(echo "$ver" | cut -d. -f2)"
  (( major >= 8 )) && return 0
  return 1
}

# Read the firewall mode state
suricata_fw_mode_get(){ cat "$SURICATA_FW_MODE_FILE" 2>/dev/null || echo off; }

# Mutex management: only one of CrowdSec bouncer or Suricata FW mode can own
# the packet path at a given priority level. This prevents conflicting nftables
# chains from both trying to verdict the same packets.
suricata_mutex_get(){ cat "$SURICATA_MUTEX_FILE" 2>/dev/null || echo none; }
suricata_mutex_set(){ echo "$1" >"$SURICATA_MUTEX_FILE"; }
# Check if CrowdSec bouncer is actively managing nftables rules
suricata_mutex_crowdsec_active(){
  have_cs && systemctl is-active --quiet crowdsec-firewall-bouncer 2>/dev/null
}

# Write the Suricata 8 Firewall Mode nftables rules.
# Priority mapping:
#   priority 0  = CrowdSec bouncer (cheap IP-reputation drops at the edge)
#   priority 10 = Suricata FW mode (deep inspection, deterministic pipeline)
#
# The FW mode chain uses a TWO-TIER approach:
#   1. Explicit bypass rules (SSH, loopback, established) → accept
#   2. Everything else → NFQUEUE (Suricata's deterministic pipeline)
#   3. Suricata's internal default policy: DROP (no matching accept rule = drop)
suricata_fw_write_nft(){
  local nftbin; nftbin=$(command -v nft || echo /usr/sbin/nft)
  local ncpu qmax i qargs="" qspec
  ncpu=$(nproc 2>/dev/null || echo 1); qmax=$((ncpu-1)); (( qmax>3 )) && qmax=3; (( qmax<0 )) && qmax=0
  for ((i=0;i<=qmax;i++)); do qargs+=" -q $i"; done
  if (( qmax==0 )); then qspec="queue num 0 flags bypass"; else qspec="queue num 0-$qmax flags bypass,fanout"; fi

  cat >"$SURICATA_FW_NFT" <<EOF
#!/usr/sbin/nft -f
# IntelShield · Suricata 8 Firewall Mode (deterministic packet pipeline)
#
# nftables priority orchestration:
#   CrowdSec bouncer:  priority ${SURICATA_CROWDSEC_PRIORITY}  (edge — IP reputation)
#   Suricata FW mode:  priority ${SURICATA_FW_PRIORITY}  (deep inspection, default-drop)
#
# 'flags bypass' = fail-open: if Suricata is not reading the queue (crashed,
# restarting), the kernel ACCEPTS the packet — no outage or lockout.
#
# SSH is excluded from the queue to prevent lockout. Loopback is accepted.
# Established TCP connections on SSH port bypass inspection.
# The NFQUEUE verdict goes to Suricata's deterministic pipeline where the
# default policy is DROP — only explicitly accepted packets survive.
table inet ${SURICATA_FW_CHAIN} {
    # Flow table for established connections (performance optimization)
    set bypass_v4 {
        type ipv4_addr
        flags dynamic,timeout
        timeout 30s
    }
    set bypass_v6 {
        type ipv6_addr
        flags dynamic,timeout
        timeout 30s
    }

    chain input {
        type filter hook input priority ${SURICATA_FW_PRIORITY}; policy drop;

        # Loopback always accepted
        iif "lo" accept

        # SSH port excluded from queue (anti-lockout)
        tcp dport $SSH_PORT accept

        # ICMP for path MTU discovery and diagnostics (rate-limited)
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr icmpv6 limit rate 10/second accept

        # All remaining traffic → Suricata NFQUEUE (deterministic pipeline)
        meta l4proto { tcp, udp } $qspec
    }

    chain output {
        type filter hook output priority ${SURICATA_FW_PRIORITY}; policy accept;

        # Loopback always accepted
        oif "lo" accept

        # SSH source port excluded (return traffic for admin session)
        tcp sport $SSH_PORT accept

        # Outbound inspection (Suricata can inspect outbound for C2 detection)
        meta l4proto { tcp, udp } $qspec
    }
}
EOF
}

# Write the systemd drop-in for Suricata 8 Firewall Mode.
# The key difference from IPS mode: Suricata runs with --firewall flag and
# the NFQUEUE verdict uses deterministic pipeline (default-drop).
suricata_fw_write_dropin(){
  local suri_bin; suri_bin=$(command -v suricata || echo /usr/bin/suricata)
  local ncpu qmax i qargs=""
  ncpu=$(nproc 2>/dev/null || echo 1); qmax=$((ncpu-1)); (( qmax>3 )) && qmax=3; (( qmax<0 )) && qmax=0
  for ((i=0;i<=qmax;i++)); do qargs+=" -q $i"; done

  mkdir -p "$(dirname "$SURICATA_FW_DROPIN")"
  cat >"$SURICATA_FW_DROPIN" <<EOF
[Service]
# Suricata 8 Firewall Mode: deterministic packet pipeline with default-drop.
# --firewall enables the experimental firewall mode engine.
# The pipeline processes packets through:
#   1. packet:filter hooks (fast path, before flow reassembly)
#   2. protocol detection
#   3. app:filter hooks (deep inspection, after protocol detection)
#   4. default policy: DROP (if no accept:packet or accept:flow matched)
Type=simple
ExecStartPre=
ExecStart=
ExecStart=$suri_bin -c $SURICATA_YAML --pidfile /run/suricata.pid --firewall$qargs
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_NICE CAP_IPC_LOCK CAP_SYS_RESOURCE
Restart=on-failure
RestartSec=3
EOF
}

# Write the Suricata 8 Firewall Mode default-drop ruleset.
# These rules use Suricata 8's explicit action scopes and rule hooks:
#   - packet:filter rules run fast, before flow reassembly
#   - app:filter rules run after protocol detection (deeper inspection)
#   - accept:packet / accept:flow explicitly whitelist traffic
#   - drop:flow blocks entire flows on first match
suricata_fw_write_rules(){
  local fw_rules="/etc/suricata/rules/intelshield-fw-defaults.rules"
  mkdir -p "$(dirname "$fw_rules")"
  cat >"$fw_rules" <<'EOF'
# IntelShield Suricata 8 Firewall Mode — Default-Drop Pipeline Rules
# These rules define the explicit accept/drop policy for the firewall mode.
# Traffic NOT matching any accept rule is DROPPED by Suricata's default policy.
#
# Action scopes used:
#   accept:packet  — accept this individual packet (fast path)
#   accept:flow    — accept all future packets in this TCP/UDP flow
#   drop:flow      — drop all future packets in this flow (persistent block)
#   drop:packet    — drop this single packet (transient block)
#
# Rule hooks:
#   packet:filter  — evaluated on every packet (pre-flow, fast path)
#   app:filter     — evaluated after protocol detection (deep inspection)

# --- packet:filter rules (fast path, pre-flow) ---

# Accept DNS responses (essential for host resolution)
alert dns any any -> any 53 (msg:"IntelShield FW: DNS response accepted"; \
  flow:to_server,established; sid:9100001; rev:1; \
  classtype:policy-violation;)

# Accept ICMP/ICMPv6 (path MTU, diagnostics — rate-limited at nftables level)
alert icmp any any -> any any (msg:"IntelShield FW: ICMP accepted"; \
  sid:9100002; rev:1;)

# --- app:filter rules (deep inspection, post-protocol-detection) ---

# Block known exploit patterns with drop:flow (persistent block)
drop http any any -> any any (msg:"IntelShield FW: SQL injection attempt"; \
  flow:to_server,established; \
  pcre:"/(union\s+select|insert\s+into|drop\s+table|update\s+.*set)/i"; \
  sid:9100100; rev:1; classtype:web-application-attack;)

drop http any any -> any any (msg:"IntelShield FW: Directory traversal"; \
  flow:to_server,established; \
  content:".."; http_uri; pcre:"/\.\.[\/\\\\]/"; \
  sid:9100101; rev:1; classtype:web-application-attack;)

# Block known malware C2 callbacks
drop tcp any any -> any any (msg:"IntelShield FW: Suspicious outbound C2 pattern"; \
  flow:to_server,established; \
  dsize:<100; threshold:type limit, track by_src, count 3, seconds 60; \
  sid:9100200; rev:1; classtype:trojan-activity;)

# Entropy-based detection (Suricata 8 keyword): block high-entropy DNS
# queries that may indicate DNS tunneling or DGA domains
alert dns any any -> any 53 (msg:"IntelShield FW: High-entropy DNS (possible tunnel)"; \
  flow:to_server,established; \
  dns.query; entropy > 4.5; \
  sid:9100300; rev:1; classtype:policy-violation;)

# Lua transform rule (Suricata 8 luaxform): detect unusual User-Agent strings
alert http any any -> any any (msg:"IntelShield FW: Anomalous User-Agent detected"; \
  flow:to_server,established; \
  http.user_agent; luaxform:normalize_ua; \
  sid:9100301; rev:1; classtype:policy-violation;)
EOF
  echo "$fw_rules"
}

# Enable Suricata 8 Firewall Mode.
# This replaces the traditional IDS/IPS mode with a deterministic packet pipeline.
suricata_fw_enable(){
  have suricata || { m_suricata || return 1; }

  if ! suricata_fw_check_version; then
    msg "Suricata 8 Firewall" "Suricata 8+ is required for Firewall Mode.\n\nCurrent version: $(suricata -V 2>/dev/null | tr -d '\n')\n\nThe OISF PPA ships Suricata 8 for Ubuntu 22.04/24.04. Run 'Install / repair Suricata' first."
    return 1
  fi

  # Mutex check: if CrowdSec bouncer is active, warn about coexistence
  if suricata_mutex_crowdsec_active; then
    msg "Suricata 8 Firewall + CrowdSec" "CrowdSec firewall bouncer is currently active.\n\nSuricata 8 Firewall Mode and CrowdSec bouncer both use nftables chains. IntelShield will configure them with separate priorities:\n\n  CrowdSec:  priority ${SURICATA_CROWDSEC_PRIORITY} (edge, IP reputation)\n  Suricata:  priority ${SURICATA_FW_PRIORITY} (deep inspection)\n\nThis is the recommended layered configuration." 20 96
  fi

  yesno "Enable Suricata 8 Firewall Mode" "Switch Suricata to EXPERIMENTAL FIREWALL MODE?\n\nThis enables a DETERMINISTIC PACKET PIPELINE with DEFAULT-DROP policy:\n\n• Every packet NOT explicitly accepted is DROPPED (opposite of traditional IPS)\n• Uses Suricata 8's explicit action scopes: accept:packet, drop:flow, etc.\n• Rule hooks: packet:filter (fast path) + app:filter (deep inspection)\n• SSH port ($SSH_PORT) excluded from inspection (anti-lockout)\n• Fail-open: if Suricata stops, traffic still flows (no outage)\n\nWARNING: This is an experimental feature in Suricata 8.\nStart with alert-only rules, then enable drops after testing.\n\nProceed?" 22 96 || return

  local nftbin; nftbin=$(command -v nft || echo /usr/sbin/nft)
  have nft || run apt-get install -y nftables

  # Take a pre-change snapshot for rollback
  local bak; bak="$(suricata_yaml_backup)" || true

  # Write the firewall mode components
  suricata_fw_write_nft
  local fw_rules; fw_rules="$(suricata_fw_write_rules)"
  suricata_fw_write_dropin

  # Wire the firewall rules into the ruleset
  suricata_apply_dropin 60-firewall.yaml <<EOF
# IntelShield override — Suricata 8 Firewall Mode configuration
# Default-drop policy: traffic not matching any accept rule is dropped
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules
  - $SURICATA_LOCAL_RULES
  - $fw_rules

# Suricata 8 Firewall Mode engine settings
app-layer:
  protocols:
    tls:
      ja3-fingerprints: yes
      ja4-fingerprints: yes
    http:
      enabled: yes
    dns:
      enabled: yes
    ssh:
      enabled: yes
EOF
  if [[ $? -ne 0 ]]; then
    rm -f "$SURICATA_FW_NFT" "$SURICATA_FW_DROPIN"
    [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"
    msg "Suricata 8 Firewall" "Config validation failed — rolled back. See $LOG."
    return 1
  fi

  # Install the nftables service
  cat >"$SURICATA_FW_SVC" <<EOF
[Unit]
Description=IntelShield Suricata 8 Firewall Mode nftables rules
After=nftables.service crowdsec-firewall-bouncer.service network-pre.target
Wants=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$nftbin -f $SURICATA_FW_NFT
ExecStop=-$nftbin delete table inet ${SURICATA_FW_CHAIN}
[Install]
WantedBy=multi-user.target
EOF
  run systemctl daemon-reload
  run systemctl enable "$(basename "$SURICATA_FW_SVC")"

  # Load the nftables rules
  if ! "$nftbin" -f "$SURICATA_FW_NFT" >>"$LOG" 2>&1; then
    rm -f "$SURICATA_FW_NFT" "$SURICATA_FW_SVC" "$SURICATA_FW_DROPIN"
    run systemctl daemon-reload
    [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"
    msg "Suricata 8 Firewall" "nftables firewall ruleset failed to load — aborted. See $LOG."
    return 1
  fi

  run systemctl restart suricata
  sleep 3

  if systemctl is-active --quiet suricata; then
    echo on >"$SURICATA_FW_MODE_FILE"
    echo "suricata" >"$SURICATA_MUTEX_FILE"
    state_write
    msg "Suricata 8 Firewall Mode Active" "Suricata is now in EXPERIMENTAL FIREWALL MODE.\n\nPipeline: deterministic packet inspection → default DROP\nAction scopes: accept:packet, accept:flow, drop:flow, drop:packet\nRule hooks: packet:filter (fast) + app:filter (deep inspection)\n\nnftables priority: CrowdSec=${SURICATA_CROWDSEC_PRIORITY} | Suricata=${SURICATA_FW_PRIORITY}\n\nFail-open and SSH-exclusion are enforced at the kernel level.\n\nStart with alert-only rules, then enable drops via IPS blocking policy." 22 96
    return 0
  fi

  # Rollback: service didn't come up
  rm -f "$SURICATA_FW_DROPIN"
  "$nftbin" delete table inet "${SURICATA_FW_CHAIN}" 2>/dev/null || true
  run systemctl disable --now "$(basename "$SURICATA_FW_SVC")" 2>/dev/null || true
  rm -f "$SURICATA_FW_SVC" "$SURICATA_FW_NFT"
  run systemctl daemon-reload
  [[ -n "$bak" && -f "$bak" ]] && cp -a "$bak" "$SURICATA_YAML"
  run systemctl restart suricata || true
  echo ids >"$SURICATA_MODE_FILE"; echo off >"$SURICATA_FW_MODE_FILE"
  suricata_mutex_set none; state_write
  msg "Suricata 8 Firewall" "Firewall mode failed to start — auto-reverted to IDS. Traffic was never blocked (fail-open). See $LOG."
  return 1
}

# Teardown Suricata 8 Firewall Mode (quiet, no prompts — reused by profile
# downgrades, component control, and uninstaller).
suricata_fw_teardown(){
  local nftbin; nftbin=$(command -v nft || echo /usr/sbin/nft)
  rm -f "$SURICATA_FW_DROPIN"
  systemctl disable --now "$(basename "$SURICATA_FW_SVC")" >>"$LOG" 2>&1 || true
  "$nftbin" delete table inet "${SURICATA_FW_CHAIN}" 2>/dev/null || true
  rm -f "$SURICATA_FW_SVC" "$SURICATA_FW_NFT"
  # Remove the firewall-mode drop-in from suricata config
  rm -f "$SURICATA_INCLUDE_DIR/60-firewall.yaml"
  suricata_write_include_block 2>/dev/null || true
  systemctl daemon-reload >>"$LOG" 2>&1 || true
  echo off >"$SURICATA_FW_MODE_FILE" 2>/dev/null || true
  echo none >"$SURICATA_MUTEX_FILE" 2>/dev/null || true
}

# Disable Suricata 8 Firewall Mode and revert to IDS
suricata_fw_disable(){
  [[ "$(suricata_fw_mode_get)" == on ]] || { msg "Suricata 8 Firewall" "Firewall mode is not active."; return 3; }
  suricata_fw_teardown
  run systemctl restart suricata || true
  state_write
  # Offer to re-enable CrowdSec bouncer if it was stopped for the mutex
  if have_cs && ! systemctl is-active --quiet crowdsec-firewall-bouncer; then
    yesno "Re-enable CrowdSec Bouncer?" "Suricata Firewall mode is off. The CrowdSec firewall bouncer is currently stopped — re-enable it?" && run systemctl enable --now crowdsec-firewall-bouncer
  fi
  msg "Suricata 8 Firewall" "Reverted to IDS (passive) mode. Firewall mode plumbing removed."
}

# View Suricata 8 Firewall Mode status and exception policies
suricata_fw_status(){
  local f="$IS_TMP/suricata-fw-status"
  {
    echo "Suricata 8 Firewall Mode Status — $(date -Is)"
    echo "================================================================"
    echo "Firewall mode  : $(suricata_fw_mode_get)"
    echo "Mutex owner    : $(suricata_mutex_get)"
    echo "Engine version : $(suricata -V 2>/dev/null | tr -d '\n')"
    echo "Mode file      : $(suri_mode_get)"
    echo
    echo "=== nftables rules ==="
    nft list table inet "${SURICATA_FW_CHAIN}" 2>/dev/null || echo "(no firewall mode table)"
    echo
    echo "=== Exception policies (Suricata 8 granular stats) ==="
    if [[ -f /var/log/suricata/stats.log ]]; then
      grep -Ei 'exception|drop|reject|pass|tcp\.reassembly_gap|memcap|detect\.engine' \
        /var/log/suricata/stats.log 2>/dev/null | tail -40 || echo "(no stats available)"
    else
      echo "(stats.log not found — Suricata may not have run yet)"
    fi
    echo
    echo "=== CPU affinity ==="
    # Suricata 8 auto-configures CPU affinity; show the result
    grep -Ei 'thread|cpu|affinity|worker' "$SURICATA_YAML" 2>/dev/null | head -20 || echo "(check suricata.yaml for threading section)"
    echo
    echo "=== Dropped streams ==="
    if [[ -f /var/log/suricata/stats.log ]]; then
      grep -Ei 'flow\.tcp\.reassembly_gap|flow\.icmp\.frag|decoder\.ipv4\.trunc|decoder\.ipv6\.trunc' \
        /var/log/suricata/stats.log 2>/dev/null | tail -10 || echo "(no drop counters)"
    fi
  } >"$f"
  showfile "Suricata 8 Firewall Mode Status" "$f" 36 120
}

# Firewall Mode menu
suricata_fw_menu(){
  have suricata || { msg "Suricata 8 Firewall" "Install Suricata first."; return 1; }
  local c m cs fw
  while :; do
    m=$(suri_mode_get); fw="$(suricata_fw_mode_get)"; cs=$(svc_state crowdsec-firewall-bouncer)
    c=$(menu "Suricata 8 Firewall Mode" "Engine: ${m^^}   FW mode: ${fw}   CrowdSec: ${cs}   mutex: $(suricata_mutex_get)" \
      W "What is Firewall Mode? (read this first)" \
      E "Enable Firewall Mode (deterministic pipeline, default-drop)" \
      D "Disable Firewall Mode — revert to passive IDS" \
      S "View Firewall Mode status + exception policies" \
      B "IPS blocking policy (which rules DROP)" \
      b "Back") || return
    case "$c" in
      W) msg "Suricata 8 Firewall Mode" "EXPERIMENTAL — Suricata 8 Firewall Mode replaces traditional IDS/IPS with a DETERMINISTIC PACKET PIPELINE.\n\nHow it works:\n  1. nftables captures packets via NFQUEUE\n  2. Suricata processes them through a deterministic pipeline:\n     - packet:filter hooks (fast path, before flow reassembly)\n     - protocol detection\n     - app:filter hooks (deep inspection, after protocol detection)\n  3. Default policy: DROP (if no rule explicitly accepts)\n\nAction scopes (Suricata 8):\n  accept:packet  — accept this packet immediately\n  accept:flow    — accept all future packets in this flow\n  drop:packet    — drop this packet immediately\n  drop:flow      — drop all future packets in this flow\n  reject:packet  — drop + send ICMP unreachable / TCP RST\n\nnftables priority orchestration:\n  CrowdSec:  priority 0  (edge — cheap IP reputation drops)\n  Suricata:  priority 10 (deep inspection, deterministic pipeline)\n\nSafety rails:\n  • fail-open: if Suricata stops, kernel accepts traffic (no outage)\n  • SSH port excluded from queue (no lockout)\n  • Mutex prevents conflicts with CrowdSec bouncer\n\nStart with alert-only rules (default), then enable drops for high-confidence\ncategories once you've verified the pipeline works on your traffic mix." 24 96 ;;
      E) suricata_fw_enable ;;
      D) suricata_fw_disable ;;
      S) suricata_fw_status ;;
      B) suricata_drop_policy_menu ;;
      b) return ;;
    esac
  done
}

#==============================================================================
#  TRANSACTIONAL RULE MANAGEMENT  (v8.3 — bidirectional rules, new keywords)
#==============================================================================
# Suricata 8 introduces transactional rules that combine request and response
# logic into single rule definitions. This saves CPU cycles by avoiding
# separate rules for each direction. The engine also adds 107 new keywords
# including entropy, luaxform, absent, and JSON dataset IoC context parsing.
#
# Transactional rule example (Suricata 8):
#   alert http any any -> any any (msg:"Transaction"; \
#     http.method; content:"POST"; \
#     http.response_body; content:"error"; \
#     sid:1234567; rev:1;)
#
# This single rule matches BOTH the request (POST) and response (error body)
# — previously you needed two separate rules.

# Manage the transactional rule configuration files (enable/disable/drop.conf)
# via a dynamic CLI interface.
suricata_transactional_rules_menu(){
  have suricata || { msg "Suricata" "Install Suricata first."; return 1; }
  local c
  while :; do
    c=$(menu "Transactional Rule Management" "Manage rule states via enable/disable/drop.conf.\n\nSuricata 8 transactional rules combine request+response logic.\nNew keywords: entropy, luaxform, absent, JSON datasets." \
      V "View current disable.conf (muted rules)" \
      E "View current enable.conf (forced rules)" \
      D "View current drop.conf (IPS drop rules)" \
      A "Add SID to disable.conf (mute a rule)" \
      R "Remove SID from disable.conf" \
      G "Add SID to drop.conf (force drop in IPS)" \
      C "Clear drop.conf" \
      S "View loaded rule count + Suricata 8 keyword stats" \
      J "Parse JSON datasets for IoC context" \
      b "Back") || return
    case "$c" in
      V) { echo "=== disable.conf ($SURICATA_DISABLE_CONF) ==="; echo; cat "$SURICATA_DISABLE_CONF" 2>/dev/null || echo "(empty)"; } >"$IS_TMP/disconf"
         showfile "disable.conf" "$IS_TMP/disconf" 34 118 ;;
      E) { echo "=== enable.conf ($SURICATA_ENABLE_CONF) ==="; echo; cat "$SURICATA_ENABLE_CONF" 2>/dev/null || echo "(empty)"; } >"$IS_TMP/enconf"
         showfile "enable.conf" "$IS_TMP/enconf" 34 118 ;;
      D) { echo "=== drop.conf ($SURICATA_DROP_CONF) ==="; echo; cat "$SURICATA_DROP_CONF" 2>/dev/null || echo "(empty — alert-only)"; } >"$IS_TMP/drpconf"
         showfile "drop.conf" "$IS_TMP/drpconf" 34 118 ;;
      A) local sid; sid=$(input "Disable SID" "Signature ID to add to disable.conf (mute):" "") || continue
         [[ "$sid" =~ ^[0-9]+$ ]] || { msg "Suricata" "Invalid SID — must be numeric."; continue; }
         touch "$SURICATA_DISABLE_CONF"
         # Preserve the IntelShield managed block (v8.0 SID self-heal)
         if grep -qxF "$sid" "$SURICATA_DISABLE_CONF"; then
           msg "Suricata" "SID $sid is already in disable.conf."
         else
           # Add outside the managed block (user entry)
           echo "$sid" >>"$SURICATA_DISABLE_CONF"
           msg "Suricata" "SID $sid added to disable.conf.\nRun 'Update rules' to re-merge the ruleset."
         fi ;;
      R) local sid; sid=$(input "Enable SID" "Signature ID to remove from disable.conf (re-enable):" "") || continue
         [[ "$sid" =~ ^[0-9]+$ ]] || { msg "Suricata" "Invalid SID."; continue; }
         if grep -qxF "$sid" "$SURICATA_DISABLE_CONF" 2>/dev/null; then
           grep -vxF "$sid" "$SURICATA_DISABLE_CONF" >"$IS_TMP/disable.tmp" 2>/dev/null
           mv -f "$IS_TMP/disable.tmp" "$SURICATA_DISABLE_CONF"
           msg "Suricata" "SID $sid removed from disable.conf.\nRun 'Update rules' to re-merge."
         else
           msg "Suricata" "SID $sid not found in disable.conf."
         fi ;;
      G) local sid; sid=$(input "Drop SID" "Signature ID to add to drop.conf (force drop in IPS):" "") || continue
         [[ "$sid" =~ ^[0-9]+$ ]] || { msg "Suricata" "Invalid SID."; continue; }
         touch "$SURICATA_DROP_CONF"
         grep -qxF "$sid" "$SURICATA_DROP_CONF" || echo "$sid" >>"$SURICATA_DROP_CONF"
         msg "Suricata" "SID $sid will DROP in IPS/Firewall mode.\nRun 'Update rules' to apply." ;;
      C) yesno "Clear drop.conf" "Remove ALL entries from drop.conf?\n\nIPS mode will become alert-only (no blocking)." || continue
         : >"$SURICATA_DROP_CONF"
         msg "Suricata" "drop.conf cleared — IPS is now alert-only." ;;
      S) { echo "Suricata Rule Statistics — $(date -Is)"
           echo "================================================================"
           local cnt; cnt=$(wc -l < /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo '?')
           echo "Loaded rules: $cnt"
           echo
           echo "=== Suricata 8 keyword support ==="
           # Check for Suricata 8 specific keywords in the ruleset
           local rules="/var/lib/suricata/rules/suricata.rules"
           if [[ -f "$rules" ]]; then
             echo "entropy keywords     : $(grep -c 'entropy' "$rules" 2>/dev/null || echo 0)"
             echo "luaxform keywords    : $(grep -c 'luaxform' "$rules" 2>/dev/null || echo 0)"
             echo "absent keywords      : $(grep -c 'absent' "$rules" 2>/dev/null || echo 0)"
             echo "dataset rules        : $(grep -c 'dataset' "$rules" 2>/dev/null || echo 0)"
             echo "http2 keywords       : $(grep -c 'http2' "$rules" 2>/dev/null || echo 0)"
             echo "ja4 keywords         : $(grep -c 'ja4' "$rules" 2>/dev/null || echo 0)"
           fi
           echo
           echo "=== Transactional rules (bidirectional) ==="
           if [[ -f "$rules" ]]; then
             echo "flow rules (bidir)   : $(grep -c 'flow:' "$rules" 2>/dev/null || echo 0)"
             echo "alert rules          : $(grep -c '^alert' "$rules" 2>/dev/null || echo 0)"
             echo "drop rules           : $(grep -c '^drop' "$rules" 2>/dev/null || echo 0)"
             echo "reject rules         : $(grep -c '^reject' "$rules" 2>/dev/null || echo 0)"
           fi
           echo
           echo "=== Enabled sources ==="
           suricata-update list-enabled-sources 2>/dev/null || echo "(suricata-update unavailable)"
           echo
           echo "=== Muted categories (disable.conf) ==="
           grep '^group:' "$SURICATA_DISABLE_CONF" 2>/dev/null || echo "(none)"
           echo
           echo "=== IPS drop policy (drop.conf) ==="
           cat "$SURICATA_DROP_CONF" 2>/dev/null || echo "(none = alert-only)"
         } >"$IS_TMP/rule-stats-8"
         showfile "Suricata 8 Rule Statistics" "$IS_TMP/rule-stats-8" 36 120 ;;
      J) # Parse JSON datasets for IoC context
         { echo "JSON Dataset IoC Context — $(date -Is)"
           echo "================================================================"
           if [[ -d "$SURICATA_DATASETS_DIR" ]]; then
             local ds
             for ds in "$SURICATA_DATASETS_DIR"/*.json; do
               [[ -f "$ds" ]] || continue
               echo "--- $(basename "$ds") ---"
               # Count entries and show sample structure
               local total; total=$(grep -c '{' "$ds" 2>/dev/null || echo '?')
               echo "  entries: $total"
               # Show first 5 entries as sample
               head -n 5 "$ds" 2>/dev/null | jq -c '.' 2>/dev/null || head -n 5 "$ds"
               echo
             done
           else
             echo "No datasets directory at $SURICATA_DATASETS_DIR"
             echo "Datasets are populated by suricata-update from threat intelligence feeds."
           fi
           echo
           echo "=== Dataset references in rules ==="
           local rules="/var/lib/suricata/rules/suricata.rules"
           [[ -f "$rules" ]] && grep 'dataset' "$rules" 2>/dev/null | head -20 || echo "(no dataset rules found)"
         } >"$IS_TMP/dataset-ioc"
         showfile "JSON Dataset IoC Context" "$IS_TMP/dataset-ioc" 36 120 ;;
      b) return ;;
    esac
  done
}

# Atomic rule state management: add/remove SIDs from disable.conf with
# automatic validation. Uses deterministic execution gates:
#   1. Validate input (SID must be numeric, conf must be known)
#   2. Backup the target file before modification
#   3. Apply the change atomically (write to tmp, then mv)
#   4. Validate the change was applied correctly
#   5. Log the action with timestamp
# This replaces manual file surgery and ensures no half-written states.
suricata_rule_state_toggle(){
  local conf="$1" sid="$2" action="$3"
  local file="" bak="" tmp=""
  # --- Gate 1: Input validation ---
  case "$conf" in
    disable) file="$SURICATA_DISABLE_CONF" ;;
    enable)  file="$SURICATA_ENABLE_CONF" ;;
    drop)    file="$SURICATA_DROP_CONF" ;;
    *) log "suricata_rule_state_toggle: unknown conf '$conf'"; return 1 ;;
  esac
  [[ "$sid" =~ ^[0-9]+$ ]] || { log "suricata_rule_state_toggle: invalid SID '$sid'"; return 1; }
  [[ "$action" == "add" || "$action" == "remove" ]] || { log "suricata_rule_state_toggle: unknown action '$action'"; return 1; }
  # --- Gate 2: Backup before modification ---
  touch "$file"
  bak="$IS_TMP/$(basename "$file").bak.$(date +%s)"
  cp -a "$file" "$bak" 2>/dev/null || true
  # --- Gate 3: Atomic write ---
  tmp="$file.tmp.$$"
  case "$action" in
    add)
      grep -qxF "$sid" "$file" 2>/dev/null && {
        log "suricata_rule_state_toggle: SID $sid already in $conf"
        rm -f "$tmp" 2>/dev/null
        return 0
      }
      cat "$file" >"$tmp" 2>/dev/null
      echo "$sid" >>"$tmp"
      ;;
    remove)
      grep -vxF "$sid" "$file" >"$tmp" 2>/dev/null
      ;;
  esac
  # --- Gate 4: Validate and commit ---
  if [[ -s "$tmp" ]] || [[ "$action" == "remove" ]]; then
    mv -f "$tmp" "$file"
  else
    rm -f "$tmp" 2>/dev/null
    log "suricata_rule_state_toggle: empty result after $action SID $sid from $conf — aborting"
    [[ -f "$bak" ]] && cp -a "$bak" "$file" 2>/dev/null
    return 1
  fi
  # --- Gate 5: Verify the change was applied ---
  case "$action" in
    add)    grep -qxF "$sid" "$file" 2>/dev/null || { log "suricata_rule_state_toggle: verification failed — SID $sid not found after add"; [[ -f "$bak" ]] && cp -a "$bak" "$file" 2>/dev/null; return 1; } ;;
    remove) grep -qxF "$sid" "$file" 2>/dev/null && { log "suricata_rule_state_toggle: verification failed — SID $sid still present after remove"; [[ -f "$bak" ]] && cp -a "$bak" "$file" 2>/dev/null; return 1; } ;;
  esac
  log "suricata_rule_state_toggle: $action SID $sid in $conf (verified)"
  # Cleanup backup (keep last 5 per conf)
  local bdir bak_count
  bdir="$(dirname "$bak")"
  bak_count=$(find "$bdir" -maxdepth 1 -name "$(basename "$file").bak.*" 2>/dev/null | wc -l)
  if (( bak_count > 5 )); then
    find "$bdir" -maxdepth 1 -name "$(basename "$file").bak.*" -printf '%T@ %p\n' 2>/dev/null \
      | sort -n | head -n $((bak_count - 5)) | awk '{print $2}' \
      | xargs rm -f 2>/dev/null
  fi
  return 0
}

# Transactional rule application: applies changes from disable/enable/drop.conf
# with deterministic execution gates. Used by the maintenance engine and CLI.
# Gate sequence: snapshot -> validate -> apply -> verify -> restart-or-rollback
suricata_apply_transactional_rules(){
  local mode="${1:-validate}"  # validate | apply
  local pre_snapshot post_snapshot
  # Gate 1: Snapshot current state for rollback
  pre_snapshot="$IS_TMP/suricata-rules-pre-transactional"
  [[ -f /var/lib/suricata/rules/suricata.rules ]] && cp -a /var/lib/suricata/rules/suricata.rules "$pre_snapshot" 2>/dev/null
  # Gate 2: Run suricata-update to re-merge with current conf files
  if ! run suricata-update --no-test --no-reload 2>>"$LOG"; then
    log "suricata_apply_transactional_rules: suricata-update re-merge failed"
    return 1
  fi
  # Gate 3: Validate the merged ruleset
  if ! suricata_sanitize_rules; then
    log "suricata_apply_transactional_rules: rule validation failed — rolling back"
    [[ -f "$pre_snapshot" ]] && cp -a "$pre_snapshot" /var/lib/suricata/rules/suricata.rules 2>/dev/null
    return 1
  fi
  # Gate 4: If in apply mode, restart Suricata
  if [[ "$mode" == "apply" ]]; then
    if run systemctl reload suricata && systemctl is-active --quiet suricata; then
      log "suricata_apply_transactional_rules: rules applied and reloaded successfully"
    else
      restart_or_rollback suricata "" || {
        log "suricata_apply_transactional_rules: restart failed — rolling back rules"
        [[ -f "$pre_snapshot" ]] && cp -a "$pre_snapshot" /var/lib/suricata/rules/suricata.rules 2>/dev/null
        run systemctl reload suricata 2>>"$LOG" || true
        return 1
      }
    fi
  fi
  log "suricata_apply_transactional_rules: transaction completed (mode=$mode)"
  return 0
}

#----------------------------- Wazuh Agent Integration ------------------------
wazuh_add_repo(){ run apt-get update || true; run apt-get install -y gnupg apt-transport-https curl ca-certificates; if [[ ! -f /usr/share/keyrings/wazuh.gpg ]]; then curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import >>"$WAZUH_LOG" 2>&1; chmod 644 /usr/share/keyrings/wazuh.gpg; fi; echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' >/etc/apt/sources.list.d/wazuh.list; run apt-get update; }
wazuh_write_helper(){ cat >"$WAZUH_HELPER" <<'EOF'
#!/usr/bin/env bash
# emit exactly one JSON object; is-active/is-enabled print AND return non-zero, so
# capture stdout into a var and default it (a bare '|| echo x' would add a 2nd line
# and produce invalid JSON for the Wazuh command collector).
profile="$(cat /var/lib/intelshield/active-profile 2>/dev/null || echo none)"
agent_status="$(systemctl is-active wazuh-agent 2>/dev/null)"; [ -z "$agent_status" ] && agent_status=missing
agent_enabled="$(systemctl is-enabled wazuh-agent 2>/dev/null)"; [ -z "$agent_enabled" ] && agent_enabled=disabled
manager="$(grep -m1 '<address>' /var/ossec/etc/ossec.conf 2>/dev/null | sed -E 's/.*<address>([^<]+)<\/address>.*/\1/')"
printf '{"component":"intelshield-wazuh","agent_status":"%s","agent_enabled":"%s","manager":"%s","intelshield_profile":"%s","updated_at":"%s"}\n' "$agent_status" "$agent_enabled" "$manager" "$profile" "$(date -Is)"
EOF
chmod 750 "$WAZUH_HELPER"; }
wazuh_managed_block(){ cat <<'EOF'
  <!-- INTELSHIELD-WAZUH-MANAGED-START -->
  <localfile><location>/var/log/intelshield.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/intelshield-wazuh.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/lib/intelshield/state.json</location><log_format>json</log_format></localfile>
  <localfile><location>/var/lib/intelshield/preflight-risk.json</location><log_format>json</log_format></localfile>
  <localfile><location>/var/log/suricata/eve.json</location><log_format>json</log_format></localfile>
  <localfile><location>/var/log/suricata/fast.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/suricata/stats.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/crowdsec.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/ufw.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/auth.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/syslog</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/audit/audit.log</location><log_format>audit</log_format></localfile>
  <localfile><location>/var/log/clamav/freshclam.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/clamav/scan_*.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/clamav/quarantine/.manifest.tsv</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/log/intelshield/anti-rootkit/*.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>/var/lib/intelshield/anti-rootkit/quarantine/manifest.tsv</location><log_format>syslog</log_format></localfile>
  <localfile><location>journald</location><log_format>journald</log_format></localfile>
  <localfile><command>/usr/local/bin/intelshieldctl-wazuh</command><alias>intelshield-wazuh-status</alias><frequency>300</frequency><log_format>json</log_format></localfile>
  <syscheck>
    <directories check_all="yes" realtime="yes">/etc/intelshield,/var/lib/intelshield,/etc/sysctl.d,/etc/ssh/sshd_config.d,/etc/ufw,/etc/crowdsec,/etc/suricata,/etc/audit,/etc/systemd/system/x-ui.service.d,/etc/systemd/system/xray.service.d,/usr/local/etc/xray,/etc/xray</directories>
    <ignore>/var/lib/intelshield/anti-rootkit/quarantine</ignore>
    <ignore>/var/clamav/quarantine</ignore>
  </syscheck>
  <!-- INTELSHIELD-WAZUH-MANAGED-END -->
EOF
}
wazuh_strip_managed_block(){ [[ -f "$WAZUH_OSSEC" ]] || return 0; python3 - "$WAZUH_OSSEC" <<'PY'
import sys,re,pathlib
p=pathlib.Path(sys.argv[1]); s=p.read_text(errors='ignore'); s=re.sub(r'\n?\s*<!-- INTELSHIELD-WAZUH-MANAGED-START -->.*?<!-- INTELSHIELD-WAZUH-MANAGED-END -->\s*\n?', '\n', s, flags=re.S); p.write_text(s)
PY
}
wazuh_configure_logs(){ wazuh_agent_present || { msg Wazuh "Wazuh agent is not installed."; return 1; }; [[ -f "$WAZUH_OSSEC" ]] || { msg Wazuh "Missing $WAZUH_OSSEC"; return 1; }; do_backup >/dev/null 2>&1 || true; cp -a "$WAZUH_OSSEC" "$WAZUH_OSSEC.intelshield.bak.$(date +%s)"; wazuh_write_helper; wazuh_strip_managed_block; local block tmp; block="$(wazuh_managed_block)"; tmp="$(mktemp "${WAZUH_OSSEC}.XXXXXX")"; awk -v block="$block" '/<\/ossec_config>/ && !done { print block; done=1 } { print }' "$WAZUH_OSSEC" >"$tmp"; chown --reference="$WAZUH_OSSEC" "$tmp" 2>/dev/null || true; chmod --reference="$WAZUH_OSSEC" "$tmp" 2>/dev/null || true; mv -f "$tmp" "$WAZUH_OSSEC"; run systemctl restart wazuh-agent || true; state_write; msg "Wazuh Log Forwarding" "IntelShield log forwarding, FIM, journald and command status collection configured."; }
wazuh_configure_fim(){ wazuh_configure_logs; }
wazuh_configure_commands(){ wazuh_write_helper; wazuh_configure_logs; }
wazuh_configure_active_response_safe(){ wazuh_agent_present || { msg Wazuh "Wazuh agent is not installed."; return 1; }; do_backup >/dev/null 2>&1 || true; mkdir -p /var/ossec/active-response/bin; cat >"$WAZUH_AR_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -u
OUTDIR="/var/log/intelshield/wazuh-active-response"; mkdir -p "$OUTDIR"; TS="$(date +%Y%m%d_%H%M%S)"
{ echo "IntelShield Wazuh Safe Active Response - $TS"; echo "Hostname: $(hostname)"; echo "Date: $(date -Is)"; echo; echo "== sockets =="; ss -tunap 2>/dev/null || true; echo; echo "== ufw =="; ufw status verbose 2>/dev/null || true; echo; echo "== crowdsec =="; cscli decisions list 2>/dev/null || true; echo; echo "== failed systemd units =="; systemctl --failed --no-pager 2>/dev/null || true; echo; echo "== intelshield state =="; cat /var/lib/intelshield/state.json 2>/dev/null || true; echo; echo "== risk =="; cat /var/lib/intelshield/preflight-risk.json 2>/dev/null || true; } >"$OUTDIR/safe-response-${TS}.txt"
exit 0
EOF
chmod 750 "$WAZUH_AR_SCRIPT"; state_write; msg "Wazuh Safe Active Response" "Safe evidence-only response installed. Configure triggers on Wazuh manager side."; }
wazuh_install_agent(){ local manager agent_name agent_group regpass opts=(); manager="$(input "Wazuh Agent" "Wazuh Manager IP/FQDN:" "")" || return 3; [[ -n "$manager" ]] || { msg "Wazuh Agent" "Manager address is required."; return 1; }; agent_name="$(input "Wazuh Agent" "Agent name shown in Wazuh dashboard:" "$(hostname)-intelshield")" || return 3; agent_group="$(input "Wazuh Agent" "Agent group, optional:" "intelshield")" || return 3; regpass="$(secret_input "Wazuh Agent" "Enrollment password/key, optional (hidden):")" || return 3; do_backup >/dev/null 2>&1 || true; wazuh_add_repo; [[ -n "$agent_name" ]] && opts+=("WAZUH_AGENT_NAME=$agent_name"); [[ -n "$agent_group" ]] && opts+=("WAZUH_AGENT_GROUP=$agent_group"); [[ -n "$regpass" ]] && opts+=("WAZUH_REGISTRATION_PASSWORD=$regpass"); if ! env WAZUH_MANAGER="$manager" "${opts[@]}" apt-get install -y wazuh-agent >>"$WAZUH_LOG" 2>&1; then msg "Wazuh Agent" "apt-get install wazuh-agent FAILED — integration not configured. See $WAZUH_LOG."; return 1; fi; run systemctl daemon-reload || true; run systemctl enable --now wazuh-agent; wazuh_write_helper; wazuh_configure_logs; wazuh_configure_active_response_safe; state_write; msg "Wazuh Agent" "Installed and IntelShield integration configured."; }
wazuh_status(){ state_write; { echo "IntelShield Wazuh Agent Status - $(date -Is)"; echo; systemctl status wazuh-agent --no-pager 2>/dev/null || echo "wazuh-agent service not found"; echo; /var/ossec/bin/wazuh-control status 2>/dev/null || true; echo; echo "== state =="; jq . "$STATE_DB" 2>/dev/null || cat "$STATE_DB" 2>/dev/null || true; } >"$IS_TMP/wazuh-status.txt"; showfile "Wazuh Agent Status" "$IS_TMP/wazuh-status.txt" 34 118; }
wazuh_health(){ local f="$IS_TMP/wazuh-health.txt"; state_write; { echo "IntelShield Wazuh Integration Health - $(date -Is)"; [[ -x /var/ossec/bin/wazuh-control ]] && echo "OK agent binaries present" || echo "FAIL binaries missing"; systemctl is-active --quiet wazuh-agent && echo "OK wazuh-agent active" || echo "FAIL wazuh-agent inactive"; grep -q 'INTELSHIELD-WAZUH-MANAGED-START' "$WAZUH_OSSEC" 2>/dev/null && echo "OK managed ossec.conf block present" || echo "FAIL managed block missing"; [[ -x "$WAZUH_HELPER" ]] && echo "OK command/status helper present" || echo "FAIL helper missing"; [[ -x "$WAZUH_AR_SCRIPT" ]] && echo "OK safe active response script present" || echo "WARN safe active response missing"; } >"$f"; showfile "Wazuh Integration Health" "$f" 34 118; }
wazuh_repair(){ wazuh_agent_present || { msg "Wazuh Repair" "Wazuh agent missing. Install it first."; return 1; }; do_backup >/dev/null 2>&1 || true; wazuh_write_helper; wazuh_configure_logs; wazuh_configure_active_response_safe; run systemctl restart wazuh-agent || true; state_write; msg "Wazuh Repair" "Wazuh integration repaired."; }
wazuh_remove_integration(){ wazuh_agent_present || { msg "Wazuh Remove" "Wazuh agent is not installed."; return 3; }; yesno "Remove Wazuh Integration" "Remove IntelShield-managed Wazuh config and safe active response?" || return 3; do_backup >/dev/null 2>&1 || true; cp -a "$WAZUH_OSSEC" "$WAZUH_OSSEC.intelshield.remove.bak.$(date +%s)" 2>/dev/null || true; wazuh_strip_managed_block; rm -f "$WAZUH_HELPER" "$WAZUH_AR_SCRIPT"; run systemctl restart wazuh-agent || true; if yesno "Purge Wazuh Agent?" "Also purge wazuh-agent package? Choose No if used by other policy."; then run systemctl disable --now wazuh-agent || true; run apt-get purge -y wazuh-agent || true; run apt-get autoremove -y || true; fi; state_write; msg "Wazuh Remove" "IntelShield Wazuh integration removed safely."; }
wazuh_menu(){ local c; while :; do c=$(menu "Wazuh SIEM / XDR Integration" "Agent-only integration. Wazuh Manager installation is intentionally skipped." I "Install Wazuh Agent" L "Configure IntelShield → Wazuh log forwarding" F "Configure Wazuh FIM for IntelShield paths" C "Configure Wazuh command/status collection" A "Configure Wazuh active response — safe mode" S "View Wazuh agent status" H "View Wazuh integration health" R "Repair Wazuh integration" X "Remove Wazuh integration safely" b Back) || break; case "$c" in I) wazuh_install_agent;; L) wazuh_configure_logs;; F) wazuh_configure_fim;; C) wazuh_configure_commands;; A) wazuh_configure_active_response_safe;; S) wazuh_status;; H) wazuh_health;; R) wazuh_repair;; X) wazuh_remove_integration;; b) break;; esac; done; }


#----------------------------- Profiles ---------------------------------------
profile_details(){ case "$1" in vps-balanced) echo "Installs/enables: baseline, kernel tuning/security, CPU/platform audit, UFW, CrowdSec+bouncer, health. Disables heavy audit/IDS/AV timers.";; vps-high) echo "Installs/enables: VPS balanced + SSH hardening, Suricata, Suricata->CrowdSec, ClamAV, auditd, Anti-rootkit, sandbox.";; baremetal-high) echo "Installs/enables: VPS high + AIDE, AppArmor, high-throughput Suricata.";; vpn-performance) echo "Installs/enables: baseline, BBR, CPU audit, UFW, CrowdSec+bouncer, sandbox, panel restriction, health. Disables heavy services.";; forensic-audit) echo "Installs/enables: auditd, AIDE, Suricata, CrowdSec wiring, ClamAV, Anti-rootkit, forensics.";; minimal-safe) echo "Installs/enables: baseline, kernel security, UFW, CrowdSec+bouncer, health. Disables heavy services.";; esac; }
profile_disable_heavy(){ [[ "$(suri_mode_get)" == ips ]] && suricata_ips_teardown; [[ "$(suricata_fw_mode_get)" == on ]] && suricata_fw_teardown; run systemctl disable --now suricata || true; run systemctl disable --now auditd || true; run systemctl disable --now intelshield-clamscan-full.timer || true; run systemctl disable --now intelshield-clamscan-smart.timer || true; run systemctl disable --now intelshield-antirootkit-rkhunter.timer || true; run systemctl disable --now intelshield-antirootkit-chkrootkit.timer || true; }
profile_apply(){ local profile="$1" mods=(); yesno "Apply Profile" "$(profile_details "$profile")\n\nSwitching profiles is safe: needed modules are installed/enabled; downgrade profiles disable heavy components instead of purging packages.\n\nProceed?" 20 100 || return; do_backup >/dev/null 2>&1 || true; case "$profile" in vps-balanced) profile_disable_heavy; mods=(m_baseline m_kernel_network m_kernel_security m_cpu_microcode m_platform_security m_ufw m_crowdsec m_bouncer m_health_timer);; vps-high) mods=(m_baseline m_kernel_network m_kernel_security m_cpu_microcode m_platform_security m_ufw m_ssh m_crowdsec m_bouncer m_suricata m_wiring m_clamav_install m_auditd m_ark_install m_sandbox m_health_timer);; baremetal-high) mods=(m_baseline m_kernel_network m_kernel_security m_cpu_microcode m_platform_security m_ufw m_ssh m_crowdsec m_bouncer m_suricata m_wiring m_clamav_install m_auditd m_aide m_apparmor m_ark_install m_sandbox m_health_timer suricata_tune_highthroughput);; vpn-performance) profile_disable_heavy; mods=(m_baseline m_kernel_network m_cpu_microcode m_ufw m_crowdsec m_bouncer m_sandbox m_panel m_health_timer);; forensic-audit) mods=(m_baseline m_kernel_security m_cpu_microcode m_platform_security m_ufw m_crowdsec m_bouncer m_suricata m_wiring m_clamav_install m_auditd m_aide m_ark_install m_health_timer);; minimal-safe) profile_disable_heavy; mods=(m_baseline m_kernel_security m_ufw m_crowdsec m_bouncer m_health_timer);; *) msg Profile "Unknown profile: $profile"; return 1;; esac; for fn in "${mods[@]}"; do $fn || true; done; echo "$profile" >"$PROFILE_FILE"; state_write; msg "Profile Applied" "Active profile: $profile"; }
profiles_menu(){ local c; while :; do c=$(menu "IntelShield Profiles" "Choose a production profile. Existing packages are not purged when downgrading; heavy services/timers are disabled cleanly." 1 "VPS balanced" 2 "VPS high-security" 3 "Bare-metal high-security" 4 "VPN relay performance" 5 "Forensic/audit mode" 6 "Minimal safe mode" V "View current state" R "Run preflight risk engine" b Back) || break; case "$c" in 1) profile_apply vps-balanced;; 2) profile_apply vps-high;; 3) profile_apply baremetal-high;; 4) profile_apply vpn-performance;; 5) profile_apply forensic-audit;; 6) profile_apply minimal-safe;; V) state_view;; R) preflight_risk_engine;; b) break;; esac; done; }


# ---------- uninstall / revert ----------------------------------------------
uninstall_configs(){ yesno Uninstall "Remove IntelShield-managed configs/timers/drop-ins? A backup will be created first." || return; do_backup >/dev/null 2>&1 || true; suricata_ips_teardown; suricata_fw_teardown; for t in intelshield-health intelshield-clamscan-full intelshield-clamscan-smart intelshield-antirootkit-rkhunter intelshield-antirootkit-chkrootkit; do run systemctl disable --now ${t}.timer || true; rm -f /etc/systemd/system/${t}.service /etc/systemd/system/${t}.timer; done; run systemctl disable --now intelshield-cpu.service 2>/dev/null || true; rm -f "$SYSCTL_NET" "$SYSCTL_SEC" "$PERF_SYSCTL" "$ACQUIS_FILE" "$ALLOWLIST_FILE" "$CRON_FILE" /etc/modules-load.d/intelshield-bbr.conf /etc/rkhunter.conf.local "$ARK_CONF" "$SURICATA_LOCAL_RULES" "$UPGRADE_BLACKLIST" "$UPDATE_AUTOCONF"; rm -f "$MAINT_CRON" "$MAINT_LOGROTATE" "$UPDATE_CONF" /etc/logrotate.d/intelshield-suricata; rm -rf "$SURICATA_INCLUDE_DIR"; suricata_write_include_block 2>/dev/null || true; rmdir "$SURICATA_INCLUDE_DIR" 2>/dev/null || true; rm -f /etc/systemd/system/x-ui.service.d/99-intelshield-sandbox.conf /etc/systemd/system/xray.service.d/99-intelshield-sandbox.conf /etc/audit/rules.d/99-intelshield.rules /etc/systemd/system/intelshield-cpu.service /usr/local/sbin/intelshield-health; if yesno_danger "Revert SSH hardening?" "Also remove the IntelShield SSH drop-in (/etc/ssh/sshd_config.d/99-harden.conf)? This restores the previous SSH port/crypto policy."; then rm -f /etc/ssh/sshd_config.d/99-harden.conf; sshd -t 2>>"$LOG" && { run systemctl reload ssh || run systemctl reload sshd; }; fi; wazuh_strip_managed_block || true; run systemctl daemon-reload; run sysctl --system || true; state_write; msg Uninstall "IntelShield configs removed (Suricata IPS plumbing, timers, drop-ins). Backups/state preserved.\nNote: the canonical copy at /usr/local/sbin/intelshield was left in place."; }
purge_packages_prompt(){ local sel; sel=$(checklist "Purge Packages" "Select only items you do not use elsewhere." crowdsec "CrowdSec + bouncer" OFF suricata "Suricata" OFF clamav "ClamAV" OFF auditd "auditd" OFF aide "AIDE" OFF rkhunter "rkhunter" OFF chkrootkit "chkrootkit" OFF wazuh "Wazuh agent" OFF ufw "UFW" OFF) || return; sel=${sel//\"/}; [[ -z "$sel" ]] && return; yesno Purge "Purge: $sel ?" || return; case " $sel " in *" crowdsec "*) run apt-get purge -y crowdsec crowdsec-firewall-bouncer-nftables;; esac; case " $sel " in *" suricata "*) run apt-get purge -y suricata suricata-update;; esac; case " $sel " in *" clamav "*) run apt-get purge -y 'clamav*';; esac; case " $sel " in *" auditd "*) run apt-get purge -y auditd audispd-plugins;; esac; case " $sel " in *" aide "*) run apt-get purge -y aide aide-common;; esac; case " $sel " in *" rkhunter "*) run apt-get purge -y rkhunter;; esac; case " $sel " in *" chkrootkit "*) run apt-get purge -y chkrootkit;; esac; case " $sel " in *" wazuh "*) run systemctl disable --now wazuh-agent || true; run apt-get purge -y wazuh-agent;; esac; case " $sel " in *" ufw "*) run ufw disable || true; run apt-get purge -y ufw;; esac; run apt-get autoremove -y; state_write; msg Purge Done; }
#==============================================================================
#  COMPONENT CONTROL CENTER  (granular per-module disable / remove / purge)
#==============================================================================
# Each row: tag|label|units in STOP order|packages|IntelShield config files|hook
# Disabling one module never breaks another — 'hook' cleans the cross-wiring
# (e.g. muting Suricata unhooks the CrowdSec acquis so the engine isn't tailing a
# dead sensor; disabling CrowdSec stops its bouncer first; Wazuh keeps running
# through all of it because its logcollector tolerates missing files).
COMPONENTS=(
  "crowdsec|CrowdSec engine + bouncer|crowdsec-firewall-bouncer.service crowdsec.service|crowdsec crowdsec-firewall-bouncer-nftables|$ALLOWLIST_FILE $ACQUIS_FILE|"
  "suricata|Suricata IDS/IPS|suricata.service|suricata suricata-update|$SURICATA_LOCAL_RULES $SURICATA_THRESHOLD $SURICATA_DROP_CONF $SURICATA_DISABLE_CONF $SURICATA_ENABLE_CONF|comp_hook_suricata"
  "clamav|ClamAV antivirus|clamav-clamonacc.service clamav-daemon.service clamav-freshclam.service|clamav clamav-daemon clamav-freshclam clamav-base|$CLAMD_CONF|comp_hook_clamav"
  "auditd|auditd audit rules|auditd.service|auditd audispd-plugins|/etc/audit/rules.d/99-intelshield.rules|comp_hook_auditd"
  "aide|AIDE file integrity||aide aide-common||"
  "antirootkit|rkhunter + chkrootkit||rkhunter chkrootkit|/etc/rkhunter.conf.local $ARK_CONF|comp_hook_antirootkit"
  "wazuh|Wazuh agent integration|wazuh-agent.service|wazuh-agent||comp_hook_wazuh"
  "sandbox|x-ui/Xray systemd sandbox|||/etc/systemd/system/x-ui.service.d/99-intelshield-sandbox.conf /etc/systemd/system/xray.service.d/99-intelshield-sandbox.conf|comp_hook_sandbox"
  "ufw|UFW firewall||ufw||comp_hook_ufw"
  "kernelnet|Kernel network + BBR sysctls|||$SYSCTL_NET /etc/modules-load.d/intelshield-bbr.conf|comp_hook_sysctl"
  "kernelsec|Kernel security sysctls|||$SYSCTL_SEC|comp_hook_sysctl"
  "perf|Performance profile + CPU governor|intelshield-cpu.service||$PERF_SYSCTL /etc/systemd/system/intelshield-cpu.service|comp_hook_sysctl"
  "health|Health-check timer|intelshield-health.timer||/etc/systemd/system/intelshield-health.service /etc/systemd/system/intelshield-health.timer /usr/local/sbin/intelshield-health|"
  "autobackup|Weekly backup cron|||$CRON_FILE|"
  "maintenance|Maintenance & auto-update engine (cron)|||$MAINT_CRON $MAINT_LOGROTATE $UPDATE_CONF|"
)

comp_lookup(){ local e; for e in "${COMPONENTS[@]}"; do [[ "${e%%|*}" == "$1" ]] && { printf '%s' "$e"; return 0; }; done; return 1; }
comp_state_line(){ # compact per-unit status for the picker; 'config-only' if no units
  local u out=""; [[ -z "$1" ]] && { printf 'config-only'; return; }
  for u in $1; do if svc_exists "$u"; then out+="${u%%.*}:$(svc_state "$u") "; else out+="${u%%.*}:absent "; fi; done
  printf '%s' "${out% }"
}

# ---- cross-wiring hooks: $1 = disable | remove -------------------------------
comp_hook_suricata(){ [[ "$(suri_mode_get)" == ips ]] && suricata_ips_teardown   # drop inline plumbing
  [[ "$(suricata_fw_mode_get)" == on ]] && suricata_fw_teardown   # drop Suricata 8 FW plumbing
  if [[ "$1" == remove ]]; then
    # drop the v8 include architecture cleanly: delete the drop-ins, then
    # regenerate the managed block (now empty) so suricata.yaml has no dangling
    # include references that would fail the next -T.
    rm -rf "$SURICATA_INCLUDE_DIR"
    suricata_write_include_block 2>/dev/null || true
    rmdir "$SURICATA_INCLUDE_DIR" 2>/dev/null || true
    rm -f /etc/logrotate.d/intelshield-suricata
  fi
  if [[ -f "$ACQUIS_FILE" ]]; then rm -f "$ACQUIS_FILE"; systemctl is-active --quiet crowdsec && run systemctl restart crowdsec; fi; }
comp_hook_clamav(){ local t; for t in full smart; do run systemctl disable --now "intelshield-clamscan-${t}.timer" 2>/dev/null || true; [[ "$1" == remove ]] && rm -f "/etc/systemd/system/intelshield-clamscan-${t}.service" "/etc/systemd/system/intelshield-clamscan-${t}.timer"; done; run systemctl daemon-reload; }
comp_hook_antirootkit(){ ark_disable_schedule rkhunter; ark_disable_schedule chkrootkit; }
comp_hook_auditd(){ [[ "$1" == remove ]] && run augenrules --load || true; }
comp_hook_sandbox(){ if [[ "$1" == remove ]]; then sandbox_off; else run systemctl daemon-reload; local u; for u in x-ui xray; do systemctl is-active --quiet "$u" && run systemctl restart "$u"; done; fi; }
comp_hook_wazuh(){ wazuh_strip_managed_block || true; [[ "$1" == remove ]] && rm -f "$WAZUH_HELPER" "$WAZUH_AR_SCRIPT"; systemctl is-active --quiet wazuh-agent && run systemctl restart wazuh-agent || true; }
comp_hook_ufw(){ run ufw disable || true; }
comp_hook_sysctl(){ [[ "$1" == remove ]] && { run systemctl daemon-reload; run sysctl --system || true; }; }

# ---- lifecycle verbs ---------------------------------------------------------
comp_enable(){ local entry tag label units pkgs cfgs hook u rev=(); entry=$(comp_lookup "$1") || return 1; IFS='|' read -r tag label units pkgs cfgs hook <<<"$entry"
  for u in $units; do rev=("$u" "${rev[@]}"); done
  for u in "${rev[@]}"; do svc_exists "$u" && run systemctl enable --now "$u"; done
  state_write; msg "$label" "Enabled: ${units:-nothing to start (config-only component)}"; }
comp_disable(){ local entry tag label units pkgs cfgs hook u mode="${2:-disable}" f; entry=$(comp_lookup "$1") || return 1; IFS='|' read -r tag label units pkgs cfgs hook <<<"$entry"
  do_backup >/dev/null 2>&1 || true
  for u in $units; do svc_exists "$u" && run systemctl disable --now "$u"; done
  [[ -n "$hook" ]] && "$hook" "$mode"
  if [[ "$mode" == remove && -n "$cfgs" ]]; then for f in $cfgs; do rm -f "$f"; done; run systemctl daemon-reload; fi
  state_write
  msg "$label" "$([[ "$mode" == remove ]] && echo 'Disabled and IntelShield config removed. Packages kept.' || echo 'Stopped and disabled. Config + packages kept — re-enable any time.')"; }
comp_purge(){ local entry tag label units pkgs cfgs hook arr; entry=$(comp_lookup "$1") || return 1; IFS='|' read -r tag label units pkgs cfgs hook <<<"$entry"
  [[ -z "$pkgs" ]] && { msg "$label" "Config-only component — use Remove instead."; return 3; }
  comp_disable "$1" remove; read -ra arr <<<"$pkgs"; run apt-get purge -y "${arr[@]}"; run apt-get autoremove -y; state_write; msg "$label" "Purged packages: $pkgs"; }

comp_action_menu(){ local entry tag label units pkgs cfgs hook a; entry=$(comp_lookup "$1") || return; IFS='|' read -r tag label units pkgs cfgs hook <<<"$entry"
  a=$(menu "$label" "Units: ${units:-none}\nPackages: ${pkgs:-none}\nStatus: $(comp_state_line "$units")" \
    E "Enable + start" \
    D "Disable  (stop services; keep packages + config)" \
    R "Remove   (disable + delete IntelShield config; keep packages)" \
    P "Purge    (remove + uninstall packages)" \
    b "Back") || return
  case "$a" in
    E) comp_enable "$tag" ;;
    D) yesno_danger "Disable $label" "Stop and disable now?\n\nCross-wired modules are unhooked automatically (e.g. CrowdSec stops tailing Suricata)." && comp_disable "$tag" disable ;;
    R) yesno_danger "Remove $label" "Disable AND delete IntelShield-managed config for this component?\n\nA snapshot is taken first; packages are kept." && comp_disable "$tag" remove ;;
    P) yesno_danger "Purge $label" "Uninstall packages: ${pkgs}\n\nOnly proceed if nothing else on this host uses them." 15 78 && comp_purge "$tag" ;;
  esac; }
component_menu(){ local entry tag label units pkgs cfgs hook c args; while :; do args=(); for entry in "${COMPONENTS[@]}"; do IFS='|' read -r tag label units pkgs cfgs hook <<<"$entry"; args+=("$tag" "$label   [$(comp_state_line "$units")]"); done
    c=$(menu "Component Control Center" "Per-component lifecycle. Disabling one module never breaks another — cross-wiring is cleaned up automatically." "${args[@]}") || return
    comp_action_menu "$c"; done; }

uninstall_menu(){ local c; c=$(menu "Uninstall / Revert" "Safe removal options" M "Component control center (per-module disable/remove)" R "Restore snapshot" C "Remove IntelShield configs only" P "Purge selected packages" F "Full: configs + package purge" b Back) || return; case "$c" in M) component_menu;; R) m_restore_interface;; C) uninstall_configs;; P) purge_packages_prompt;; F) uninstall_configs; purge_packages_prompt;; esac; }


#==============================================================================
#  MODULE 3: CREATIVE FORENSIC ANALYSIS ENGINE (AI-OPTIMIZED)
#==============================================================================
# Copy a log non-destructively, capping huge files to the last N lines.
# $1 src  $2 dst  $3 max_lines(optional, default 8000)
fx_grab(){
  local src="$1" dst="$2" max="${3:-8000}" sz
  [[ -r "$src" ]] || return 0
  sz=$(stat -c%s "$src" 2>/dev/null || echo 0)
  if [[ "$sz" -gt 10485760 ]]; then tail -n "$max" "$src" >"$dst" 2>/dev/null
  else cp --preserve=timestamps "$src" "$dst" 2>/dev/null || tail -n "$max" "$src" >"$dst" 2>/dev/null; fi
}
fx_cmd(){ "$@" >/dev/null 2>&1; }   # reserved helper

# Gather EVERYTHING worth having into a single folder tree for AI/forensic review.
# $1 = destination folder (already empty)
run_forensic_collection(){
  local d="$1" b lf svc k f
  mkdir -p "$d"/{04-crowdsec,05-suricata,06-clamav,07-xui-xray,08-system-logs,09-kernel,10-processes} 2>/dev/null

  # ---------- 00 README (grounding context + ready-made AI prompt) ----------
  {
    echo "=============================================================================="
    echo " INTELSHIELD  ·  FORENSIC & MONITORING BUNDLE"
    echo "=============================================================================="
    echo "Generated (UTC)   : $(date -u '+%F %T')"
    echo "Generated (local) : $(date '+%F %T %Z')"
    echo "Hostname          : $(hostname)"
    echo "OS                : $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
    echo "Kernel            : $(uname -r)"
    echo "Uptime            : $(uptime -p 2>/dev/null || uptime 2>/dev/null)"
    echo "Egress IP / NIC   : ${PUB_IP:-?}  /  ${NIC:-?}        SSH port: ${SSH_PORT:-?}"
    echo
    echo "ROLE: Ubuntu edge relay — x-ui/3x-ui + Xray VLESS-Reality on :443, behind OPNsense."
    echo "      Suricata = IDS sensor · CrowdSec = IPS brain + firewall bouncer · ClamAV = AV."
    echo
    echo "CONTENTS"
    echo "  00-README.txt            this file"
    echo "  01-system-overview.txt   host, uptime, sessions, disk, memory"
    echo "  02-connections-state.txt LIVE socket snapshot + remote-IP / :443 summary"
    echo "  03-firewall.txt          ufw / nftables / iptables / addresses / routes / ARP"
    echo "  04-crowdsec/             cscli metrics, decisions, alerts, bouncers, hub, logs"
    echo "  05-suricata/             suricata.log, fast.log, stats.log, eve.json (capped)+alerts"
    echo "  06-clamav/               custom_suite.log, freshclam.log, scan logs, quarantine"
    echo "  07-xui-xray/             x-ui & xray journals, configs, app logs, listeners"
    echo "  08-system-logs/          auth, syslog, journal errors (48h), failed units"
    echo "  09-kernel/               dmesg, kernel journal, modules, security sysctls"
    echo "  10-processes/            process tree, top consumers, services, ports-by-PID"
    echo
    echo "------------------------------------------------------------------------------"
    echo "SUGGESTED AI PROMPT (copy this, then attach the files or the .tar.gz):"
    echo "------------------------------------------------------------------------------"
    echo "  You are a senior Linux DFIR and network-security analyst. This bundle comes"
    echo "  from an Ubuntu VLESS-Reality relay sitting behind an OPNsense firewall. Read"
    echo "  every file. Correlate CrowdSec decisions/alerts with Suricata eve alerts and"
    echo "  SSH auth failures. Flag: unexpected listeners or outbound connections, signs"
    echo "  of compromise, brute-force/scanning, config that weakens the relay, ClamAV"
    echo "  detections, and kernel/service errors. Return a prioritised findings list"
    echo "  (Critical/High/Medium/Low), each with the exact file + evidence and a concrete"
    echo "  remediation command. Note: traffic to/from :443 inside Reality is encrypted and"
    echo "  cannot be inspected by Suricata — judge it by metadata, not payload."
    echo
    echo "PRIVACY: contains IPs, ports, hostnames and possibly client source IPs + config"
    echo "  paths. Secrets (x-ui.db, private keys) are intentionally NOT included. Review"
    echo "  before sharing publicly. 02-connections-state is a point-in-time snapshot."
  } > "$d/00-README.txt"

  # ---------- 01 system overview ----------
  {
    echo "## HOSTNAMECTL";        hostnamectl 2>/dev/null
    echo; echo "## OS-RELEASE";   cat /etc/os-release 2>/dev/null
    echo; echo "## UNAME -A";     uname -a 2>/dev/null
    echo; echo "## UPTIME/LOAD";  uptime 2>/dev/null
    echo; echo "## DATE";         echo "UTC:   $(date -u)"; echo "Local: $(date)"
    echo; echo "## WHO / W";      who 2>/dev/null; echo "----"; w 2>/dev/null
    echo; echo "## LAST -n 25";   last -n 25 2>/dev/null
    echo; echo "## FAILED LOGINS (lastb -n 25)"; lastb -n 25 2>/dev/null || echo "n/a (no btmp / permission)"
    echo; echo "## DISK (df -h)"; df -h 2>/dev/null
    echo; echo "## LSBLK";        lsblk 2>/dev/null
    echo; echo "## MEMORY (free -m)"; free -m 2>/dev/null
  } > "$d/01-system-overview.txt"

  # ---------- 02 live connection state (its own snapshot log) ----------
  {
    echo "## ALL TCP/UDP SOCKETS (ss -tunap)"; ss -tunap 2>/dev/null
    echo; echo "## LISTENING PORTS (ss -tlnpu)"; ss -tlnpu 2>/dev/null
    echo; echo "## ESTABLISHED TCP COUNT"; ss -tnH state established 2>/dev/null | wc -l
    echo; echo "## TOP 25 REMOTE PEERS (established, by IP)"
    ss -tnH state established 2>/dev/null | awk '{print $4}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -25
    echo; echo "## DISTINCT PEERS ON LOCAL :443"
    ss -tnH state established 2>/dev/null | awk '$3 ~ /:443$/{print $4}' | sed 's/:[0-9]*$//' | sort -u | wc -l
    echo; echo "## CONNECTIONS PER STATE"
    ss -tanH 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn
    echo; echo "## CONNTRACK COUNT"; conntrack -C 2>/dev/null || cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo "n/a"
    echo; echo "## INTERFACE STATS (ip -s link)"; ip -s link 2>/dev/null
  } > "$d/02-connections-state.txt"

  # ---------- 03 firewall / addressing ----------
  {
    echo "## UFW STATUS VERBOSE"; ufw status verbose 2>/dev/null || echo "ufw n/a"
    echo; echo "## NFT RULESET"; nft list ruleset 2>/dev/null || echo "nft n/a"
    echo; echo "## IPTABLES -L -n -v"; iptables -L -n -v 2>/dev/null || echo "iptables n/a"
    echo; echo "## IP ADDR"; ip a 2>/dev/null
    echo; echo "## IP ROUTE"; ip route 2>/dev/null
    echo; echo "## IP NEIGH (ARP)"; ip neigh 2>/dev/null
  } > "$d/03-firewall.txt"

  # ---------- 04 CrowdSec (every cscli view we can get) ----------
  if have_cs; then
    cscli metrics            > "$d/04-crowdsec/metrics.txt"      2>&1 || true
    cscli decisions list     > "$d/04-crowdsec/decisions.txt"    2>&1 || true
    cscli alerts list        > "$d/04-crowdsec/alerts.txt"       2>&1 || true
    cscli bouncers list      > "$d/04-crowdsec/bouncers.txt"     2>&1 || true
    cscli machines list      > "$d/04-crowdsec/machines.txt"     2>&1 || true
    cscli collections list   > "$d/04-crowdsec/collections.txt"  2>&1 || true
    cscli parsers list       > "$d/04-crowdsec/parsers.txt"      2>&1 || true
    cscli scenarios list     > "$d/04-crowdsec/scenarios.txt"    2>&1 || true
    cscli postoverflows list > "$d/04-crowdsec/postoverflows.txt" 2>&1 || true
    cscli hub list           > "$d/04-crowdsec/hub.txt"          2>&1 || true
    cscli capi status        > "$d/04-crowdsec/capi-status.txt"  2>&1 || true
    cscli console status     > "$d/04-crowdsec/console-status.txt" 2>&1 || true
    cscli lapi status        > "$d/04-crowdsec/lapi-status.txt"  2>&1 || true
  else
    echo "CrowdSec / cscli not installed on this host." > "$d/04-crowdsec/_absent.txt"
  fi
  fx_grab /var/log/crowdsec.log "$d/04-crowdsec/crowdsec.log"
  journalctl -u crowdsec -n 2000 --no-pager > "$d/04-crowdsec/crowdsec-journal.txt" 2>/dev/null || true
  journalctl -u crowdsec-firewall-bouncer -n 1000 --no-pager > "$d/04-crowdsec/bouncer-journal.txt" 2>/dev/null || true
  [[ -f "$ACQUIS_FILE" ]] && cp --preserve=timestamps "$ACQUIS_FILE" "$d/04-crowdsec/acquis-suricata.yaml" 2>/dev/null || true

  # ---------- 05 Suricata ----------
  for f in suricata.log fast.log stats.log; do fx_grab "/var/log/suricata/$f" "$d/05-suricata/$f"; done
  if [[ -f /var/log/suricata/eve.json ]]; then
    tail -n 10000 /var/log/suricata/eve.json > "$d/05-suricata/eve-tail.json" 2>/dev/null || true
    if [[ "$(stat -c%s "$d/05-suricata/eve-tail.json" 2>/dev/null || echo 0)" -gt 52428800 ]]; then
      tail -c 52428800 "$d/05-suricata/eve-tail.json" > "$d/05-suricata/eve-tail.json.cap" 2>/dev/null && mv -f "$d/05-suricata/eve-tail.json.cap" "$d/05-suricata/eve-tail.json"
    fi
    jq -c 'select(.event_type=="alert")' "$d/05-suricata/eve-tail.json" > "$d/05-suricata/eve-alerts.json" 2>/dev/null || true
    jq -r '.event_type' "$d/05-suricata/eve-tail.json" 2>/dev/null | sort | uniq -c | sort -rn > "$d/05-suricata/eve-eventtype-summary.txt" || true
  fi
  journalctl -u suricata -n 1000 --no-pager > "$d/05-suricata/suricata-journal.txt" 2>/dev/null || true

  # ---------- 06 ClamAV ----------
  fx_grab "$CLAMAV_LOG" "$d/06-clamav/custom_suite.log"
  fx_grab /var/log/clamav/freshclam.log "$d/06-clamav/freshclam.log"
  for lf in $(ls -1t /var/log/clamav/scan_*.log 2>/dev/null | head -5); do cp --preserve=timestamps "$lf" "$d/06-clamav/" 2>/dev/null || true; done
  [[ -f "$CLAM_MANIFEST" ]] && cp --preserve=timestamps "$CLAM_MANIFEST" "$d/06-clamav/quarantine-manifest.tsv" 2>/dev/null || true
  {
    echo "## CLAMSCAN VERSION"; clamscan --version 2>/dev/null || echo "ClamAV not installed"
    echo; echo "## SIGNATURE DB INFO"; sigtool --info /var/lib/clamav/daily.c?d 2>/dev/null | head -20 || echo "n/a"
    echo; echo "## SERVICE STATE"
    for svc in clamav-freshclam clamav-daemon clamav-clamonacc; do echo "  $svc : active=$(systemctl is-active $svc 2>/dev/null) enabled=$(systemctl is-enabled $svc 2>/dev/null)"; done
    echo; echo "## QUARANTINE VAULT ($CLAM_QUAR)"; ls -la "$CLAM_QUAR" 2>/dev/null || echo "empty / absent"
  } > "$d/06-clamav/clamav-status.txt"

  # ---------- 07 x-ui / Xray (journals + every app log we can find) ----------
  journalctl -u x-ui -n 2000 --no-pager > "$d/07-xui-xray/x-ui-journal.txt" 2>/dev/null || true
  journalctl -u xray  -n 2000 --no-pager > "$d/07-xui-xray/xray-journal.txt" 2>/dev/null || true
  for b in /usr/local/x-ui /etc/x-ui /var/log/x-ui /opt/3x-ui /usr/local/etc/xray /etc/xray /var/log/xray; do
    [[ -d "$b" ]] || continue
    while IFS= read -r lf; do
      cp --preserve=timestamps "$lf" "$d/07-xui-xray/$(echo "${lf#/}" | tr '/' '_')" 2>/dev/null || true
    done < <(find "$b" -maxdepth 3 -type f \( -name '*.log' -o -name 'access.log' -o -name 'error.log' \) -size -20M 2>/dev/null)
  done
  {
    echo "## X-UI / XRAY LISTENERS"; ss -tlnpu 2>/dev/null | grep -Ei 'x-ui|xray' || echo "no x-ui/xray-named listeners visible"
    echo; echo "## CONFIG / DB PRESENT (not copied — may hold secrets)"
    for f in /usr/local/x-ui/x-ui.db /opt/3x-ui/x-ui.db /usr/local/etc/xray/config.json /etc/xray/config.json; do
      [[ -e "$f" ]] && echo "  $f  ($(stat -c '%s bytes, mtime %y' "$f" 2>/dev/null))"
    done
    echo; echo "## SERVICE STATE"
    for svc in x-ui xray; do echo "  $svc : active=$(systemctl is-active $svc 2>/dev/null) enabled=$(systemctl is-enabled $svc 2>/dev/null)"; done
  } > "$d/07-xui-xray/listeners-and-config.txt"

  # ---------- 08 system logs ----------
  fx_grab /var/log/auth.log "$d/08-system-logs/auth.log" 6000 || true
  [[ -f /var/log/auth.log ]] || fx_grab /var/log/secure "$d/08-system-logs/secure" 6000
  fx_grab /var/log/syslog   "$d/08-system-logs/syslog" 6000 || true
  [[ -f /var/log/syslog ]]   || fx_grab /var/log/messages "$d/08-system-logs/messages" 6000
  journalctl -p 0..4 --since "2 days ago" --no-pager > "$d/08-system-logs/journal-priority-errors-48h.txt" 2>/dev/null || true
  systemctl --failed --no-pager > "$d/08-system-logs/failed-units.txt" 2>/dev/null || true
  journalctl -b -p warning --no-pager > "$d/08-system-logs/journal-thisboot-warn.txt" 2>/dev/null || true

  # ---------- 09 kernel ----------
  dmesg > "$d/09-kernel/dmesg.txt" 2>/dev/null || echo "dmesg restricted (kernel.dmesg_restrict=1)" > "$d/09-kernel/dmesg.txt"
  journalctl -k -n 2000 --no-pager > "$d/09-kernel/journal-kernel.txt" 2>/dev/null || true
  lsmod > "$d/09-kernel/lsmod.txt" 2>/dev/null || true
  {
    for k in kernel.dmesg_restrict kernel.kptr_restrict kernel.yama.ptrace_scope \
             net.ipv4.ip_forward net.ipv4.tcp_syncookies net.ipv4.conf.all.rp_filter \
             net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.send_redirects \
             net.ipv4.conf.all.accept_source_route kernel.unprivileged_bpf_disabled \
             net.ipv4.tcp_congestion_control net.core.default_qdisc; do
      echo "$k = $(sysctl -n "$k" 2>/dev/null)"
    done
  } > "$d/09-kernel/security-sysctls.txt"
  cat /proc/sys/kernel/tainted > "$d/09-kernel/kernel-tainted.txt" 2>/dev/null || true

  # ---------- 10 processes / sessions ----------
  ps auxf > "$d/10-processes/ps-auxf.txt" 2>/dev/null || ps aux > "$d/10-processes/ps-auxf.txt" 2>/dev/null || true
  ps aux --sort=-%cpu 2>/dev/null | head -n 30 > "$d/10-processes/top-cpu.txt" || true
  ps aux --sort=-%mem 2>/dev/null | head -n 30 > "$d/10-processes/top-mem.txt" || true
  top -b -n1 2>/dev/null | head -n 40 > "$d/10-processes/top-snapshot.txt" || true
  systemctl list-units --type=service --state=running --no-pager > "$d/10-processes/running-services.txt" 2>/dev/null || true
  ss -tlnpu > "$d/10-processes/listeners-by-pid.txt" 2>/dev/null || true
}

# Build the folder, archive it, and tell the user how to pull + use it.
forensic_bundle(){
  local ts dir tarball sz
  ts="$(date +%Y%m%d_%H%M%S)"
  dir="${FORENSIC_DIR}/forensic-logs"
  tarball="${FORENSIC_DIR}/forensic-logs_${ts}.tar.gz"
  rm -rf "$dir" 2>/dev/null; mkdir -p "$dir"
  infobox "Forensic Bundle" "Gathering CrowdSec, Suricata, ClamAV, x-ui/Xray, system, kernel,\nnetwork-state and process logs into one folder for AI analysis...\n\nThis can take a moment on a busy host."
  run_forensic_collection "$dir"
  tar -czf "$tarball" -C "$FORENSIC_DIR" forensic-logs 2>>"$LOG" || true
  log "forensic bundle created: $tarball"
  sz="$(du -sh "$tarball" 2>/dev/null | awk '{print $1}')"
  msg "Forensic Bundle Ready" "All logs collected into one folder and archived.\n\n📁 Folder : ${dir}/\n📦 Archive: ${tarball}  (${sz:-?})\n\nPull it to your workstation:\n  scp -P ${SSH_PORT:-22} <user>@<server-ip>:${tarball} .\n\nUnpack, then hand the files (or the .tar.gz) to an AI.\n00-README.txt inside has a ready-made analysis prompt." 20 96
}

forensics_menu(){
  local c f_tmp="$IS_TMP/forensics_view"
  while :; do
    c=$(menu "⚡ ADVANCED FORENSICS ENGINE ⚡" "Analyze structural vector patterns, track listeners, or bundle log states for AI parsing:" \
      P "📁 View Active Open Ports & Interface Daemons" \
      C "🔗 Trace Active Traffic Streams & Socket Telemetry" \
      T "📡 Sniff Inbound Network Activity (Live 15s Capture Window)" \
      A "🔒 Extract Host Security Authentication Failure Footprints" \
      E "🤖 Build Full Forensic-Logs Bundle (all logs → one folder, for AI)" \
      b "Return to Main Context")
    case "$?" in
      1|255) break ;;
    esac
    case "$c" in
      P) { echo -e "⚡ ACTIVE INTERFACE SOCKETS & DAEMON PATHWAYS ⚡\n"; ss -tlnpu; } > "$f_tmp"
         showfile "Forensics: Active Interface Listeners" "$f_tmp" ;;
      C) { echo -e "⚡ TRACING LOGICAL ESTABLISHED STREAM ARRAYS ⚡\n"; ss -toea | sed 's/ users:(/\n\tMapped Consumers: (/g'; } > "$f_tmp"
         showfile "Forensics: Active Network Streams" "$f_tmp" ;;
      T) if ! command -v tcpdump >/dev/null 2>&1; then
           if yesno "Network Capture Pipeline" "tcpdump is not installed.\n\nInstall it now (apt-get install tcpdump)?"; then run apt-get install -y tcpdump; fi
         fi
         if ! command -v tcpdump >/dev/null 2>&1; then
           msg "Network Capture Pipeline" "tcpdump unavailable — cannot capture. See $LOG."
         else
           infobox "Network Capture Pipeline" "Analyzing structural tracking frames over interface network link array [$NIC] for 15 seconds...\nYour SSH session (port $SSH_PORT) is excluded."
           { echo -e "⚡ REALTIME TRANSIT CAPTURE SNIPPET (15s Window) ⚡"; echo -e "Interface: ${NIC}   Filter: not port ${SSH_PORT} (admin session excluded)\n"; timeout 15 tcpdump -c 100 -nnvvv -i "$NIC" "not port ${SSH_PORT}" </dev/null 2>&1; } > "$f_tmp"
           showfile "Forensics: Ingest Sniffer" "$f_tmp"
         fi ;;
      A) { echo -e "⚡ THREAT ATTACK ENTROPY AUTHENTICATION FAILURES ⚡\n"
           if [[ -f /var/log/auth.log ]]; then grep -E "Failed|Invalid" /var/log/auth.log | tail -n 60
           else journalctl _SYSTEMD_UNIT=ssh.service + _SYSTEMD_UNIT=sshd.service --no-pager -n 60 | grep -E "Failed|Invalid"; fi
         } > "$f_tmp"
         showfile "Forensics: Authentication Failure Trails" "$f_tmp" ;;
      E) forensic_bundle ;;
      b) break ;;
    esac
  done
}


#==============================================================================
#  MODULE 4: PERFORMANCE TUNING ENGINE
#==============================================================================
get_cpu_governor_status() {
  if [[ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
  elif [[ -f /sys/devices/system/cpu/cpufreq/policy0/scaling_governor ]]; then
    cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor
  else
    echo "Virtualized/Static"
  fi
}

set_cpu_governor() {
  local gov="$1" cpu ok=1
  if compgen -G "/sys/devices/system/cpu/cpufreq/policy*/scaling_governor" >/dev/null 2>&1; then
    for cpu in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
      [[ -w "$cpu" ]] && echo "$gov" > "$cpu" 2>/dev/null && ok=0
    done
  elif [[ -w /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]]; then
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      [[ -w "$cpu" ]] && echo "$gov" > "$cpu" 2>/dev/null && ok=0
    done
  fi
  return $ok
}

# echo the first available "balanced-ish" governor (empty if cpufreq not exposed)
pick_balanced_governor(){
  local f avail g
  for f in /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors \
           /sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors; do
    [[ -r "$f" ]] && { avail=" $(cat "$f" 2>/dev/null) "; break; }
  done
  [[ -z "$avail" ]] && return 0
  for g in schedutil ondemand conservative powersave; do
    [[ "$avail" == *" $g "* ]] && { echo "$g"; return 0; }
  done
}

# persist a governor across reboot via a tiny systemd oneshot (only if governors exist)
persist_governor(){
  local gov="$1"
  [[ -z "$gov" ]] && return 0
  [[ -e /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor || -e /sys/devices/system/cpu/cpufreq/policy0/scaling_governor ]] || return 0
  cat >/etc/systemd/system/intelshield-cpu.service <<EOF
[Unit]
Description=intelshield CPU governor ($gov)
After=multi-user.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do [ -w "\$g" ] && echo $gov > "\$g"; done'
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >>"$LOG" 2>&1
  systemctl enable intelshield-cpu >>"$LOG" 2>&1
}

apply_performance_profile() {
  local mode="$1" gov epp epp_val
  if [[ "$mode" == "high" ]]; then
    gov="performance"; epp_val="performance"
    set_cpu_governor "$gov"
    for epp in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do
      [[ -w "$epp" ]] && echo "$epp_val" > "$epp" 2>/dev/null
    done
    cat > "$PERF_SYSCTL" << 'EOF'
# IntelShield ultra low-latency compute optimizations
vm.swappiness = 10
vm.dirty_background_ratio = 3
vm.dirty_ratio = 5
net.core.netdev_max_backlog = 32768
fs.file-max = 2097152
EOF
  else
    gov="$(pick_balanced_governor)"; epp_val="balance_performance"
    [[ -n "$gov" ]] && set_cpu_governor "$gov"
    for epp in /sys/devices/system/cpu/cpu*/cpufreq/energy_performance_preference; do
      [[ -w "$epp" ]] && echo "$epp_val" > "$epp" 2>/dev/null
    done
    cat > "$PERF_SYSCTL" << 'EOF'
# IntelShield balanced virtualization footprint profile
vm.swappiness = 30
vm.dirty_background_ratio = 10
vm.dirty_ratio = 20
net.core.netdev_max_backlog = 4096
EOF
  fi
  sysctl --system >>"$LOG" 2>&1
  persist_governor "$gov"
}

performance_menu(){
  local c cg cc sw
  while :; do
    cg=$(get_cpu_governor_status)
    cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
    sw=$(sysctl -n vm.swappiness 2>/dev/null)
    c=$(menu "🚀 KERNEL OPTIMIZATION ENGINE" "Governor: $cg   Congestion Module: $cc   Swap Weight: $sw" \
      H "⚡ Activate Low-Latency High-Performance Compute Profile" \
      B "⚖️  Activate Standard Balanced Virtualization Profile" \
      I "📊 View Operational Real-Time Resource Jitter Dashboards" \
      b "Return to Main Context")
    case "$?" in
      1|255) break ;;
    esac
    case "$c" in
      H) apply_performance_profile "high"
         msg "Performance Mode Active" "Subsystem variables modified successfully:\n- Dynamic scaling governors locked to MAX efficiency profiles\n- Network backlog widened + memory cache sync tuned for latency\n- Profile persisted across reboot where CPU scaling is exposed." ;;
      B) apply_performance_profile "balanced"
         msg "Balanced Mode Active" "Subsystem variables restored to standard resource profiles." ;;
      I) { echo "=========================================================================="
           echo "                 ACTIVE TUNING TRANSIT PROCESSING TELEMETRY               "
           echo "=========================================================================="
           echo -e "\n### MEMORY ALLOCATION STATE\n"; free -h
           echo -e "\n### IO INTERFACE SCHEDULING DYNAMICS\n"; vmstat 1 3
           echo -e "\n### SOCKET SUMMARY\n"; ss -s 2>/dev/null
           echo -e "\n### TCP RETRANSMIT / ERROR COUNTERS\n"
           if command -v nstat >/dev/null 2>&1; then
             nstat -az 2>/dev/null | grep -Ei "retrans|fail|drop|error|reset|backlog" | head -n 30 || echo "(no matching counters)"
           else
             awk '/Tcp:/{print}' /proc/net/snmp 2>/dev/null || echo "(counters unavailable)"
           fi
         } > "$IS_TMP/perf_dashboard"
         showfile " TUI Monitor Dashboard " "$IS_TMP/perf_dashboard" ;;
      b) break ;;
    esac
  done
}


#==============================================================================
#  MODULE REGISTRY + SCHEDULING
#==============================================================================
MODULES=(
  "backup|Config snapshot (tar backup, for rollback)|m_backup_system|ON"
  "baseline|System baseline (updates, auto-patch, time sync)|m_baseline|ON"
  "kernelnet|Kernel network + BBR tuning (perf + anti-spoof)|m_kernel_network|ON"
  "kernelsec|Kernel security sysctls (hardening)|m_kernel_security|ON"
  "cpu|CPU microcode + mitigations audit|m_cpu_microcode|ON"
  "platform|Secure Boot / TPM / disk audit|m_platform_security|ON"
  "ufw|UFW firewall (deny-in, allow SSH + 443 tcp/udp)|m_ufw|ON"
  "ssh|SSH hardening (keys, modern crypto, limits)|m_ssh|OFF"
  "crowdsec|CrowdSec engine (IPS brain)|m_crowdsec|ON"
  "allowlist|Admin allowlist (anti-lockout)|m_allowlist|ON"
  "bouncer|CrowdSec firewall bouncer (enforcement)|m_bouncer|ON"
  "suricata|Suricata IDS (sensor)|m_suricata|ON"
  "wiring|Suricata -> CrowdSec (IDS -> IPS loop)|m_wiring|ON"
  "clamav|ClamAV antivirus (install / reinstall)|m_clamav_install|OFF"
  "auditd|auditd rules (file + exec audit)|m_auditd|ON"
  "aide|AIDE baseline (file integrity)|m_aide|OFF"
  "apparmor|AppArmor (MAC profiles)|m_apparmor|OFF"
  "usg|USG CIS audit-only|m_usg_audit|OFF"
  "antirootkit|Anti-rootkit (rkhunter + chkrootkit)|m_ark_install|OFF"
  "sandbox|x-ui/Xray systemd sandbox (blast-radius limit)|m_sandbox|OFF"
  "console|CrowdSec console enroll (optional)|m_console|OFF"
  "panel|x-ui panel protection helper (optional)|m_panel|OFF"
  "health|Health-check timer|m_health_timer|ON"
)


run_module(){
  local key="$1" title="$2" fn="$3" rc
  COUNTER=$((COUNTER+1))
  infobox "Processing Task ($COUNTER/$TOTAL)" "Executing module pipeline operations:\n ➡️  $title"
  log "=== LOG SECTOR START [$key] ==="
  "$fn"; rc=$?
  case $rc in
    0) RESULT[$key]="[ SUCCESS ] $title" ;;
    3) RESULT[$key]="[ SKIPPED ] $title" ;;
    *) RESULT[$key]="[ FAULTED ] $title (Exit Code: $rc)" ;;
  esac
  log "=== LOG SECTOR END [$key] TERMINATED WITH RE: $rc ==="
}

summary(){
  local out="" tag
  for m in "${MODULES[@]}"; do
    tag="${m%%|*}"
    [[ -n "${RESULT[$tag]:-}" ]] && out+="${RESULT[$tag]}"$'\n'
  done
  [[ -z "$out" ]] && out="No operational tasks metrics tracked inside run instance environment logs."
  printf '%s\n' "$out" >"$IS_TMP/summary"
  showfile "Operational Pipeline Deployment Overview" "$IS_TMP/summary"
}

select_modules(){
  local CHK_ARGS=() tag desc fn state sel
  for m in "${MODULES[@]}"; do
    IFS='|' read -r tag desc fn state <<<"$m"
    CHK_ARGS+=("$tag" "$desc" "$state")
  done
  sel=$(whiptail --backtitle "$BT" --title "Custom Deployment Profiler" --checklist \
    "SPACEBAR = Select/Deselect Module   |   ENTER = Confirm Array Pipeline Launch Sequence" \
    22 96 12 "${CHK_ARGS[@]}" 3>&1 1>&2 2>&3) || return
  sel=${sel//\"/}
  [[ -z "$sel" ]] && return
  RESULT=(); COUNTER=0; TOTAL=$(wc -w <<<"$sel")
  for m in "${MODULES[@]}"; do
    IFS='|' read -r tag desc fn state <<<"$m"
    case " $sel " in *" $tag "*) run_module "$tag" "$desc" "$fn" ;; esac
  done
  summary
}


guided(){
  preflight_risk_engine
  local seq=(backup baseline kernelnet kernelsec cpu platform ufw crowdsec allowlist bouncer suricata wiring auditd health) tag desc fn state want
  RESULT=(); COUNTER=0; TOTAL=${#seq[@]}
  for want in "${seq[@]}"; do
    for m in "${MODULES[@]}"; do
      IFS='|' read -r tag desc fn state <<<"$m"
      [[ "$tag" == "$want" ]] && run_module "$tag" "$desc" "$fn"
    done
  done
  yesno "Optional Addon" "Apply key-based cryptographic constraints over the SSH interface?" && { TOTAL=$((TOTAL+1)); run_module ssh "SSH Hardening" m_ssh; }
  yesno "Optional Addon" "Affix systemd container isolation over the x-ui/Xray service?" && { TOTAL=$((TOTAL+1)); run_module sandbox "Systemd Isolation" m_sandbox; }
  summary
}


#==============================================================================
#  CROWDSEC ADVANCED SUITE CONTROLS (TUI NESTED RECURSIONS)
#==============================================================================
cs_show(){ local t="$1"; shift; { "$@"; } >"$IS_TMP/cs" 2>&1 || echo "Command exited non-zero — check service state / logs." >>"$IS_TMP/cs"; showfile "$t" "$IS_TMP/cs"; }

cs_service_menu(){
  local c
  while :; do
    c=$(menu "CrowdSec Orchestration Interface" "Daemon Engine: $(systemctl is-active crowdsec 2>/dev/null)  |  Bouncer Layer: $(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null)" \
      A "Actively Enable & Trigger Complete IPS Core Daemon Chains" \
      D "Deactivate, Unbind & Flush Operational Intelligence Units" \
      1 "Issue Structural Restart Tracking Order to Engine" \
      2 "Kill Engine Tracking Listeners Safely" \
      3 "Issue Structural Restart Tracking Order to Bouncer" \
      4 "Kill Network Dropping Bouncer Elements" \
      b "Return to Parent Management Tree")
    case "$?" in 1|255) break ;; esac
    case "$c" in
      A) run systemctl enable --now crowdsec crowdsec-firewall-bouncer; msg "Status Update" "IPS subsystems re-triggered." ;;
      D) yesno_danger "Confirm Purge" "Confirm total unbinding of protective filtering structures?" && { run systemctl disable --now crowdsec-firewall-bouncer crowdsec; msg "Alert" "Subsystems stopped."; } ;;
      1) run systemctl restart crowdsec ;;
      2) run systemctl stop crowdsec ;;
      3) run systemctl restart crowdsec-firewall-bouncer ;;
      4) run systemctl stop crowdsec-firewall-bouncer ;;
      b) break ;;
    esac
  done
}

cs_decisions_menu(){
  local c ip dur
  while :; do
    c=$(menu "Active IP Drops Management Console" "Current Tracked Filter Violations: $(cscli decisions list -o raw 2>/dev/null | grep -c .)" \
      l "List Live Network Ban Arrays" \
      a "Manually Quarantine Specific Address Vector" \
      u "Remove Target Isolation Constraints" \
      U "Flush All Operational Decisions (Emergency Override Lift)" \
      b "Return to Parent Management Tree")
    case "$?" in 1|255) break ;; esac
    case "$c" in
      l) cs_show "Active Mitigation Pool" cscli decisions list ;;
      a) ip=$(input "Block Vector" "Specify target host address pattern to drop:" "") || continue
         valid_ip "$ip" || { msg "Syntax Violation" "'$ip' is not a valid IPv4 address or CIDR."; continue; }
         dur=$(input "Block Lease" "Input structural ban duration scope (e.g. 24h, 168h):" "24h") || continue
         [[ "$dur" =~ ^[0-9]+[smhd]$ ]] || { msg "Syntax Violation" "Duration must look like 24h, 168h, 30m."; continue; }
         run cscli decisions add --ip "$ip" --duration "$dur" --reason "Manual structural override" ;;
      u) ip=$(input "Lift Vector" "Specify target host address pattern to unban:" "") || continue
         valid_ip "$ip" || { msg "Syntax Violation" "'$ip' is not a valid IPv4 address or CIDR."; continue; }
         run cscli decisions delete --ip "$ip" ;;
      U) yesno_danger "Emergency Global Unlock" "Purge every active filtering barrier across local tables?" && run cscli decisions delete --all ;;
      b) break ;;
    esac
  done
}

cs_diag_menu(){
  local c ip
  while :; do
    c=$(menu "IPS Intelligence Logs Discovery Panel" "Diagnostics Interface" \
      i "Deep-Inspect Target Address History & Logs Signature Profiles" \
      a "Stream Recent Alert Events Signatures Map" \
      m "Review Parsing Efficiency Metrics Matrix" \
      L "Tail Primary Engine Event Sequences Logs" \
      b "Return to Parent Management Tree")
    case "$?" in 1|255) break ;; esac
    case "$c" in
      i) ip=$(input "Host Auditing" "Specify target address pattern to trace:" "") || continue
         valid_ip "$ip" || { msg "Syntax Violation" "'$ip' is not a valid IPv4 address or CIDR."; continue; }
         # pass $ip as a positional arg, never interpolate it into the command string
         cs_show "Audit Trail: $ip" bash -c 'cscli decisions list --ip "$1"; echo; cscli alerts list --ip "$1"' _ "$ip" ;;
      a) cs_show "Active Alerts" cscli alerts list ;;
      m) cs_show "Engine Processing Metrics" cscli metrics ;;
      L) cs_show "Live Engine Sequences Log Stream" bash -c "journalctl -u crowdsec -n 150 --no-pager 2>/dev/null || tail -n 150 /var/log/crowdsec.log" ;;
      b) break ;;
    esac
  done
}

crowdsec_menu(){
  need_cs || return
  local c
  while :; do
    c=$(menu "CrowdSec Framework Orchestrator" "Intelligence Core Subsystem Status Control Routing" \
      S "Daemon Infrastructure Service Level Adjustments" \
      D "Quarantine Ledger Operational Decision Overrides" \
      G "Structural Signal Logging Diagnostics Dashboard" \
      X "EMERGENCY FALLBACK: Drop Filters & Flush Active Block Tables" \
      q "Return to Main Context")
    case "$?" in
      1|255) break ;;
    esac
    case "$c" in
      S) cs_service_menu ;;
      D) cs_decisions_menu ;;
      G) cs_diag_menu ;;
      X) run systemctl stop crowdsec-firewall-bouncer; cscli decisions delete --all; msg "Panic Triggered" "All blocks dropped." ;;
      q) break ;;
    esac
  done
}


#==============================================================================
#  UFW FIREWALL MANAGEMENT  (allow / block / custom rules by port, IP or range)
#==============================================================================
ufw_present(){ command -v ufw >/dev/null 2>&1; }
ufw_ensure(){
  ufw_present && return 0
  yesno "UFW Firewall" "UFW is not installed.\n\nInstall it now (apt-get install ufw)?" && run apt-get install -y ufw
  ufw_present
}
ufw_active(){ ufw status 2>/dev/null | grep -q "Status: active"; }

ufw_status_view(){
  { echo "⚡ UFW FIREWALL STATE ⚡"; echo
    echo "=== verbose ==="; ufw status verbose 2>/dev/null
    echo; echo "=== numbered (use these numbers to delete) ==="; ufw status numbered 2>/dev/null
  } >"$IS_TMP/ufw"
  showfile "UFW: Current Firewall State" "$IS_TMP/ufw"
}

# Guided add of an allow/deny rule. $1 = allow | deny
ufw_add_rule(){
  local action="$1" kind port proto src desc
  kind=$(menu "UFW ${action^^} rule" "What should this ${action^^} rule match?" \
    P "A PORT  (optionally restricted to one source IP / range)" \
    S "A SOURCE IP / RANGE  (all ports, or one port)") || return
  if [[ "$kind" == "P" ]]; then
    port=$(input "UFW ${action^^} rule" "Port or range to ${action} (e.g. 443  or  8000:8100):" "") || return
    [[ -z "$port" ]] && return
    valid_port "$port" || { msg "Invalid Port" "'$port' is not a valid port or range."; return; }
    proto=$(menu "Protocol" "Protocol for port ${port}:" \
      tcp "TCP only" udp "UDP only" both "TCP + UDP") || return
    src=$(input "Source (optional)" "Restrict to a source IP or CIDR.\nLeave BLANK to apply from anywhere:" "") || return
    [[ -n "$src" ]] && { valid_ip "$src" || { msg "Invalid Source" "'$src' is not a valid IP or CIDR."; return; }; }
    # NOTE: ufw REQUIRES a protocol for a port RANGE (e.g. 8000:8100/tcp). The old
    # code ran `ufw allow 8000:8100` which ufw rejects, so the rule silently failed.
    if [[ -z "$src" ]]; then
      if [[ "$proto" == "both" ]]; then
        run ufw "$action" "${port}/tcp"; run ufw "$action" "${port}/udp"; desc="ufw $action ${port} tcp+udp (from anywhere)"
      else run ufw "$action" "${port}/${proto}"; desc="ufw $action ${port}/${proto} (from anywhere)"; fi
    else
      if [[ "$proto" == "both" ]]; then
        run ufw "$action" from "$src" to any port "$port" proto tcp; run ufw "$action" from "$src" to any port "$port" proto udp; desc="ufw $action from $src to any port $port tcp+udp"
      else run ufw "$action" from "$src" to any port "$port" proto "$proto"; desc="ufw $action from $src to any port $port proto $proto"; fi
    fi
  else
    src=$(input "UFW ${action^^} rule" "Source IP or CIDR to ${action} (e.g. 203.0.113.5  or  203.0.113.0/24):" "") || return
    [[ -z "$src" ]] && return
    valid_ip "$src" || { msg "Invalid Source" "'$src' is not a valid IP or CIDR."; return; }
    port=$(input "Destination port (optional)" "Limit this rule to ONE destination port.\nLeave BLANK for all ports from this source:" "") || return
    if [[ -n "$port" ]]; then
      valid_port "$port" || { msg "Invalid Port" "'$port' is not a valid port or range."; return; }
      if [[ "$port" == *:* ]]; then   # a range needs a protocol → apply both
        run ufw "$action" from "$src" to any port "$port" proto tcp; run ufw "$action" from "$src" to any port "$port" proto udp; desc="ufw $action from $src to any port $port tcp+udp"
      else run ufw "$action" from "$src" to any port "$port"; desc="ufw $action from $src to any port $port"; fi
    else
      run ufw "$action" from "$src"; desc="ufw $action from $src (all ports)"
    fi
  fi
  local note=""; ufw_active || note="\n\nNOTE: UFW is currently INACTIVE — this rule is saved and will take effect when you enable the firewall."
  msg "Rule Applied" "Executed:\n  $desc${note}\n\nUse 'Show status' to verify or 'Delete a rule' to remove it."
}

# Delete a rule via a pick-list built from `ufw status numbered`
ufw_delete_rule(){
  local raw=() args=() l n d choice
  mapfile -t raw < <(ufw status numbered 2>/dev/null | grep -E '^\[')
  [[ ${#raw[@]} -eq 0 ]] && { msg "Delete Rule" "No numbered rules found (UFW may be inactive or have no rules)."; return; }
  for l in "${raw[@]}"; do
    n="$(sed -E 's/^\[ *([0-9]+)\].*/\1/' <<<"$l")"
    d="$(sed -E 's/^\[ *[0-9]+\] *//' <<<"$l")"
    args+=("$n" "$d")
  done
  choice=$(menu "Delete UFW Rule" "Select the rule number to DELETE:" "${args[@]}") || return
  [[ -z "$choice" ]] && return
  yesno "Confirm Delete" "Delete this rule?\n\n$(printf '%s\n' "${raw[@]}" | grep -E "^\[ *$choice\]")" || return
  yes | ufw delete "$choice" >>"$LOG" 2>&1
  msg "Rule Deleted" "Rule #$choice removed.\n\nRemaining rule numbers shift after a delete — reopen the list for fresh numbers."
}

ufw_defaults(){
  local inc out
  inc=$(menu "Default INCOMING policy" "Action for inbound traffic not matched by any rule:" \
    deny "deny  (recommended)" reject "reject" allow "allow  (NOT recommended)") || return
  out=$(menu "Default OUTGOING policy" "Action for outbound traffic:" \
    allow "allow  (recommended)" deny "deny") || return
  run ufw default "$inc" incoming
  run ufw default "$out" outgoing
  msg "Defaults Set" "Default incoming: $inc\nDefault outgoing: $out"
}

ufw_logging(){
  local lvl
  lvl=$(menu "UFW Logging" "Firewall logging level:" \
    on "on (default)" off "off" low "low" medium "medium" high "high") || return
  run ufw logging "$lvl"
  msg "Logging Set" "UFW logging level set to: $lvl"
}

ufw_toggle(){
  if ufw_active; then
    yesno_danger "Disable UFW" "UFW is ACTIVE.\n\nDisable the firewall entirely? Inbound filtering stops until re-enabled." \
      && { run ufw disable; msg "UFW Disabled" "Firewall is now inactive."; }
  else
    run ufw limit "${SSH_PORT}"/tcp
    run ufw allow "${SSH_PORT}"/tcp
    run ufw allow 443/tcp
    run ufw allow 443/udp
    run ufw --force enable
    msg "UFW Enabled" "Firewall is ACTIVE.\n\nAnti-lockout safety: SSH/${SSH_PORT} (rate-limited), 443/tcp and 443/udp were allowed before enabling."
  fi
}

ufw_reset(){
  yesno_danger "Reset UFW" "This WIPES all UFW rules and resets defaults.\n\nFor safety, SSH (${SSH_PORT}) and 443 are re-allowed and the firewall re-enabled afterward.\n\nProceed?" || return
  yes | ufw reset >>"$LOG" 2>&1
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw limit "${SSH_PORT}"/tcp
  run ufw allow "${SSH_PORT}"/tcp
  run ufw allow 443/tcp
  run ufw allow 443/udp
  run ufw --force enable
  msg "UFW Reset" "Firewall rebuilt to a safe baseline:\n- default deny incoming / allow outgoing\n- allowed: SSH/${SSH_PORT}, 443/tcp, 443/udp\n- firewall re-enabled"
}

ufw_menu(){
  ufw_ensure || { msg "UFW Firewall" "UFW is not available on this host."; return; }
  local c st
  while :; do
    st="INACTIVE"; ufw_active && st="ACTIVE"
    c=$(menu "🔥 UFW FIREWALL MANAGEMENT" "Firewall: ${st}   SSH:${SSH_PORT}   (rules apply immediately while active)" \
      S "📊 Show full status (verbose + numbered)" \
      A "✅ Add ALLOW rule  (open a port / source)" \
      D "⛔ Add DENY / BLOCK rule  (block a port / source)" \
      X "🗑️  Delete a rule  (pick from a list)" \
      P "⚙️  Set default policies (in / out)" \
      G "📝 Set logging level" \
      T "🔁 Toggle firewall ON / OFF" \
      R "♻️  Reset firewall (safe re-baseline)" \
      b "Return to Main Context")
    case "$?" in 1|255) break ;; esac
    case "$c" in
      S) ufw_status_view ;;
      A) ufw_add_rule allow ;;
      D) ufw_add_rule deny ;;
      X) ufw_delete_rule ;;
      P) ufw_defaults ;;
      G) ufw_logging ;;
      T) ufw_toggle ;;
      R) ufw_reset ;;
      b) break ;;
    esac
  done
}


#==============================================================================
#  MODULE 5: CLAMAV ANTIVIRUS MANAGEMENT SUITE
#==============================================================================
clamlog(){ mkdir -p "$(dirname "$CLAMAV_LOG")" 2>/dev/null; printf '[%s UTC] %s\n' "$(date -u '+%F %T')" "$*" >>"$CLAMAV_LOG" 2>/dev/null; log "clamav: $*"; }

# spec: detect APT / YUM / DNF / Pacman  (routed through run() so it streams live)
pkg_install(){
  if   command -v apt-get >/dev/null 2>&1; then run apt-get update -y; run apt-get install -y "$@"
  elif command -v dnf     >/dev/null 2>&1; then run dnf install -y "$@"
  elif command -v yum     >/dev/null 2>&1; then run yum install -y "$@"
  elif command -v pacman  >/dev/null 2>&1; then run pacman -Sy --noconfirm "$@"
  else return 1; fi
}

clam_present(){ command -v clamscan >/dev/null 2>&1; }

clam_ensure(){
  clam_present && return 0
  infobox "ClamAV Engine" "Installing ClamAV engine, daemon and signature updater..."
  if   command -v apt-get >/dev/null 2>&1; then pkg_install clamav clamav-daemon clamav-freshclam
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then pkg_install clamav clamav-update clamd
  elif command -v pacman >/dev/null 2>&1; then pkg_install clamav
  fi
  # initial signature sync — freshclam daemon locks the db/log, so stop it first
  systemctl stop clamav-freshclam >/dev/null 2>&1
  run freshclam || true
  systemctl enable --now clamav-freshclam >/dev/null 2>&1
  # NOTE: clamav-daemon (on-access) intentionally NOT auto-enabled — clamscan
  # works standalone, and a resident clamd costs ~1GB RAM on a relay.
  clam_present
}

# Registry module: install ClamAV, or FULL reinstall if already present, then verify.
# Returns 0 = verified OK, 3 = user declined reinstall, non-zero = failure.
m_clamav_install(){
  local reinstall=0 probs="" ver dbv
  if clam_present; then
    yesno "ClamAV Full Reinstall" "ClamAV is already installed.\n\nDo a FULL reinstall? This purges the ClamAV packages and their config, then installs fresh.\n\n(Your quarantine vault at ${CLAM_QUAR} is preserved.)" || return 3
    reinstall=1
  fi

  if [[ $reinstall -eq 1 ]]; then
    infobox "ClamAV Reinstall" "Stopping services and purging existing ClamAV packages + config..."
    run systemctl stop clamav-freshclam
    run systemctl stop clamav-daemon
    run systemctl stop clamav-clamonacc
    if   command -v apt-get >/dev/null 2>&1; then apt-get purge -y 'clamav*' >>"$LOG" 2>&1; apt-get autoremove -y >>"$LOG" 2>&1
    elif command -v dnf     >/dev/null 2>&1; then dnf remove -y 'clamav*' >>"$LOG" 2>&1
    elif command -v yum     >/dev/null 2>&1; then yum remove -y 'clamav*' >>"$LOG" 2>&1
    elif command -v pacman  >/dev/null 2>&1; then pacman -Rns --noconfirm clamav >>"$LOG" 2>&1
    fi
    rm -rf /etc/clamav /var/lib/clamav 2>/dev/null   # leftover config/db (vault kept)
    clamlog "purged ClamAV for full reinstall"
  fi

  infobox "ClamAV Install" "Installing ClamAV engine, daemon and freshclam updater..."
  if   command -v apt-get >/dev/null 2>&1; then pkg_install clamav clamav-daemon clamav-freshclam
  elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then pkg_install clamav clamav-update clamd
  elif command -v pacman >/dev/null 2>&1; then pkg_install clamav
  else msg "ClamAV" "No supported package manager (apt/dnf/yum/pacman) detected."; return 1; fi

  infobox "ClamAV Signatures" "Synchronising the virus signature database — the first sync can take a minute..."
  run systemctl stop clamav-freshclam          # daemon locks the db/log during manual run
  run freshclam || true
  run systemctl enable --now clamav-freshclam
  install -d -m 700 "$CLAM_QUAR" 2>/dev/null

  # ---- verify a proper install ----
  clam_present || probs+="• clamscan binary missing\n"
  command -v freshclam >/dev/null 2>&1 || probs+="• freshclam binary missing\n"
  ls /var/lib/clamav/*.c?d >/dev/null 2>&1 || probs+="• signature database not present\n"
  systemctl is-active --quiet clamav-freshclam 2>/dev/null || probs+="• clamav-freshclam service not active\n"
  if [[ -n "$probs" ]]; then
    clamlog "install verification FAILED:\n$probs"
    msg "ClamAV Install — Issues" "Installation finished with problems:\n\n${probs}\nSee $LOG for details."
    return 1
  fi

  ver="$(clamscan --version 2>/dev/null)"
  dbv="$(sigtool --info /var/lib/clamav/daily.c?d 2>/dev/null | grep -m1 -iE 'version|build')"
  clamlog "ClamAV installed & verified: $ver"
  msg "ClamAV Ready ✅" "ClamAV installed and verified.\n\nEngine : ${ver}\n${dbv}\n\nReal-time stays OFF by default (clamscan runs standalone; scheduled scans cover you). Manage scans, quarantine and scheduling from the main menu → ClamAV Antivirus Management.\nQuarantine vault: ${CLAM_QUAR}"
  return 0
}

clam_conf_get(){ local key="$1" f="${2:-$CLAMD_CONF}"; grep -E "^${key}\b" "$f" 2>/dev/null | awk '{print $2}' | head -1; }
clam_conf_set(){
  local key="$1" val="$2" f="${3:-$CLAMD_CONF}"
  [[ -f "$f" ]] || return 1
  if grep -qE "^[#[:space:]]*${key}\b" "$f"; then sed -i -E "s|^[#[:space:]]*${key}\b.*|${key} ${val}|" "$f"
  else echo "${key} ${val}" >>"$f"; fi
}
clam_reload_daemon(){ systemctl is-active --quiet clamav-daemon 2>/dev/null && { run systemctl reload clamav-daemon || run systemctl restart clamav-daemon; }; }

# spec: alerting hook (placeholder — wire mail/webhook here)
clam_alert_hook(){
  local n="$1" what="${2:-scan}"
  clamlog "ALERT: ${n} infected file(s) during ${what} on $(hostname) (notify-hook placeholder)"
  # Example wiring (left disabled by design):
  #   command -v mail >/dev/null 2>&1 && echo "IntelShield: $n infected ($what) on $(hostname)" | mail -s "ClamAV ALERT" root
  #   [[ -n "${CLAM_WEBHOOK:-}" ]] && curl -fsS -X POST -d "host=$(hostname)&infected=$n&scan=$what" "$CLAM_WEBHOOK" >/dev/null 2>&1
  return 0
}

# Core engine: scan -> parse FOUND -> quarantine(+manifest) -> log -> alert.
# No TUI here, so it is reusable by the headless scheduler hook.
# $1 mode(quarantine|report)  $2 label  $3.. paths
clam_core_scan(){
  clam_present || { clamlog "engine missing — scan aborted"; return 1; }
  local mode="$1" label="$2"; shift 2
  install -d -m 700 "$CLAM_QUAR" 2>/dev/null; mkdir -p /var/log/clamav 2>/dev/null
  local p real=() ts scanlog
  for p in "$@"; do [[ -e "$p" ]] && real+=("$p"); done
  [[ ${#real[@]} -eq 0 ]] && { clamlog "$label scan: no valid paths"; return 1; }
  ts=$(date +%Y%m%d_%H%M%S); scanlog="/var/log/clamav/scan_${ts}.log"
  nice -n 19 ionice -c 3 clamscan -r -i --no-summary \
    --max-filesize="$CLAM_MAXSIZE" --max-scansize="$CLAM_MAXSIZE" \
    --exclude-dir="$CLAM_EXCLUDE" "${real[@]}" >"$scanlog" 2>>"$LOG"
  local infected=0 quarantined=0 reported=0 line path sig qf fmeta
  while IFS= read -r line; do
    [[ "$line" == *" FOUND" ]] || continue
    infected=$((infected+1))
    path="$(sed 's/: [^:]* FOUND$//' <<<"$line")"
    sig="$(sed -E 's/.*: ([^:]*) FOUND$/\1/' <<<"$line")"
    if [[ "$mode" == "quarantine" && ! "$path" =~ $CLAM_PROTECT ]]; then
      qf="${CLAM_QUAR}/$(date +%s)_$$_$(basename "$path")"
      fmeta="$(stat -c '%a:%u:%g' "$path" 2>/dev/null || echo '644:0:0')"   # remember mode/owner for a faithful restore
      if mv -f "$path" "$qf" 2>>"$LOG"; then
        chmod 000 "$qf" 2>/dev/null
        printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u '+%F %T')" "$qf" "$path" "$sig" "$fmeta" >>"$CLAM_MANIFEST"
        quarantined=$((quarantined+1))
      fi
    else
      reported=$((reported+1))
    fi
  done < "$scanlog"
  clamlog "$label scan: infected=$infected quarantined=$quarantined reported=$reported (log $scanlog)"
  [[ $infected -gt 0 ]] && clam_alert_hook "$infected" "$label"
  CLAM_LAST_LOG="$scanlog"; CLAM_LAST_INF=$infected; CLAM_LAST_Q=$quarantined; CLAM_LAST_R=$reported
  return 0
}

# TUI wrapper around the core engine
clam_run_scan(){
  clam_ensure || { msg "ClamAV" "Engine unavailable — install failed. See $LOG."; return 1; }
  local label="$1" mode="$2"; shift 2
  infobox "ClamAV ${label} Scan" "Scanning: $*\n\nThrottled with nice/ionice. A full scan can take several minutes — the screen will update when it finishes."
  clam_core_scan "$mode" "$label" "$@"
  { echo "ClamAV ${label} scan — $(date '+%F %T %Z')"
    echo "scanned    : $*"
    echo "infected   : ${CLAM_LAST_INF:-0}"
    echo "quarantined: ${CLAM_LAST_Q:-0}   (moved to ${CLAM_QUAR}, perms 000)"
    echo "reported   : ${CLAM_LAST_R:-0}   (critical/system paths — NOT auto-moved, review manually)"
    echo "scan log   : ${CLAM_LAST_LOG:-n/a}"
    if [[ "${CLAM_LAST_INF:-0}" -gt 0 ]]; then echo; echo "detections:"; grep ' FOUND$' "${CLAM_LAST_LOG}" 2>/dev/null; fi
  } >"$IS_TMP/clam"
  showfile "ClamAV ${label} Scan Results" "$IS_TMP/clam"
}

clam_quarantine_menu(){
  local pick meta m_ts m_qf m_path m_sig m_meta m_mode m_uid m_gid act ts qf path sig fmeta
  while :; do
    [[ -s "$CLAM_MANIFEST" ]] || { msg "Quarantine Vault" "Vault is empty.\n\nLocation: ${CLAM_QUAR}"; return; }
    local args=()
    while IFS=$'\t' read -r ts qf path sig fmeta; do
      [[ -e "$qf" ]] && args+=("$qf" "$(basename "$path")  [${sig}]  ${ts}")
    done < "$CLAM_MANIFEST"
    [[ ${#args[@]} -eq 0 ]] && { msg "Quarantine Vault" "No live quarantined files remain."; : >"$CLAM_MANIFEST"; return; }
    pick=$(menu "🗄️ Quarantine Vault" "Vault: ${CLAM_QUAR}   —   select an item to act on:" "${args[@]}") || return
    # match the quarantine path as an EXACT tab-field (field 2), not a substring —
    # grep -F would let one entry's path match another whose path is a superstring.
    meta="$(awk -F'\t' -v q="$pick" '$2==q{print; exit}' "$CLAM_MANIFEST")"
    IFS=$'\t' read -r m_ts m_qf m_path m_sig m_meta <<<"$meta"
    act=$(menu "Quarantined Item" "File   : $(basename "$m_path")\nOrigin : ${m_path}\nSig    : ${m_sig}\nWhen   : ${m_ts}\n\nAction:" \
      R "♻️  Restore to original location" \
      D "🗑️  Permanently DELETE" \
      b "Back") || continue
    case "$act" in
      R) mkdir -p "$(dirname "$m_path")"
         IFS=: read -r m_mode m_uid m_gid <<<"${m_meta:-644:0:0}"
         if mv -f "$pick" "$m_path" 2>>"$LOG"; then
           chmod "${m_mode:-644}" "$m_path" 2>/dev/null || true       # restore original mode/owner instead of a blanket 644
           chown "${m_uid:-0}:${m_gid:-0}" "$m_path" 2>/dev/null || true
           awk -F'\t' -v q="$pick" '$2!=q' "$CLAM_MANIFEST" >"${CLAM_MANIFEST}.tmp" 2>/dev/null && mv -f "${CLAM_MANIFEST}.tmp" "$CLAM_MANIFEST" 2>/dev/null
           clamlog "restored $m_path (mode ${m_mode:-644} owner ${m_uid:-0}:${m_gid:-0})"
           msg "Restored" "File returned to:\n${m_path}\n(mode ${m_mode:-644}, owner ${m_uid:-0}:${m_gid:-0})\n\nRescan it before trusting it."
         else msg "Restore Failed" "Could not move the file back — see $LOG."; fi ;;
      D) yesno_danger "Confirm Delete" "Permanently delete this quarantined file?\n\n${m_path}" || continue
         rm -f "$pick"
         awk -F'\t' -v q="$pick" '$2!=q' "$CLAM_MANIFEST" >"${CLAM_MANIFEST}.tmp" 2>/dev/null && mv -f "${CLAM_MANIFEST}.tmp" "$CLAM_MANIFEST" 2>/dev/null
         clamlog "deleted quarantined $m_path"
         msg "Deleted" "Quarantined file permanently removed." ;;
    esac
  done
}

clam_toggle_realtime(){
  clam_ensure || { msg "ClamAV" "Engine unavailable."; return; }
  [[ -f "$CLAMD_CONF" ]] || { msg "On-Access" "clamd.conf not found at ${CLAMD_CONF}."; return; }
  if systemctl is-active --quiet clamav-clamonacc 2>/dev/null; then
    yesno "Real-Time Protection" "On-access scanning is currently ON.\n\nDisable it? (Frees memory; scheduled scans still run.)" || return
    run systemctl disable --now clamav-clamonacc
    clamlog "on-access disabled"
    msg "Real-Time OFF" "On-access scanning disabled."
  else
    yesno "Real-Time Protection" "Enable on-access (real-time) scanning?\n\nStarts clamd + clamonacc and uses notably more RAM. On a pure relay this is usually unnecessary — scheduled scans are lighter." || return
    clam_conf_set "OnAccessIncludePath" "/home"
    clam_conf_set "OnAccessPrevention" "false"
    clam_conf_set "OnAccessExcludeUname" "clamav"
    run systemctl enable --now clamav-daemon
    run systemctl enable --now clamav-clamonacc
    sleep 1
    if systemctl is-active --quiet clamav-clamonacc; then
      clamlog "on-access enabled"
      msg "Real-Time ON" "On-access scanning enabled (watching /home, detect-only)."
    else
      msg "Real-Time" "clamonacc didn't start yet — clamd may still be building its DB. Check 'systemctl status clamav-clamonacc' and $LOG."
    fi
  fi
}

clam_update(){
  clam_ensure || { msg "ClamAV" "Engine unavailable."; return; }
  infobox "Signature Update" "Stopping the freshclam daemon and pulling the latest signatures..."
  run systemctl stop clamav-freshclam
  # routed through run_capture (v8.0): streams live to the terminal, logs, AND
  # preserves the real exit code — the old bare $(freshclam) did none of that.
  local out="$IS_TMP/freshclam.out" rc=0
  run_capture "$out" freshclam || rc=$?
  cat "$out" >>"$LOG" 2>/dev/null || true
  run systemctl start clamav-freshclam
  clamlog "manual signature update (rc=$rc)"
  if (( rc == 0 )) || grep -qiE 'up.to.date|updated|is up to date|main\.|daily\.' "$out"; then
    msg "Update Complete" "Signature database refreshed.\n\n$(sigtool --info /var/lib/clamav/daily.c?d 2>/dev/null | grep -m1 -iE 'version|build')"
  else
    msg "Update Finished" "freshclam exited with rc=$rc — output (tail):\n\n$(tail -n 6 "$out" 2>/dev/null)"
  fi
}

clam_set_timer(){
  local kind="$1" freq oncal self
  freq=$(menu "Frequency" "How often should the ${kind} scan run?" \
    daily "Every day at 03:00" \
    weekly "Every Sunday at 03:00") || return
  [[ "$freq" == "daily" ]] && oncal="*-*-* 03:00:00" || oncal="Sun *-*-* 03:00:00"
  self="$(install_self)"
  cat >"/etc/systemd/system/intelshield-clamscan-${kind}.service" <<EOF
[Unit]
Description=IntelShield ClamAV ${kind} scan
[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
RuntimeMaxSec=6h
ExecStart=${self} --clamav-scan ${kind}
EOF
  cat >"/etc/systemd/system/intelshield-clamscan-${kind}.timer" <<EOF
[Unit]
Description=IntelShield ClamAV ${kind} scan schedule
[Timer]
OnCalendar=${oncal}
Persistent=true
[Install]
WantedBy=timers.target
EOF
  run systemctl daemon-reload
  run systemctl enable --now "intelshield-clamscan-${kind}.timer"
  clamlog "scheduled ${kind} scan (${freq})"
  msg "Schedule Set" "${kind^} scan scheduled: ${freq} at 03:00 (server local time).\nTimer: intelshield-clamscan-${kind}.timer"
}

clam_rm_timer(){
  local kind
  kind=$(menu "Disable Schedule" "Which scheduled scan should be removed?" \
    full "Full scan timer" \
    smart "Smart scan timer") || return
  run systemctl disable --now "intelshield-clamscan-${kind}.timer"
  rm -f "/etc/systemd/system/intelshield-clamscan-${kind}.timer" "/etc/systemd/system/intelshield-clamscan-${kind}.service"
  run systemctl daemon-reload
  clamlog "removed ${kind} schedule"
  msg "Schedule Removed" "${kind^} scan schedule deleted."
}

clam_schedule_menu(){
  local c fs ss
  while :; do
    # svc_enabled always emits exactly ONE token — `is-enabled X || echo disabled`
    # printed TWO lines ("disabled\ndisabled") when the unit existed but was
    # disabled, because is-enabled prints its state AND returns non-zero.
    fs="$(svc_enabled intelshield-clamscan-full.timer)"
    ss="$(svc_enabled intelshield-clamscan-smart.timer)"
    c=$(menu "🗓️ Automated Scan Scheduling" "Full timer: ${fs}    Smart timer: ${ss}" \
      F "Schedule FULL scan (daily / weekly)" \
      S "Schedule SMART scan (daily / weekly)" \
      X "Disable a scheduled scan" \
      b "Back") || return
    case "$c" in
      F) clam_set_timer full ;;
      S) clam_set_timer smart ;;
      X) clam_rm_timer ;;
      b) return ;;
    esac
  done
}

clam_toggle_conf(){
  local key="$1" cur; cur="$(clam_conf_get "$key")"
  if [[ "$cur" == "yes" || "$cur" == "true" ]]; then clam_conf_set "$key" "no"; else clam_conf_set "$key" "yes"; fi
  clamlog "$key -> $(clam_conf_get "$key")"; clam_reload_daemon
  msg "$key" "${key} is now: $(clam_conf_get "$key")\n\n(Applies to clamd-based scans; takes effect on next daemon start if clamd isn't running.)"
}

clam_toggle_structured(){
  local cur; cur="$(clam_conf_get StructuredDataDetection)"
  if [[ "$cur" == "yes" ]]; then
    clam_conf_set StructuredDataDetection no
  else
    clam_conf_set StructuredDataDetection yes
    clam_conf_set StructuredMinCreditCardCount 3
    clam_conf_set StructuredMinSSNCount 3
    clam_conf_set StructuredSSNFormatNormal yes
  fi
  clamlog "StructuredDataDetection -> $(clam_conf_get StructuredDataDetection)"; clam_reload_daemon
  msg "Structured Data Detection" "StructuredDataDetection is now: $(clam_conf_get StructuredDataDetection)\n\nMatches SSN / credit-card patterns (DLP). Expect false positives on legit data files."
}

clam_hardening_menu(){
  clam_ensure || { msg "ClamAV" "Engine unavailable."; return; }
  [[ -f "$CLAMD_CONF" ]] || { msg "Hardening" "clamd.conf not found at ${CLAMD_CONF}."; return; }
  local c pua heur sdc
  while :; do
    pua="$(clam_conf_get DetectPUA)"; heur="$(clam_conf_get HeuristicScanPrecedence)"; sdc="$(clam_conf_get StructuredDataDetection)"
    c=$(menu "🛡️ ClamAV Protection & Hardening" "Toggle clamd.conf detection behaviours (reload applied if clamd is running):" \
      P "PUA blocking (DetectPUA)              [now: ${pua:-no}]" \
      H "Heuristic precedence                   [now: ${heur:-no}]" \
      S "Structured data DLP (SSN / CC)         [now: ${sdc:-no}]" \
      b "Back") || return
    case "$c" in
      P) clam_toggle_conf DetectPUA ;;
      H) clam_toggle_conf HeuristicScanPrecedence ;;
      S) clam_toggle_structured ;;
      b) return ;;
    esac
  done
}

clamav_menu(){
  local c st rt sig
  while :; do
    st="not installed"; clam_present && st="installed"
    rt="off"; systemctl is-active --quiet clamav-clamonacc 2>/dev/null && rt="ON"
    sig="$(date -r /var/lib/clamav/daily.cld '+%F' 2>/dev/null || date -r /var/lib/clamav/daily.cvd '+%F' 2>/dev/null || echo '?')"
    c=$(menu "🦠 ClamAV Antivirus Management" "Engine: ${st}   ·   Real-time: ${rt}   ·   Signatures: ${sig}" \
      1 "🔎 Full System Comprehensive Scan" \
      2 "⚡ Smart Scan (high-risk paths)" \
      3 "🗄️  Quarantine Management" \
      4 "🛰️  Toggle Real-Time (On-Access) Protection" \
      5 "🔄 Force Update Signature Database" \
      6 "🗓️  Configure Automated Scan Scheduling" \
      7 "🛡️  Protection & Hardening (clamd.conf)" \
      b "Return to Main Context")
    case "$?" in 1|255) break ;; esac
    case "$c" in
      1) clam_run_scan "Full"  quarantine / ;;
      2) clam_run_scan "Smart" quarantine /root /home /var/www /etc /tmp /dev/shm ;;
      3) clam_quarantine_menu ;;
      4) clam_toggle_realtime ;;
      5) clam_update ;;
      6) clam_schedule_menu ;;
      7) clam_hardening_menu ;;
      b) break ;;
    esac
  done
}


#==============================================================================
#  STATUS / DIAGNOSTICS
#==============================================================================
status(){
  local f="$IS_TMP/is_status"
  state_write
  {
    echo "=============================================================================="
    echo "                    INTELSHIELD NODE STATUS  —  $(date -Is)"
    echo "=============================================================================="
    echo "OS               : ${OS_DESC:-?}"
    echo "NIC / public IP  : ${NIC:-?} / ${PUB_IP:-?}      SSH port: ${SSH_PORT:-?}"
    echo "Active profile   : $(cat "$PROFILE_FILE" 2>/dev/null || echo none)"
    echo "CPU governor     : $(get_cpu_governor_status)"
    echo "TCP congestion   : $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
    echo "UFW              : $(ufw status 2>/dev/null | head -n1)"
    echo "CrowdSec engine  : $(svc_state crowdsec)   bouncer: $(svc_state crowdsec-firewall-bouncer)"
    echo "Suricata         : $(svc_state suricata)   mode: $(suri_mode_get | tr a-z A-Z)   fw: $(suricata_fw_mode_get)"
    echo "x-ui / Xray      : x-ui=$(svc_state x-ui) xray=$(svc_state xray)   sandbox=$(sandbox_is_applied && echo applied || echo off)"
    echo "ClamAV freshclam : $(svc_state clamav-freshclam)"
    echo "auditd           : $(svc_state auditd)"
    echo "Wazuh agent      : $(svc_state wazuh-agent)"
    echo "Maintenance cron : $(maint_cron_status)   (audit: $MAINT_LOG)"
    echo "rkhunter         : $(rkhunter_present && echo installed || echo missing)"
    echo "chkrootkit       : $(chkrootkit_present && echo installed || echo missing)"
    echo "State database   : $STATE_DB"
    echo "Backups dir      : $BACKUP_DIR"
  } >"$f"
  showfile "IntelShield Node Status" "$f"
}

#==============================================================================
#  UPDATE CENTER  (system / package / firmware / driver updates + auto-update)
#==============================================================================
# Relay-safe auto-upgrade guard: never auto-installs the kernel, network drivers or
# the live security engines (they only move on a manual maintenance window).
write_kernel_upgrade_blacklist(){ cat >"$UPGRADE_BLACKLIST" <<'EOF'
Unattended-Upgrade::Package-Blacklist {
    "linux-image-";
    "linux-headers-";
    "linux-modules-";
    "linux-modules-extra-";
    "suricata";
    "crowdsec";
    "crowdsec-firewall-bouncer-nftables";
    "wazuh-agent";
    "xray";
    "x-ui";
};
Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
}

reboot_required(){ [[ -f /var/run/reboot-required ]]; }
reboot_pending(){ [[ -f /run/systemd/shutdown/scheduled ]]; }
# schedule a ONE-OFF reboot at 01:11 (next occurrence). Used after a manual upgrade
# that needs a reboot; the auto-update path uses unattended-upgrades' own timer.
update_schedule_reboot(){
  shutdown -c >/dev/null 2>&1 || true
  if shutdown -r "$AUTO_REBOOT_TIME" "IntelShield: applying updates (scheduled reboot)" >>"$LOG" 2>&1; then
    log "one-off reboot scheduled for $AUTO_REBOOT_TIME"; return 0
  fi
  # fallback for systems where 'shutdown hh:mm' is unavailable
  systemd-run --on-calendar="*-*-* ${AUTO_REBOOT_TIME}:00" --timer-property=AccuracySec=1min systemctl reboot >>"$LOG" 2>&1
}
update_cancel_reboot(){ shutdown -c >>"$LOG" 2>&1 || true; log "pending reboot cancelled"; }

# after any manual upgrade action, offer to defer the required reboot to 01:11
update_offer_reboot(){
  reboot_required || return 0
  local pkgs=""; [[ -f /var/run/reboot-required.pkgs ]] && pkgs="$(tr '\n' ' ' </var/run/reboot-required.pkgs)"
  if yesno "Reboot Required" "A reboot is needed to finish applying updates${pkgs:+ (from: ${pkgs})}.\n\nSchedule an automatic reboot at ${AUTO_REBOOT_TIME}?\n\n(No = reboot yourself later; nothing is applied until you do.)"; then
    update_schedule_reboot
    msg "Reboot Scheduled" "The server will reboot at ${AUTO_REBOOT_TIME} to apply updates.\nCancel any time from the Update Center (or: shutdown -c)."
  else
    msg "Reboot Deferred" "A reboot is still required to finish applying updates. Reboot manually when convenient."
  fi
}

# refresh package index only
update_refresh(){ infobox "Package Index" "Refreshing repositories (apt-get update)..."; run apt-get update; msg "Package Index" "Repository metadata refreshed."; }

# $1 = safe (apt upgrade, no removals)  |  full (apt full-upgrade, allows dep changes)
# NEVER performs a release upgrade (do-release-upgrade is never invoked).
update_packages(){
  local mode="${1:-safe}" out; local -a cmd
  if [[ "$mode" == full ]]; then cmd=(apt-get -y -o Dpkg::Options::=--force-confold full-upgrade)
  else cmd=(apt-get -y --with-new-pkgs -o Dpkg::Options::=--force-confold upgrade); fi
  infobox "Package Upgrade" "Running $([[ "$mode" == full ]] && echo 'full-upgrade (with dependency changes)' || echo 'safe upgrade (no package removals)').\nThis is NOT a release upgrade — your Ubuntu version stays the same.\n\nWorking..."
  run apt-get update
  out="$IS_TMP/upgrade.out"
  # stream the upgrade live (when the live console is on) AND capture it for the summary
  DEBIAN_FRONTEND=noninteractive run_capture "$out" "${cmd[@]}"; local rc=$?
  cat "$out" >>"$LOG"
  run apt-get -y autoremove
  { echo "Package upgrade ($mode) — $(date '+%F %T')"; echo "exit: $rc"; echo;
    echo "== upgraded / changed =="; grep -Ei 'Setting up|Unpacking|Removing|newly installed|upgraded,' "$out" | tail -n 60 || true;
    echo; echo "== reboot required =="; reboot_required && cat /var/run/reboot-required 2>/dev/null || echo "no"; } >"$IS_TMP/upgrade.view"
  showfile "Package Upgrade Result" "$IS_TMP/upgrade.view"
  state_write
  update_offer_reboot
}

update_firmware(){
  local virt; virt=$(systemd-detect-virt 2>/dev/null || echo none)
  have fwupdmgr || { infobox "Firmware" "Installing fwupd (firmware update daemon)..."; run apt-get install -y fwupd; }
  have fwupdmgr || { msg "Firmware" "fwupd is not available on this host."; return 1; }
  if [[ "$virt" != none && "$virt" != "bare-metal" ]]; then
    yesno "Firmware Update" "This host is virtualized ($virt); fwupd usually finds no updatable devices on a VM/VPS.\n\nRun the firmware check anyway?" || return 3
  fi
  infobox "Firmware" "Refreshing firmware metadata and checking for device updates..."
  run fwupdmgr refresh --force
  { echo "== fwupd devices =="; fwupdmgr get-devices 2>&1 | sed -n '1,80p'; echo; echo "== available updates =="; fwupdmgr get-updates 2>&1; } >"$IS_TMP/fw.view"
  showfile "Firmware Status" "$IS_TMP/fw.view"
  if fwupdmgr get-updates >/dev/null 2>&1; then
    yesno_danger "Apply Firmware Updates" "Firmware updates were found.\n\nApplying firmware can require a reboot and, on rare devices, carries a small bricking risk if power is lost.\n\nProceed with 'fwupdmgr update'?" || return 3
    run fwupdmgr update
    msg "Firmware" "Firmware update attempted. Some devices apply on the next reboot — see $LOG."
    update_offer_reboot
  else
    msg "Firmware" "No applicable firmware updates were reported for this host."
  fi
}

update_drivers(){
  have ubuntu-drivers || { infobox "Drivers" "Installing ubuntu-drivers-common..."; run apt-get install -y ubuntu-drivers-common; }
  { echo "== detected devices / recommended drivers =="; ubuntu-drivers devices 2>&1 || echo "(ubuntu-drivers unavailable or no devices)"; } >"$IS_TMP/drv.view"
  showfile "Driver Detection" "$IS_TMP/drv.view"
  yesno "Driver Update" "Install the recommended hardware drivers (ubuntu-drivers autoinstall) and refresh the linux-firmware blobs?\n\nOn a plain VPS this is usually a no-op; on bare metal it may pull GPU/NIC drivers." || return 3
  infobox "Drivers" "Installing recommended drivers and refreshing linux-firmware..."
  run ubuntu-drivers autoinstall
  run apt-get install -y --only-upgrade linux-firmware
  msg "Drivers" "Driver install/refresh finished. See $LOG for details."
  state_write
  update_offer_reboot
}

update_auto_status(){
  local en reboot rtime bl
  en="disabled"; [[ -f "$UPDATE_AUTOCONF" ]] && grep -q 'Unattended-Upgrade "1"' "$UPDATE_AUTOCONF" && en="ENABLED"
  reboot="no"; grep -rqs 'Automatic-Reboot "true"' "$UPDATE_AUTOCONF" && reboot="yes"
  rtime="$(grep -hs 'Automatic-Reboot-Time' "$UPDATE_AUTOCONF" 2>/dev/null | sed -E 's/.*"([^"]+)".*/\1/' | head -1)"
  bl="present (kernel/engines protected)"; [[ -f "$UPGRADE_BLACKLIST" ]] || bl="absent (kernel included in auto-update)"
  printf '%s' "auto-update: $en | auto-reboot: $reboot ${rtime:+@ $rtime} | blacklist: $bl"
}

update_auto_enable(){
  infobox "Auto-Update" "Configuring unattended security updates with an automatic ${AUTO_REBOOT_TIME} reboot when required..."
  run apt-get install -y unattended-upgrades
  local include_kernel=no
  if yesno_danger "Include Kernel & Firmware?" "Also auto-install KERNEL and driver/firmware updates?\n\nYes = fully patched, but the ${AUTO_REBOOT_TIME} reboot may bounce the kernel and briefly drop the VLESS tunnel.\nNo  = recommended for relays: auto-patch everything EXCEPT the kernel/engines (still reboots at ${AUTO_REBOOT_TIME} for other updates that need it)."; then
    include_kernel=yes
    rm -f "$UPGRADE_BLACKLIST"          # allow the kernel/engines to auto-upgrade
  else
    write_kernel_upgrade_blacklist       # keep the relay-safe guard
  fi
  # highest-precedence apt.conf.d file: turns unattended-upgrades ON and sets the reboot policy
  cat >"$UPDATE_AUTOCONF" <<EOF
// IntelShield auto-update policy (overrides earlier apt.conf.d files)
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
EOF
  run systemctl enable --now unattended-upgrades
  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer
  # validate the policy actually parses — the old `a || b || true` swallowed a
  # broken apt.conf.d file and reported success anyway.
  local dry_warn=""
  if have unattended-upgrade; then
    run unattended-upgrade --dry-run || dry_warn="\n\n⚠ 'unattended-upgrade --dry-run' exited non-zero — the policy may not parse. Check $LOG before relying on auto-updates."
  fi
  state_write
  msg "Auto-Update Enabled" "Automatic updates are ON.\n\n• Security updates apply on the daily apt timer\n• Kernel/firmware auto-install: ${include_kernel}\n• If a reboot is required, the server reboots automatically at ${AUTO_REBOOT_TIME}\n\nStatus: $(update_auto_status)${dry_warn}"
}

update_auto_disable(){
  # override the periodic keys to 0 and stop auto-reboots, without touching the
  # baseline files; restore the relay-safe kernel blacklist.
  cat >"$UPDATE_AUTOCONF" <<'EOF'
// IntelShield: automatic updates DISABLED
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::Download-Upgradeable-Packages "0";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
  write_kernel_upgrade_blacklist
  run systemctl disable --now apt-daily-upgrade.timer || true
  update_cancel_reboot
  state_write
  msg "Auto-Update Disabled" "Automatic updates and the ${AUTO_REBOOT_TIME} auto-reboot are OFF.\nManual updates from this menu still work normally."
}

update_center_menu(){
  local c
  while :; do
    c=$(menu "🔄 Update Center" "System / package / firmware / driver updates. Never performs a release (distro) upgrade.\n$(update_auto_status)" \
      R "Refresh package lists (apt update)" \
      U "Package upgrade — safe (no removals)" \
      F "Full upgrade — allow dependency changes (same release)" \
      W "Firmware update (fwupd)" \
      D "Driver update (recommended drivers + linux-firmware)" \
      A "Activate automatic updates + ${AUTO_REBOOT_TIME} auto-reboot" \
      X "Disable automatic updates" \
      S "Reboot status / schedule ${AUTO_REBOOT_TIME} reboot / cancel" \
      b "Back") || return
    case "$c" in
      R) update_refresh ;;
      U) update_packages safe ;;
      F) yesno_danger "Full Upgrade" "Full-upgrade may change or remove dependencies (still within the same Ubuntu release — no distro upgrade).\n\nProceed?" && update_packages full ;;
      W) update_firmware ;;
      D) update_drivers ;;
      A) update_auto_enable ;;
      X) update_auto_disable ;;
      S) local rs; rs="not required"; reboot_required && rs="REQUIRED"; reboot_pending && rs="$rs (a reboot is already scheduled)"
         local a; a=$(menu "Reboot Control" "Reboot-required: ${rs}" \
              G "Schedule a reboot at ${AUTO_REBOOT_TIME}" \
              C "Cancel a pending scheduled reboot" \
              N "Reboot now" \
              b "Back") || continue
         case "$a" in
           G) update_schedule_reboot; msg "Reboot Scheduled" "Server will reboot at ${AUTO_REBOOT_TIME}." ;;
           C) update_cancel_reboot; msg "Reboot Cancelled" "Any pending scheduled reboot was cancelled." ;;
           N) yesno_danger "Reboot Now" "Reboot the server immediately?" && { log "manual immediate reboot from Update Center"; systemctl reboot; } ;;
         esac ;;
      b) return ;;
    esac
  done
}

#==============================================================================
#  MAINTENANCE & AUTO-UPDATE ENGINE  (v8.0 — opt-in cron, dedicated audit log)
#==============================================================================
# Design contract:
#   • OPT-IN: the cron file is written ONLY from the maintenance menu — never
#     behind the user's back on install/upgrade.
#   • Every cron-triggered action, warning and failure lands in $MAINT_LOG with
#     a timestamp and the step's REAL exit code (ALERT: lines mark failures).
#   • Services are restarted ONLY after a step verifiably succeeded, and every
#     restart is gated: if the daemon doesn't come back, the previous working
#     state is restored (restart_or_rollback / the Suricata ruleset snapshot).
#   • One run at a time: a flock on $MAINT_LOCK makes overlapping cron fires a
#     logged no-op instead of two apt/dpkg processes fighting each other.

maint_log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$MAINT_LOG"; }
# run one maintenance step: stream combined stdout+stderr into the audit log
# (and to the terminal when the live console is on), log the REAL exit code,
# and RETURN it — callers gate restarts on this, so nothing gets swallowed.
maint_step(){
  local label="$1" rc; shift
  maint_log "[$label] + $*"
  if (( ${LIVE_OUTPUT:-0} )) && [[ -t 1 ]]; then
    printf '\033[1;36m[%s] $ %s\033[0m\n' "$label" "$*"
    "$@" </dev/null 2>&1 | tee -a "$MAINT_LOG"; rc="${PIPESTATUS[0]}"
  else
    "$@" </dev/null >>"$MAINT_LOG" 2>&1; rc=$?
  fi
  if (( rc == 0 )); then maint_log "[$label] rc=0 OK"
  else maint_log "ALERT: [$label] rc=$rc FAILED"; fi
  return "$rc"
}

maint_write_logrotate(){
  [[ -f "$MAINT_LOGROTATE" ]] && return 0
  cat >"$MAINT_LOGROTATE" <<EOF
$MAINT_LOG {
    weekly
    rotate 8
    missingok
    notifempty
    compress
    delaycompress
    create 600 root root
}
EOF
}

# ---- phase 1: OS packages (safe upgrade — no removals, never a release upgrade)
maint_os_update(){
  local rc=0
  maint_log "=== OS package maintenance started (IntelShield v$VERSION) ==="
  maint_step os-apt-update apt-get -o "$APT_LOCK_OPT" update || rc=1
  maint_step os-apt-upgrade apt-get -o "$APT_LOCK_OPT" -y --with-new-pkgs \
             -o Dpkg::Options::=--force-confold upgrade || rc=1
  maint_step os-autoremove apt-get -o "$APT_LOCK_OPT" -y autoremove || true
  if [[ -f /var/run/reboot-required ]]; then
    local pkgs=""; [[ -f /var/run/reboot-required.pkgs ]] && pkgs=" (pkgs: $(tr '\n' ' ' </var/run/reboot-required.pkgs))"
    maint_log "NOTICE: reboot required${pkgs} — handled by the ${AUTO_REBOOT_TIME} auto-reboot policy if enabled (Update Center)"
  fi
  maint_log "=== OS package maintenance finished rc=$rc ==="
  return $rc
}

# ---- phase 2: security components, sequential, each restart gated on success
maint_components(){
  local overall=0
  maint_log "=== Component maintenance started ==="
  # 1) Suricata threat rules — full snapshot → update → SID self-heal → gated
  #    restart pipeline (suricata_update_rules already implements the atomic
  #    rollback contract; in non-interactive mode its dialogs become log lines).
  if have suricata && have suricata-update && systemctl is-active --quiet suricata; then
    if suricata_update_rules; then maint_log "[suricata-rules] updated, validated and applied"
    else maint_log "ALERT: [suricata-rules] update failed — self-heal engaged, sensor kept running (details in $LOG)"; overall=1; fi
  else maint_log "[suricata-rules] skipped (engine not installed or not active)"; fi
  # 2) CrowdSec hub (parsers/scenarios/collections) — reload ONLY on success
  if have_cs && systemctl is-active --quiet crowdsec; then
    if maint_step crowdsec-hub-update cscli hub update && \
       maint_step crowdsec-hub-upgrade cscli hub upgrade; then
      if maint_step crowdsec-reload systemctl reload crowdsec || \
         maint_step crowdsec-restart systemctl restart crowdsec; then
        systemctl is-active --quiet crowdsec || { maint_log "ALERT: crowdsec NOT active after hub upgrade"; overall=1; }
      else overall=1; fi
    else
      maint_log "ALERT: [crowdsec] hub upgrade failed — engine NOT reloaded (keeps running on current hub)"
      overall=1
    fi
  else maint_log "[crowdsec] skipped (not installed or not active)"; fi
  # 3) ClamAV signature database (freshclam daemon released around the manual run)
  if have freshclam; then
    systemctl stop clamav-freshclam >>"$MAINT_LOG" 2>&1 || true
    maint_step clamav-freshclam freshclam || overall=1
    systemctl start clamav-freshclam >>"$MAINT_LOG" 2>&1 || true
  else maint_log "[clamav] skipped (not installed)"; fi
  # 4) Wazuh agent — upgrade via apt; restart ONLY if the version actually moved
  if wazuh_agent_present; then
    local wv_before wv_after
    wv_before="$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null)"
    if maint_step wazuh-agent-upgrade apt-get -o "$APT_LOCK_OPT" install -y --only-upgrade wazuh-agent; then
      wv_after="$(dpkg-query -W -f='${Version}' wazuh-agent 2>/dev/null)"
      if [[ -n "$wv_after" && "$wv_after" != "$wv_before" ]]; then
        maint_log "[wazuh-agent] upgraded ${wv_before:-?} -> ${wv_after}"
        if maint_step wazuh-agent-restart systemctl restart wazuh-agent; then
          systemctl is-active --quiet wazuh-agent || { maint_log "ALERT: wazuh-agent NOT active after upgrade"; overall=1; }
        else overall=1; fi
      else maint_log "[wazuh-agent] already current (${wv_before:-?}) — no restart"; fi
    else overall=1; fi
  else maint_log "[wazuh-agent] skipped (not installed)"; fi
  maint_log "=== Component maintenance finished rc=$overall ==="
  return $overall
}

# ---- phase 3: script self-update (verified, atomic, hot-reload optional) ------
update_url_get(){
  local url=""
  # sed (not awk -F=) so URLs containing '=' (query strings, tokens) survive intact
  [[ -f "$UPDATE_CONF" ]] && url="$(sed -n 's/^UPDATE_URL=//p' "$UPDATE_CONF" 2>/dev/null | tail -1 | tr -d '"' | tr -d "'")"
  [[ -z "$url" ]] && url="$UPDATE_URL_DEFAULT"
  printf '%s' "$url"
}
update_url_set(){ mkdir -p "$(dirname "$UPDATE_CONF")"; printf 'UPDATE_URL=%s\n' "$1" >"$UPDATE_CONF"; chmod 600 "$UPDATE_CONF"; }

# $1 = cron | interactive.
# Security model: HTTPS-only fetch (TLS >= 1.2, no protocol downgrade), identity
# marker + VERSION header required, full `bash -n` syntax validation — and the
# candidate is NEVER executed during verification. Install is stage + rename
# (atomic): running sessions keep their already-open file descriptor, so a live
# interactive session is never corrupted mid-run.
self_update_check(){
  local mode="${1:-interactive}" url tmp remote_ver dst=/usr/local/sbin/intelshield staged
  url="$(update_url_get)"
  tmp="$IS_TMP/intelshield.remote"
  maint_log "[self-update] checking $url (local v$VERSION)"
  if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 "$url" -o "$tmp" 2>>"$MAINT_LOG"; then
    maint_log "ALERT: [self-update] download failed (URL unreachable or file missing)"
    [[ "$mode" == interactive ]] && msg "Self-Update" "Could not fetch the update source:\n$url\n\nPublish the script there (or fix the URL from this menu). See $MAINT_LOG."
    return 1
  fi
  [[ -s "$tmp" ]] || { maint_log "ALERT: [self-update] downloaded file is empty"; return 1; }
  head -n 5 "$tmp" | grep -q "IntelShield" || { maint_log "ALERT: [self-update] identity check failed (no IntelShield header) — NOT installed"; return 1; }
  remote_ver="$(grep -m1 -E 'VERSION="[0-9][^"]*"' "$tmp" | sed -E 's/.*VERSION="([^"]+)".*/\1/')"
  [[ -n "$remote_ver" ]] || { maint_log "ALERT: [self-update] no VERSION marker in remote file — NOT installed"; return 1; }
  if ! bash -n "$tmp" 2>>"$MAINT_LOG"; then
    maint_log "ALERT: [self-update] remote script failed bash -n syntax validation — NOT installed"
    [[ "$mode" == interactive ]] && msg "Self-Update" "The remote script failed syntax validation and was NOT installed. See $MAINT_LOG."
    return 1
  fi
  # newest-wins compare (sort -V handles 8.0 vs 8.0.1 vs 10.0 correctly)
  if [[ "$remote_ver" == "$VERSION" || "$(printf '%s\n%s\n' "$VERSION" "$remote_ver" | sort -V | tail -1)" == "$VERSION" ]]; then
    maint_log "[self-update] already current (local v$VERSION >= remote v$remote_ver)"
    [[ "$mode" == interactive ]] && msg "Self-Update" "IntelShield is up to date.\n\nLocal:  v$VERSION\nRemote: v$remote_ver\nSource: $url"
    return 0
  fi
  staged="${dst}.staged.$$"
  install -m 750 "$tmp" "$staged" 2>>"$MAINT_LOG" || { maint_log "ALERT: [self-update] staging to $staged failed"; rm -f "$staged"; return 1; }
  if ! mv -f "$staged" "$dst" 2>>"$MAINT_LOG"; then
    maint_log "ALERT: [self-update] atomic install to $dst failed"; rm -f "$staged"; return 1
  fi
  maint_log "[self-update] installed v$remote_ver over v$VERSION at $dst"
  log "self-update: v$remote_ver installed at $dst (was v$VERSION)"
  if [[ "$mode" == interactive ]]; then
    if yesno "IntelShield Updated" "Version $remote_ver has been installed (you were on $VERSION).\n\nHot-reload into the new version now?\n\n(The new version starts fresh at its main menu; the timers/cron already point at the updated canonical copy.)"; then
      log "self-update: hot-reloading into v$remote_ver"
      clear 2>/dev/null || true
      exec bash "$dst"
    fi
    msg "Self-Update" "v$remote_ver is installed at $dst.\nThis session keeps running v$VERSION until you exit; every timer and cron job already uses the new version."
  fi
  return 0
}

# ---- single-flight runner (used by the dispatcher and the run-now menu) -------
# Runs in a subshell holding an exclusive flock: overlapping cron fires become a
# logged no-op, and the lock is guaranteed released when the phase finishes.
maint_run(){
  local what="${1:-all}"
  (
    if ! flock -n 9; then maint_log "SKIP: previous maintenance run still active (requested: $what)"; exit 0; fi
    maint_write_logrotate
    case "$what" in
      os)         maint_os_update ;;
      components) maint_components ;;
      self)       self_update_check cron ;;
      all)        rc=0; maint_os_update || rc=1; maint_components || rc=1; self_update_check cron || rc=1; exit "$rc" ;;
      *)          echo "usage: $0 --maintain os|components|self|all" >&2; exit 2 ;;
    esac
  ) 9>"$MAINT_LOCK"
}

# ---- cron lifecycle (OPT-IN: written only from the menu) ----------------------
maint_cron_status(){ [[ -f "$MAINT_CRON" ]] && printf 'ENABLED' || printf 'disabled'; }
maint_cron_enable(){
  local self; self="$(install_self)"
  maint_write_logrotate
  cat >"$MAINT_CRON" <<EOF
# IntelShield Maintenance & Auto-Update Engine (managed — regenerated by the menu).
# Audit trail: $MAINT_LOG   Overlap guard: flock on $MAINT_LOCK (inside --maintain)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# OS packages: apt update + safe upgrade (no removals; never a release upgrade)
15 2 * * * root $self --maintain os --non-interactive --yes >>$MAINT_LOG 2>&1
# Security components: Suricata rules · CrowdSec hub · ClamAV sigs · Wazuh agent
15 3 * * * root $self --maintain components --non-interactive --yes >>$MAINT_LOG 2>&1
# IntelShield self-update (verified + atomic; weekly, Sunday)
30 4 * * 0 root $self --maintain self --non-interactive --yes >>$MAINT_LOG 2>&1
EOF
  chmod 644 "$MAINT_CRON"
  maint_log "maintenance cron ENABLED -> $MAINT_CRON (canonical script: $self)"
  state_write
}
maint_cron_disable(){ rm -f "$MAINT_CRON"; maint_log "maintenance cron DISABLED (cron file removed)"; state_write; }

maintenance_menu(){
  local c st url
  while :; do
    st="$(maint_cron_status)"; url="$(update_url_get)"
    c=$(menu "🛠 Maintenance & Auto-Update Engine" "Scheduled cron: ${st}   |   Audit log: ${MAINT_LOG}\nUpdate source: ${url}" \
      E "Enable schedule  (OS daily 02:15 · components daily 03:15 · self-update Sun 04:30)" \
      X "Disable schedule (remove the cron file)" \
      O "Run OS package maintenance NOW" \
      C "Run component updates NOW  (Suricata rules / CrowdSec hub / ClamAV / Wazuh)" \
      U "Check for an IntelShield update NOW" \
      S "Set the self-update source URL" \
      V "View the maintenance audit log" \
      b "Back") || return
    case "$c" in
      E) yesno "Enable Scheduled Maintenance" "Write $MAINT_CRON with these jobs?\n\n  02:15 daily — OS: apt update + safe upgrade (no removals)\n  03:15 daily — components: Suricata rules, CrowdSec hub, ClamAV sigs, Wazuh agent\n  04:30 Sun   — IntelShield self-update (verified, atomic)\n\nServices restart ONLY after a verified successful update; every action is logged to $MAINT_LOG." 20 96 \
           && { maint_cron_enable; msg "Maintenance Enabled" "Scheduled maintenance is ON.\n\nCron file: $MAINT_CRON\nAudit log: $MAINT_LOG\n\nA reboot needed by an OS update is NOT taken automatically — pair with the Update Center's ${AUTO_REBOOT_TIME} auto-reboot policy if you want that."; } ;;
      X) maint_cron_disable; msg "Maintenance Disabled" "The scheduled cron jobs were removed.\nManual 'run NOW' actions in this menu still work." ;;
      O) infobox "OS Maintenance" "Running apt update + safe upgrade now — output streams to the terminal (live console) and to $MAINT_LOG..."
         if maint_run os; then msg "OS Maintenance" "OS package maintenance finished cleanly.\nDetails: $MAINT_LOG"
         else msg "OS Maintenance" "OS package maintenance finished WITH ERRORS — review $MAINT_LOG."; fi ;;
      C) infobox "Component Updates" "Updating Suricata rules, CrowdSec hub, ClamAV signatures and the Wazuh agent sequentially..."
         if maint_run components; then msg "Component Updates" "All applicable components updated cleanly (services restarted only where an update succeeded).\nDetails: $MAINT_LOG"
         else msg "Component Updates" "Component maintenance finished WITH ERRORS — the failing step was rolled back / left untouched. Review $MAINT_LOG."; fi ;;
      U) self_update_check interactive ;;
      S) local newurl; newurl=$(input "Update Source" "HTTPS URL of the raw IntelShield script to self-update from:\n(published copy of this script, stable filename)" "$url") || continue
         [[ -z "$newurl" ]] && continue
         [[ "$newurl" == https://* ]] || { msg "Update Source" "Only https:// sources are accepted."; continue; }
         update_url_set "$newurl"; msg "Update Source" "Self-update source saved:\n$newurl\n\nStored in $UPDATE_CONF." ;;
      V) tail -n 400 "$MAINT_LOG" >"$IS_TMP/maintlog" 2>/dev/null || echo "(maintenance log empty)" >"$IS_TMP/maintlog"
         showfile "Maintenance Audit Log (last 400 lines)" "$IS_TMP/maintlog" 34 120 ;;
      b) return ;;
    esac
  done
}

#==============================================================================
#  HEADLESS DISPATCHER (systemd timers + scripted use)
#==============================================================================
case "${1:-}" in
  --backup)
    if out="$(do_backup)"; then echo "Snapshot written: $out"; exit 0
    else echo "Backup failed — see $LOG" >&2; exit 1; fi ;;
  --clamav-scan)
    case "${2:-}" in
      full)  clam_core_scan quarantine "Full"  / ;;
      smart) clam_core_scan quarantine "Smart" /root /home /var/www /etc /tmp /dev/shm ;;
      *) echo "usage: $0 --clamav-scan full|smart" >&2; exit 2 ;;
    esac; exit $? ;;
  --antirootkit-scan)
    preflight
    case "${2:-}" in
      rkhunter)   ark_scan_rkhunter ;;
      chkrootkit) ark_scan_chkrootkit ;;
      all)        ark_scan_all ;;
      *) echo "usage: $0 --antirootkit-scan rkhunter|chkrootkit|all" >&2; exit 2 ;;
    esac; exit $? ;;
  --preflight)        preflight; preflight_risk_engine; echo "$RISK_REPORT"; exit 0 ;;
  --state)            preflight; state_write; echo "$STATE_DB"; exit 0 ;;
  --profile)          preflight; profile_apply "${2:-}"; exit $? ;;
  --suricata-summary) preflight; suricata_export_eve_summary; exit $? ;;
  --suricata-ips)
    preflight
    case "${2:-}" in
      on|enable|ips)   suricata_ips_enable ;;
      off|disable|ids) suricata_ips_disable ;;
      *) echo "usage: $0 --suricata-ips on|off  (use with --non-interactive --yes for automation)" >&2; exit 2 ;;
    esac; exit $? ;;
  --suricata-fw)
    preflight
    case "${2:-}" in
      on|enable)  suricata_fw_enable ;;
      off|disable) suricata_fw_disable ;;
      status)      suricata_fw_status ;;
      *) echo "usage: $0 --suricata-fw on|off|status  (Suricata 8 Firewall Mode, requires Suricata 8+)" >&2; exit 2 ;;
    esac; exit $? ;;
  --sandbox)
    preflight
    case "${2:-}" in
      on|enable|apply) sandbox_apply ;;
      off|disable)     sandbox_off; echo "x-ui/Xray sandbox removed — running unconfined." ;;
      *) echo "usage: $0 --sandbox on|off  (use --sandbox off before a manual x-ui update)" >&2; exit 2 ;;
    esac; exit $? ;;
  --update)
    case "${2:-safe}" in
      safe|"") update_packages safe ;;
      full)    update_packages full ;;
      *) echo "usage: $0 --update safe|full  (never a release upgrade)" >&2; exit 2 ;;
    esac; exit $? ;;
  --auto-update)
    case "${2:-}" in
      on|enable)  update_auto_enable ;;
      off|disable) update_auto_disable ;;
      *) echo "usage: $0 --auto-update on|off  (on = auto-update + ${AUTO_REBOOT_TIME} reboot when required)" >&2; exit 2 ;;
    esac; exit $? ;;
  --maintain)
    # cron entry point — single-flight (flock), everything audited in $MAINT_LOG
    case "${2:-}" in
      os|components|self|all) maint_run "$2"; exit $? ;;
      *) echo "usage: $0 --maintain os|components|self|all" >&2; exit 2 ;;
    esac ;;
  --self-update)
    if (( NONINTERACTIVE )); then self_update_check cron; else self_update_check interactive; fi
    exit $? ;;
  --wazuh-menu)       preflight; auto_startup_backup; wazuh_menu; exit $? ;;
  --uninstall)        preflight; auto_startup_backup; uninstall_menu; exit $? ;;
esac

#==============================================================================
#  INTERACTIVE MAIN LOOP
#==============================================================================
preflight
auto_startup_backup
while :; do
  read -r _MH _MW < <(ui_size 30 100)
  _LIVE_LBL="OFF"; (( LIVE_OUTPUT )) && _LIVE_LBL="ON"
  CH=$(whiptail --backtitle "$BT" --title " IntelShield v${VERSION} - Core Operations " --default-item "${MENU_LAST[__main__]:-}" --menu \
"Host: ${OS_DESC:-?}\nSSH: ${SSH_PORT:-?}  |  NIC: ${NIC:-?}  |  IP: ${PUB_IP:-?}  |  Suricata: $(suri_mode_get|tr a-z A-Z)  |  FW: $(suricata_fw_mode_get)  |  Profile: $(cat "$PROFILE_FILE" 2>/dev/null || echo none)" \
"$_MH" "$_MW" $((_MH-12)) \
1  "Guided automated hardening run" \
2  "Select individual modules" \
3  "Profiles / production modes" \
4  "Preflight risk engine" \
5  "State database view" \
6  "CrowdSec management" \
7  "UFW firewall management" \
8  "ClamAV antivirus management" \
9  "Suricata IDS/IPS intelligence" \
10 "Anti-rootkit defense" \
11 "Wazuh SIEM / XDR integration" \
12 "Advanced forensics engine" \
13 "Performance / kernel tuning" \
14 "Backup / restore snapshots" \
15 "Status / diagnostics" \
16 "View IntelShield log" \
17 "Component control center (enable/disable modules)" \
U  "Update center (system / firmware / drivers / auto-update)" \
M  "Maintenance engine (scheduled updates + self-update): $(maint_cron_status)" \
S  "x-ui / Xray sandbox control (on/off for manual updates)" \
L  "Live console output: ${_LIVE_LBL}  (watch commands run in real time)" \
18 "Uninstall / revert safely" \
19 "Exit" 3>&1 1>&2 2>&3)
  case "$?" in 1|255) break ;; esac
  [[ -n "$CH" ]] && MENU_LAST[__main__]="$CH"
  case "$CH" in
    1)  guided ;;
    2)  select_modules ;;
    3)  profiles_menu ;;
    4)  preflight_risk_engine ;;
    5)  state_view ;;
    6)  crowdsec_menu ;;
    7)  ufw_menu ;;
    8)  clamav_menu ;;
    9)  suricata_intel_menu ;;
    10) anti_rootkit_menu ;;
    11) wazuh_menu ;;
    12) forensics_menu ;;
    13) performance_menu ;;
    14) backup_menu ;;
    15) status ;;
    16) showfile "IntelShield Operations Log" "$LOG" ;;
    17) component_menu ;;
    U)  update_center_menu ;;
    M)  maintenance_menu ;;
    S)  sandbox_menu ;;
    L)  if (( LIVE_OUTPUT )); then LIVE_OUTPUT=0; echo off >"$LIVE_FILE" 2>/dev/null
        else LIVE_OUTPUT=1; echo on >"$LIVE_FILE" 2>/dev/null; fi
        msg "Live Console" "Live command output is now $([[ "$LIVE_OUTPUT" == 1 ]] && echo ON || echo OFF).\n\nWhen ON, IntelShield prints each command it runs and streams the real output to this terminal (still saved to $LOG), so you can watch installs, scans and config steps happen live.\n\nWhen OFF, actions show tidy progress boxes only. The setting is remembered." ;;
    18) uninstall_menu ;;
    19) break ;;
  esac
done
clear
echo "IntelShield session closed."
echo "  Log     : $LOG"
echo "  State   : $STATE_DB"
echo "  Backups : $BACKUP_DIR"
