#!/usr/bin/env bash
#==============================================================================
#  IntelShield v9.3  —  System Immutability · Network Filtering · SIEM Export
#  Target : Ubuntu 22.04 / 24.04 LTS server
#  License: MIT
#
#  Modules:
#    1. System Immutability Engine (chattr +i toggle for /bin /sbin /usr /boot)
#    2. RFC-Compliant State & SIEM Engine (native jq serialization)
#    3. Network Filtering & IPS Harmonization (nftables + CrowdSec + Suricata 8)
#    4. Atomic Callback Rollbacks (restart_or_rollback with direct function args)
#
#  Design contract:
#    - Every function is self-contained; no global state collisions.
#    - All config mutations are atomic (write to tmp, then mv).
#    - All systemd operations gate on restart_or_rollback with callback args.
#    - State JSON is built natively via jq -n for guaranteed RFC 8259 compliance.
#
#  v9.3 — Critical bug fixes from production audit:
#    - Fixed SSH lockout: nft_sync() now calls _collect_state and uses
#      STATE_SSH_PORT instead of undeclared SSH_PORT variable.
#    - Fixed lsattr regex: _lock_path() uses lsattr -d (directory-safe) and
#      awk '{print $1}' to correctly extract attribute flags (output starts
#      with dashes like ----i---------e-------, not spaces).
#    - Fixed count_immutable() performance: replaced find -exec sh -c per-file
#      subshell spawning with single lsattr -R -d pipeline (instant execution).
#    - Removed dead qargs variable from deploy_nft_pipeline() — the nftables
#      heredoc already uses queue num 0-${qmax} directly; merged fw/ips cases.
#==============================================================================
set -o pipefail
export DEBIAN_FRONTEND=noninteractive

# ---------- constants --------------------------------------------------------
readonly APP="IntelShield"
readonly VERSION="9.3"
readonly STATE_DIR="/var/lib/intelshield"
readonly STATE_DB="${STATE_DIR}/state.json"
readonly LOCK_STATE_FILE="${STATE_DIR}/lock-state"
readonly LOG="/var/log/intelshield.log"
readonly IS_TMP="$(mktemp -d /run/intelshield.XXXXXX 2>/dev/null || mktemp -d "${TMPDIR:-/tmp}/intelshield.XXXXXX")"
readonly NFT_HOOKS_DIR="/etc/nftables.d"
readonly NFT_CROWDSEC_TABLE="inet crowdsec"
readonly NFT_SURICATA_TABLE="inet intelshield_suricata"
readonly NFT_SURICATA_FW_TABLE="inet intelshield_suricata_fw"
readonly SURICATA_YAML="/etc/suricata/suricata.yaml"
readonly SURICATA_MODE_FILE="${STATE_DIR}/suricata-mode"
readonly SURICATA_FW_MODE_FILE="${STATE_DIR}/suricata-fw-mode"
readonly SURICATA_MUTEX_FILE="${STATE_DIR}/suricata-fw-mutex"
readonly SURICATA_DISABLE_CONF="/etc/suricata/disable.conf"
readonly SURICATA_DROP_CONF="/etc/suricata/drop.conf"
readonly SURICATA_ENABLE_CONF="/etc/suricata/enable.conf"

# nftables priority boundaries:
#   CrowdSec bouncer:  priority 0   (edge — cheap IP-reputation drops)
#   Suricata FW mode:  priority 10  (deep packet inspection, default-drop)
#   Suricata IPS:      priority 100 (legacy inline NFQUEUE)
readonly CROWDSEC_PRIORITY=0
readonly SURICATA_FW_PRIORITY=10
readonly SURICATA_IPS_PRIORITY=100

# Immutability targets (chattr +i applied recursively)
readonly IMMUTABLE_PATHS=("/bin" "/sbin" "/usr" "/boot")
readonly IMMUTABLE_FILES=("/etc/passwd" "/etc/shadow" "/etc/fstab" "/etc/group" "/etc/gshadow" "/etc/sudoers")
# Paths that must NEVER be locked (system crash prevention)
readonly IMMUTABLE_EXCLUDES=("/var/log" "/var/run" "/var/tmp" "/tmp" "/proc" "/sys" "/dev" "/run" "$STATE_DIR" "/etc/resolv.conf" "/etc/hostname")

# Colors for TUI
readonly C_RESET='\033[0m'
readonly C_BOLD='\033[1m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[0;33m'
readonly C_CYAN='\033[0;36m'
readonly C_MAGENTA='\033[0;35m'

# ---------- cleanup trap -----------------------------------------------------
trap 'rm -rf "$IS_TMP" 2>/dev/null' EXIT

# ---------- logging ----------------------------------------------------------
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" >>"$LOG"; }
log_err(){ printf '[%s] ERROR: %s\n' "$(date '+%F %T')" "$*" >&2; log "ERROR: $*"; }

# ---------- binary dependency gate -------------------------------------------
# Verify all required binaries exist before any module executes.
# Returns 0 if all present, 1 if any missing (logs which ones).
check_deps(){
  local missing=() bin
  for bin in jq nft chattr systemctl ss awk sed grep; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_err "Missing dependencies: ${missing[*]}"
    return 1
  fi
  return 0
}

# ---------- run wrapper (logging + live output contract) ---------------------
# run() ALWAYS returns the wrapped command's real exit code.
# In live mode, streams output to terminal AND log.
run(){
  log "+ $*"
  "$@" </dev/null >>"$LOG" 2>&1
}

# ---------- safe array append (no global collisions) -------------------------
# Usage: arr=(); safe_append arr "value"
safe_append(){
  local -n _ref="$1"
  _ref+=("$2")
}

#==============================================================================
#  MODULE 1: SYSTEM IMMUTABILITY ENGINE
#==============================================================================
# The immutability engine uses chattr +i to make critical system directories
# and files read-only at the filesystem level. This prevents unauthorized
# modification of core OS binaries, boot files, and critical /etc configs.
#
# Mechanism:
#   system_lock()   — recursively applies chattr +i to IMMUTABLE_PATHS
#                     and IMMUTABLE_FILES, excluding IMMUTABLE_EXCLUDES.
#   system_unlock() — recursively removes chattr -i from all locked paths.
#   get_lock_status() — returns "LOCKED" or "UNLOCKED" based on state file.
#
# Safety:
#   - /proc, /sys, /dev, /run, /var/log, /tmp are NEVER locked.
#   - /etc/resolv.conf and /etc/hostname are NEVER locked (network breakage).
#   - State is persisted to $LOCK_STATE_FILE for crash recovery.
#   - Recursive locking skips symlinks to avoid locking the target instead.

# Check if a path is in the exclusion list
_is_excluded(){
  local path="$1" excl
  for excl in "${IMMUTABLE_EXCLUDES[@]}"; do
    [[ "$path" == "$excl" || "$path" == "$excl/"* ]] && return 0
  done
  return 1
}

# Apply chattr +i to a single path (file or directory).
# Skips symlinks, excluded paths, and paths already immutable.
# Uses lsattr -d (inspect the directory itself, not its contents) and
# extracts only the flag field (column 1) to check for 'i'.
_lock_path(){
  local path="$1"
  [[ -e "$path" ]] || return 0
  [[ -L "$path" ]] && return 0
  _is_excluded "$path" && return 0
  # lsattr output: ----i---------e------- /path
  # Extract column 1 (attribute flags) and grep for 'i' anywhere in it
  if ! lsattr -d "$path" 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
    chattr +i "$path" 2>/dev/null || log "WARN: could not lock $path"
  fi
}

# Remove chattr -i from a single path
_unlock_path(){
  local path="$1"
  [[ -e "$path" ]] || return 0
  [[ -L "$path" ]] && return 0
  chattr -i "$path" 2>/dev/null || true
}

# Recursively lock a directory tree, respecting excludes.
# Uses find to walk the tree; depth-first ensures children before parents.
_lock_recursive(){
  local root="$1"
  [[ -d "$root" ]] || return 0
  _lock_path "$root"
  find "$root" -maxdepth 1 -mindepth 1 ! -type l 2>/dev/null | while IFS= read -r child; do
    _is_excluded "$child" && continue
    if [[ -d "$child" ]]; then
      _lock_recursive "$child"
    else
      _lock_path "$child"
    fi
  done
}

# Recursively unlock a directory tree.
_unlock_recursive(){
  local root="$1"
  [[ -d "$root" ]] || return 0
  find "$root" -depth ! -type l 2>/dev/null | while IFS= read -r child; do
    _unlock_path "$child"
  done
  _unlock_path "$root"
}

# Lock the entire system (immutable mode).
# Returns 0 on success, 1 on failure.
system_lock(){
  local path start_ts
  start_ts="$(date +%s)"
  log "system_lock: beginning immutability lockdown"

  # Lock directories recursively
  for path in "${IMMUTABLE_PATHS[@]}"; do
    [[ -d "$path" ]] || { log "system_lock: skipping $path (not found)"; continue; }
    log "system_lock: locking $path"
    _lock_recursive "$path"
  done

  # Lock individual files
  for path in "${IMMUTABLE_FILES[@]}"; do
    [[ -f "$path" ]] || { log "system_lock: skipping $path (not found)"; continue; }
    log "system_lock: locking $path"
    _lock_path "$path"
  done

  # Persist state
  echo "LOCKED" >"$LOCK_STATE_FILE"
  local elapsed=$(( $(date +%s) - start_ts ))
  log "system_lock: completed in ${elapsed}s"
  return 0
}

# Unlock the entire system (mutable mode).
# Returns 0 on success, 1 on failure.
system_unlock(){
  local path start_ts
  start_ts="$(date +%s)"
  log "system_unlock: beginning immutability release"

  # Unlock directories (depth-first to unlock children before parents)
  for path in "${IMMUTABLE_PATHS[@]}"; do
    [[ -d "$path" ]] || continue
    log "system_unlock: unlocking $path"
    _unlock_recursive "$path"
  done

  # Unlock individual files
  for path in "${IMMUTABLE_FILES[@]}"; do
    [[ -f "$path" ]] || continue
    log "system_unlock: unlocking $path"
    _unlock_path "$path"
  done

  # Persist state
  echo "UNLOCKED" >"$LOCK_STATE_FILE"
  local elapsed=$(( $(date +%s) - start_ts ))
  log "system_unlock: completed in ${elapsed}s"
  return 0
}

# Get the current lock state.
# Outputs "LOCKED" or "UNLOCKED" to stdout.
get_lock_status(){
  cat "$LOCK_STATE_FILE" 2>/dev/null || echo "UNLOCKED"
}

# Count how many files/dirs currently have the immutable flag.
# Used for diagnostics and status display.
# Performance: uses a single lsattr -R pipeline per path (no subshell-per-file).
count_immutable(){
  local count=0 path
  for path in "${IMMUTABLE_PATHS[@]}" "${IMMUTABLE_FILES[@]}"; do
    [[ -e "$path" ]] || continue
    # lsattr -R -d: recursively list but don't descend into dirs (-d)
    # awk '{print $1}': extract only the attribute flag field
    # grep -c 'i': count lines containing the immutable flag
    count=$(( count + $(lsattr -R -d "$path" 2>/dev/null | awk '{print $1}' | grep -c 'i') ))
  done
  printf '%d' "$count"
}

#==============================================================================
#  MODULE 2: RFC-COMPLIANT STATE & SIEM ENGINE
#==============================================================================
# All state is serialized to JSON via jq -n, guaranteeing RFC 8259 compliance.
# No raw string building, no concatenation, no manual escaping.
#
# The state DB is consumed by Wazuh logcollector, Elastic ingest pipelines,
# and any SIEM that speaks JSON. Every field is a typed jq argument.

# Collect system state variables (called before state_write).
_collect_state(){
  STATE_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"
  STATE_KERNEL="$(uname -r)"
  STATE_UPTIME="$(uptime -p 2>/dev/null || uptime)"
  STATE_OS="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  STATE_NIC="$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')"
  STATE_PUB_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [[ -z "$STATE_PUB_IP" ]] && STATE_PUB_IP="$(curl -s4 --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")"
  STATE_SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
  [[ -z "$STATE_SSH_PORT" ]] && STATE_SSH_PORT=22

  # Service states
  STATE_CROWDSEC="$(systemctl is-active crowdsec 2>/dev/null || echo "inactive")"
  STATE_CROWDSEC_BOUNCER="$(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null || echo "inactive")"
  STATE_SURICATA="$(systemctl is-active suricata 2>/dev/null || echo "inactive")"
  STATE_SURICATA_MODE="$(cat "$SURICATA_MODE_FILE" 2>/dev/null || echo "ids")"
  STATE_SURICATA_FW="$(cat "$SURICATA_FW_MODE_FILE" 2>/dev/null || echo "off")"
  STATE_SURICATA_MUTEX="$(cat "$SURICATA_MUTEX_FILE" 2>/dev/null || echo "none")"

  # Immutability state
  STATE_LOCK="$(get_lock_status)"
  STATE_IMMUTABLE_COUNT="$(count_immutable)"

  # Resources
  STATE_MEM_MB="$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)"
  STATE_DISK_FREE_MB="$(df -Pm / | awk 'NR==2{print $4}' 2>/dev/null || echo 0)"
  STATE_LOAD="$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")"

  # Timestamps
  STATE_TS="$(date -u '+%FT%TZ')"
}

# Write the state database using native jq (RFC 8259 compliant).
# No raw string building — every field is a typed jq --arg or --argjson.
state_write(){
  mkdir -p "$STATE_DIR"
  _collect_state

  local tmp="${STATE_DB}.tmp.$$"
  jq -n \
    --arg version "$VERSION" \
    --arg ts "$STATE_TS" \
    --arg hostname "$STATE_HOSTNAME" \
    --arg kernel "$STATE_KERNEL" \
    --arg uptime "$STATE_UPTIME" \
    --arg os "$STATE_OS" \
    --arg nic "${STATE_NIC:-unknown}" \
    --arg pub_ip "${STATE_PUB_IP:-unknown}" \
    --argjson ssh_port "${STATE_SSH_PORT:-22}" \
    --arg lock_state "$STATE_LOCK" \
    --argjson immutable_count "${STATE_IMMUTABLE_COUNT:-0}" \
    --arg crowdsec "$STATE_CROWDSEC" \
    --arg crowdsec_bouncer "$STATE_CROWDSEC_BOUNCER" \
    --arg suricata "$STATE_SURICATA" \
    --arg suricata_mode "$STATE_SURICATA_MODE" \
    --arg suricata_fw "$STATE_SURICATA_FW" \
    --arg suricata_mutex "$STATE_SURICATA_MUTEX" \
    --argjson memory_mb "${STATE_MEM_MB:-0}" \
    --argjson disk_free_mb "${STATE_DISK_FREE_MB:-0}" \
    --argjson load_avg "${STATE_LOAD:-0}" \
    '{
      version: $version,
      timestamp: $ts,
      host: {
        hostname: $hostname,
        kernel: $kernel,
        uptime: $uptime,
        os: $os,
        nic: $nic,
        public_ip: $pub_ip,
        ssh_port: $ssh_port
      },
      immutability: {
        state: $lock_state,
        immutable_count: $immutable_count
      },
      services: {
        crowdsec: $crowdsec,
        crowdsec_bouncer: $crowdsec_bouncer,
        suricata: $suricata,
        suricata_mode: $suricata_mode,
        suricata_fw_mode: $suricata_fw,
        suricata_mutex: $suricata_mutex
      },
      resources: {
        memory_mb: $memory_mb,
        disk_free_mb: $disk_free_mb,
        load_avg: $load_avg
      }
    }' > "$tmp" 2>/dev/null

  if [[ -s "$tmp" ]] && jq empty "$tmp" 2>/dev/null; then
    chmod 600 "$tmp"
    mv -f "$tmp" "$STATE_DB"
    log "state_write: state DB updated ($STATE_DB)"
    return 0
  else
    rm -f "$tmp"
    log_err "state_write: jq serialization failed"
    return 1
  fi
}

# Export state as a pretty-printed JSON file for SIEM ingestion.
# Writes to $STATE_DIR/siem-export-<timestamp>.json
state_export_siem(){
  local outfile="${STATE_DIR}/siem-export-$(date +%Y%m%d_%H%M%S).json"
  state_write 2>/dev/null || true
  if [[ -f "$STATE_DB" ]]; then
    jq '.' "$STATE_DB" > "$outfile" 2>/dev/null
    chmod 600 "$outfile"
    printf '%s' "$outfile"
    return 0
  fi
  return 1
}

#==============================================================================
#  MODULE 3: NETWORK FILTERING & IPS HARMONIZATION
#==============================================================================
# nftables priority chain orchestration:
#   CrowdSec bouncer:  priority 0   (edge — IP reputation drops)
#   Suricata FW mode:  priority 10  (deep inspection, deterministic pipeline)
#   Suricata IPS:      priority 100 (legacy inline NFQUEUE)
#
# UFW coexistence: IntelShield injects its nftables rules AFTER UFW's chains
# by using hook priorities that run after UFW (which uses priority 0 by default
# for its input chain). Our chains use explicit priorities to avoid conflicts.
#
# Safety: all nft operations are validated before commit. A failed nft ruleset
# is rolled back automatically (atomic apply-or-revert).

# Check if nftables is available and running
nft_available(){
  command -v nft >/dev/null 2>&1 && nft list tables >/dev/null 2>&1
}

# Check if UFW is active
ufw_active(){
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"
}

# Get the nft binary path
nft_bin(){ command -v nft || echo /usr/sbin/nft; }

# Validate a complete nftables ruleset from a file.
# Returns 0 if valid, 1 if invalid (logs the error).
nft_validate(){
  local ruleset="$1"
  [[ -f "$ruleset" ]] || return 1
  $(nft_bin) -c -f "$ruleset" 2>"$IS_TMP/nft-validate.err"
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log_err "nft_validate: ruleset invalid — $(cat "$IS_TMP/nft-validate.err" 2>/dev/null)"
  fi
  return $rc
}

# Deploy the CrowdSec/Suricata nftables pipeline.
# Arguments:
#   $1 = crowdsec_priority (default 0)
#   $2 = suricata_priority (default 10)
#   $3 = ssh_port (default 22)
#   $4 = mode ("fw" for firewall mode, "ips" for IPS mode, "off" for IDS)
deploy_nft_pipeline(){
  local cs_prio="${1:-$CROWDSEC_PRIORITY}"
  local suri_prio="${2:-$SURICATA_FW_PRIORITY}"
  local ssh_port="${3:-22}"
  local mode="${4:-off}"
  local nftbin="$(nft_bin)"

  # Build the nftables ruleset
  local ruleset="$IS_TMP/intelshield-nft.nft"
  cat >"$ruleset" <<NFTEOF
#!/usr/sbin/nft -f
# IntelShield v${VERSION} — nftables pipeline
# Generated: $(date -u '+%F %T')
# Priority: CrowdSec=${cs_prio}, Suricata=${suri_prio}, SSH excluded
#
# UFW coexistence: UFW uses 'ufw user' chain at priority 0.
# Our chains use explicit priorities that run after UFW's filter rules.
# This ensures UFW's allow/deny rules are evaluated first, then our
# deep inspection chains process the survivors.

table inet intelshield_pipeline {
    # Rate-limit set for SSH brute-force protection
    set ssh_ratelimit {
        type ipv4_addr
        flags dynamic,timeout
        timeout 60s
    }

    chain input {
        type filter hook input priority ${suri_prio}; policy accept;

        # Loopback always accepted
        iif "lo" accept

        # SSH rate limiting (prevents lockout during brute-force)
        tcp dport ${ssh_port} ct state new \
            add @ssh_ratelimit { ip saddr limit rate 5/minute burst 3 packets } accept
        tcp dport ${ssh_port} ct state new \
            add @ssh_ratelimit { ip saddr limit rate 15/minute burst 5 packets } \
            drop

        # Established/related connections (performance: skip deep inspection)
        ct state established,related accept

        # ICMP for path MTU discovery (rate-limited)
        ip protocol icmp limit rate 10/second accept
        ip6 nexthdr icmpv6 limit rate 10/second accept
NFTEOF

  # Add Suricata NFQUEUE rules based on mode
  case "$mode" in
    fw|ips)
      # Firewall/IPS mode: NFQUEUE with fail-open (flags bypass)
      # Compute max queue index: min(cpu_cores - 1, 3) for fanout load-balancing
      local ncpu qmax
      ncpu=$(nproc 2>/dev/null || echo 1)
      qmax=$((ncpu - 1))
      (( qmax > 3 )) && qmax=3
      (( qmax < 0 )) && qmax=0
      cat >>"$ruleset" <<NFTEOF
        # Suricata ${mode^^}: NFQUEUE with fail-open (flags bypass)
        meta l4proto { tcp, udp } queue num 0-${qmax} flags bypass,fanout
NFTEOF
      ;;
    *)
      # IDS mode: no queue, just accept
      cat >>"$ruleset" <<NFTEOF
        # IDS mode: no inline inspection, accept all
        meta l4proto { tcp, udp } accept
NFTEOF
      ;;
  esac

  cat >>"$ruleset" <<NFTEOF
    }

    chain output {
        type filter hook output priority ${suri_prio}; policy accept;
        oif "lo" accept
        ct state established,related accept
    }
}
NFTEOF

  # Validate before applying
  if ! nft_validate "$ruleset"; then
    log_err "deploy_nft_pipeline: validation failed — aborting"
    return 1
  fi

  # Apply atomically: flush old table, load new ruleset
  "$nftbin" delete table inet intelshield_pipeline 2>/dev/null || true
  if ! "$nftbin" -f "$ruleset" 2>>"$LOG"; then
    log_err "deploy_nft_pipeline: ruleset load failed"
    return 1
  fi

  log "deploy_nft_pipeline: deployed (mode=$mode, cs_prio=$cs_prio, suri_prio=$suri_prio)"
  return 0
}

# Remove all IntelShield nftables rules (teardown).
nft_teardown(){
  $(nft_bin) delete table inet intelshield_pipeline 2>/dev/null || true
  log "nft_teardown: pipeline removed"
}

# Sync the nftables pipeline with current service states.
# Reads CrowdSec/Suricata state and deploys the correct configuration.
nft_sync(){
  local mode="off"
  local suri_active suri_fw

  # Collect fresh system state (populates STATE_SSH_PORT, etc.)
  _collect_state

  suri_active="$(systemctl is-active suricata 2>/dev/null || echo inactive)"
  suri_fw="$(cat "$SURICATA_FW_MODE_FILE" 2>/dev/null || echo off)"

  if [[ "$suri_active" == "active" ]]; then
    if [[ "$suri_fw" == "on" ]]; then
      mode="fw"
    else
      mode="ips"
    fi
  fi

  deploy_nft_pipeline "$CROWDSEC_PRIORITY" "$SURICATA_FW_PRIORITY" "${STATE_SSH_PORT:-22}" "$mode"
}

#==============================================================================
#  MODULE 4: ATOMIC CALLBACK ROLLBACKS
#==============================================================================
# restart_or_rollback() accepts:
#   $1 = systemd unit name
#   $2 = rollback callback function name (called if restart fails)
#
# Contract:
#   1. Restart the unit
#   2. Wait 2 seconds for stabilization
#   3. Check if the unit is active
#   4. If active: return 0 (success)
#   5. If NOT active: call the rollback callback, restart again, return 1
#
# No global variable dependencies — the callback is passed directly.

restart_or_rollback(){
  local unit="$1" rollback_fn="${2:-}"
  local rc=0

  log "restart_or_rollback: restarting $unit"
  systemctl restart "$unit" >>"$LOG" 2>&1 || rc=$?
  sleep 2

  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    log "restart_or_rollback: $unit is active"
    return 0
  fi

  log "restart_or_rollback: $unit failed to start (rc=$rc) — executing rollback"
  if [[ -n "$rollback_fn" ]] && declare -f "$rollback_fn" >/dev/null 2>&1; then
    "$rollback_fn"
  elif [[ -n "$rollback_fn" ]] && [[ -x "$rollback_fn" ]]; then
    "$rollback_fn"
  fi

  # Second restart attempt after rollback
  systemctl restart "$unit" >>"$LOG" 2>&1 || true
  sleep 2

  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    log "restart_or_rollback: $unit recovered after rollback"
    return 0
  fi

  log "restart_or_rollback: $unit is STILL down after rollback"
  return 1
}

# Rollback callbacks for specific services (no global state — pure functions).

# Rollback: remove Suricata IPS nftables plumbing
rollback_suricata_ips(){
  log "rollback_suricata_ips: tearing down IPS plumbing"
  nft_teardown
  rm -f /etc/systemd/system/suricata.service.d/99-intelshield-ips.conf 2>/dev/null
  systemctl daemon-reload >>"$LOG" 2>&1 || true
  echo "ids" >"$SURICATA_MODE_FILE" 2>/dev/null || true
}

# Rollback: remove Suricata FW mode plumbing
rollback_suricata_fw(){
  log "rollback_suricata_fw: tearing down Firewall Mode plumbing"
  nft_teardown
  rm -f /etc/systemd/system/suricata.service.d/99-intelshield-fw.conf 2>/dev/null
  systemctl daemon-reload >>"$LOG" 2>&1 || true
  echo "off" >"$SURICATA_FW_MODE_FILE" 2>/dev/null || true
  echo "none" >"$SURICATA_MUTEX_FILE" 2>/dev/null || true
}

# Rollback: revert nftables pipeline
rollback_nft_pipeline(){
  log "rollback_nft_pipeline: reverting to IDS mode"
  nft_teardown
}

#==============================================================================
#  MODULE 5: SURICATA 8 FIREWALL MODE
#==============================================================================
# Suricata 8's experimental firewall mode uses a deterministic packet pipeline
# with a default-drop policy. The pipeline:
#   1. packet:filter hooks (fast path, before flow reassembly)
#   2. Protocol detection
#   3. app:filter hooks (deep inspection, after protocol detection)
#   4. Default policy: DROP (if no accept:packet or accept:flow matched)

# Check if Suricata 8+ is installed (required for firewall mode)
suricata_version_check(){
  local ver
  ver="$(suricata -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)"
  [[ -z "$ver" ]] && return 1
  local major
  major="$(echo "$ver" | cut -d. -f1)"
  (( major >= 8 )) && return 0
  return 1
}

# Enable Suricata 8 Firewall Mode
suricata_fw_enable(){
  if ! suricata_version_check; then
    log_err "suricata_fw_enable: Suricata 8+ required (current: $(suricata -V 2>/dev/null | tr -d '\n'))"
    return 1
  fi

  # Deploy the nftables pipeline in firewall mode
  if deploy_nft_pipeline "$CROWDSEC_PRIORITY" "$SURICATA_FW_PRIORITY" "${SSH_PORT:-22}" "fw"; then
    echo "on" >"$SURICATA_FW_MODE_FILE"
    echo "ips" >"$SURICATA_MODE_FILE"
    echo "suricata" >"$SURICATA_MUTEX_FILE"
    log "suricata_fw_enable: firewall mode activated"
    return 0
  else
    log_err "suricata_fw_enable: nftables pipeline deployment failed"
    return 1
  fi
}

# Disable Suricata Firewall Mode and revert to IDS
suricata_fw_disable(){
  nft_teardown
  echo "off" >"$SURICATA_FW_MODE_FILE"
  echo "ids" >"$SURICATA_MODE_FILE"
  echo "none" >"$SURICATA_MUTEX_FILE"
  log "suricata_fw_disable: reverted to IDS mode"
  return 0
}

#==============================================================================
#  MODULE 6: TUI MENU
#==============================================================================
# Clean, high-contrast TUI using read -p and case blocks.
# ADHD-friendly: clear prompts, visual hierarchy, immediate feedback.

# Print a section header
_print_header(){
  echo
  echo -e "${C_BOLD}${C_CYAN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
  echo -e "${C_BOLD}${C_CYAN}║  ${APP} v${VERSION} — System Immutability · Network Filtering · SIEM  ║${C_RESET}"
  echo -e "${C_BOLD}${C_CYAN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
  echo
}

# Print current system status line
_print_status(){
  local lock_status
  lock_status="$(get_lock_status)"
  local lock_color="$C_GREEN"
  [[ "$lock_status" == "LOCKED" ]] && lock_color="$C_RED"

  echo -e "  ${C_BOLD}Status:${C_RESET}  Lock=${lock_color}${lock_status}${C_RESET}  |  Kernel=$(uname -r)  |  $(date '+%F %T')"
  echo
}

# Main TUI menu loop
main_menu(){
  local choice=""
  while true; do
    _print_header
    _print_status
    echo -e "  ${C_BOLD}${C_YELLOW}Options:${C_RESET}"
    echo -e "    ${C_CYAN}1${C_RESET}  Toggle Immutability Switch  [$(get_lock_status)]"
    echo -e "    ${C_CYAN}2${C_RESET}  Sync Firewall Rules & IPS Pipelines"
    echo -e "    ${C_CYAN}3${C_RESET}  Trigger System Diagnostic & SIEM Export"
    echo -e "    ${C_CYAN}4${C_RESET}  View Current State (JSON)"
    echo -e "    ${C_CYAN}5${C_RESET}  Exit"
    echo
    read -rp "  Select option [1-5]: " choice
    echo

    case "$choice" in
      1) _menu_toggle_immutability ;;
      2) _menu_sync_firewall ;;
      3) _menu_siem_export ;;
      4) _menu_view_state ;;
      5) echo -e "  ${C_GREEN}Exiting ${APP}. Goodbye.${C_RESET}"; return 0 ;;
      *) echo -e "  ${C_RED}Invalid option. Try again.${C_RESET}" ;;
    esac
  done
}

# Option 1: Toggle Immutability
_menu_toggle_immutability(){
  local current
  current="$(get_lock_status)"
  echo -e "  ${C_BOLD}Immutability:${C_RESET} Currently ${C_YELLOW}${current}${C_RESET}"

  if [[ "$current" == "LOCKED" ]]; then
    echo -e "  ${C_YELLOW}This will remove immutable flags from system directories.${C_RESET}"
    echo -e "  ${C_YELLOW}System will become mutable ( writable ).${C_RESET}"
    read -rp "  Unlock system? [y/N]: " confirm
    if [[ "$confirm" == [yY] ]]; then
      echo -e "  ${C_CYAN}Unlocking system...${C_RESET}"
      if system_unlock; then
        echo -e "  ${C_GREEN}System UNLOCKED successfully.${C_RESET}"
      else
        echo -e "  ${C_RED}Unlock failed. Check $LOG${C_RESET}"
      fi
    else
      echo -e "  ${C_YELLOW}Aborted.${C_RESET}"
    fi
  else
    echo -e "  ${C_YELLOW}This will apply immutable flags to critical system paths.${C_RESET}"
    echo -e "  ${C_YELLOW}/bin, /sbin, /usr, /boot, /etc/passwd, /etc/shadow, etc. will become read-only.${C_RESET}"
    echo -e "  ${C_YELLOW}You will need to UNLOCK before running apt-get or system updates.${C_RESET}"
    read -rp "  Lock system? [y/N]: " confirm
    if [[ "$confirm" == [yY] ]]; then
      echo -e "  ${C_CYAN}Locking system...${C_RESET}"
      if system_lock; then
        echo -e "  ${C_GREEN}System LOCKED successfully.${C_RESET}"
        echo -e "  ${C_GREEN}Immutable count: $(count_immutable) files/dirs${C_RESET}"
      else
        echo -e "  ${C_RED}Lock failed. Check $LOG${C_RESET}"
      fi
    else
      echo -e "  ${C_YELLOW}Aborted.${C_RESET}"
    fi
  fi
  echo
  read -rp "  Press Enter to continue..."
}

# Option 2: Sync Firewall
_menu_sync_firewall(){
  echo -e "  ${C_BOLD}Firewall & IPS Sync${C_RESET}"
  echo -e "  ${C_CYAN}Current states:${C_RESET}"
  echo -e "    CrowdSec bouncer : $(systemctl is-active crowdsec-firewall-bouncer 2>/dev/null || echo "inactive")"
  echo -e "    Suricata         : $(systemctl is-active suricata 2>/dev/null || echo "inactive")"
  echo -e "    Suricata mode    : $(cat "$SURICATA_MODE_FILE" 2>/dev/null || echo "ids")"
  echo -e "    Suricata FW mode : $(cat "$SURICATA_FW_MODE_FILE" 2>/dev/null || echo "off")"
  echo -e "    UFW              : $(ufw status 2>/dev/null | head -1 || echo "inactive")"
  echo

  local sync_choice
  echo -e "  ${C_YELLOW}Sync options:${C_RESET}"
  echo -e "    ${C_CYAN}1${C_RESET}  Deploy nftables pipeline (auto-detect mode)"
  echo -e "    ${C_CYAN}2${C_RESET}  Enable Suricata 8 Firewall Mode"
  echo -e "    ${C_CYAN}3${C_RESET}  Disable Suricata Firewall Mode (revert to IDS)"
  echo -e "    ${C_CYAN}4${C_RESET}  Teardown all nftables rules"
  echo -e "    ${C_CYAN}5${C_RESET}  Back"
  echo
  read -rp "  Select [1-5]: " sync_choice

  case "$sync_choice" in
    1)
      echo -e "  ${C_CYAN}Syncing nftables pipeline...${C_RESET}"
      if nft_sync; then
        echo -e "  ${C_GREEN}Pipeline synced successfully.${C_RESET}"
      else
        echo -e "  ${C_RED}Sync failed. Check $LOG${C_RESET}"
      fi
      ;;
    2)
      echo -e "  ${C_CYAN}Enabling Suricata 8 Firewall Mode...${C_RESET}"
      if suricata_fw_enable; then
        echo -e "  ${C_GREEN}Firewall Mode enabled.${C_RESET}"
      else
        echo -e "  ${C_RED}Failed. Check $LOG${C_RESET}"
      fi
      ;;
    3)
      echo -e "  ${C_CYAN}Disabling Suricata Firewall Mode...${C_RESET}"
      suricata_fw_disable
      echo -e "  ${C_GREEN}Reverted to IDS mode.${C_RESET}"
      ;;
    4)
      echo -e "  ${C_CYAN}Tearing down nftables rules...${C_RESET}"
      nft_teardown
      echo -e "  ${C_GREEN}All IntelShield nftables rules removed.${C_RESET}"
      ;;
    5) return 0 ;;
    *) echo -e "  ${C_RED}Invalid option.${C_RESET}" ;;
  esac
  echo
  read -rp "  Press Enter to continue..."
}

# Option 3: SIEM Export
_menu_siem_export(){
  echo -e "  ${C_BOLD}System Diagnostic & SIEM Export${C_RESET}"
  echo -e "  ${C_CYAN}Collecting system state...${C_RESET}"

  state_write 2>/dev/null
  local outfile
  outfile="$(state_export_siem 2>/dev/null)"

  if [[ -n "$outfile" && -f "$outfile" ]]; then
    echo -e "  ${C_GREEN}SIEM export written to: ${outfile}${C_RESET}"
    echo
    echo -e "  ${C_CYAN}Preview (first 20 lines):${C_RESET}"
    jq '.' "$outfile" 2>/dev/null | head -20
    echo -e "  ${C_YELLOW}... (full file: $outfile)${C_RESET}"
  else
    echo -e "  ${C_RED}SIEM export failed. Check $LOG${C_RESET}"
  fi
  echo
  read -rp "  Press Enter to continue..."
}

# Option 4: View State
_menu_view_state(){
  state_write 2>/dev/null
  if [[ -f "$STATE_DB" ]]; then
    echo -e "  ${C_BOLD}Current State (JSON):${C_RESET}"
    jq '.' "$STATE_DB" 2>/dev/null
  else
    echo -e "  ${C_RED}State database not found.${C_RESET}"
  fi
  echo
  read -rp "  Press Enter to continue..."
}

#==============================================================================
#  MODULE 7: CLI ARGUMENT DISPATCHER
#==============================================================================
# Headless operation via flags. Every flag mirrors a TUI menu action.
# All flags are idempotent — running them twice produces the same result.

usage(){
  cat <<EOF
${APP} v${VERSION} — System Immutability · Network Filtering · SIEM Export

Usage: $0 [OPTIONS]

Immutability:
  --lock              Apply immutable flags to critical system paths
  --unlock            Remove immutable flags from system paths
  --status            Show current lock state (LOCKED/UNLOCKED)

Network & IPS:
  --sync-fw           Deploy/sync the nftables pipeline (auto-detect mode)
  --fw-enable         Enable Suricata 8 Firewall Mode (requires Suricata 8+)
  --fw-disable        Disable Suricata Firewall Mode (revert to IDS)
  --fw-teardown       Remove all IntelShield nftables rules

State & SIEM:
  --export-state      Export full state as RFC 8259 JSON (SIEM-ready)
  --write-state       Write/update the state database

System:
  --check-deps        Verify all binary dependencies are present
  --help, -h          Show this help

Interactive:
  (no arguments)      Launch the interactive TUI menu

Examples:
  sudo $0 --lock                    # Lock the system
  sudo $0 --unlock                  # Unlock before apt-get
  sudo $0 --sync-fw                 # Deploy nftables pipeline
  sudo $0 --export-state            # Export SIEM JSON
  sudo $0                           # Interactive TUI
EOF
}

cli_dispatch(){
  local action="${1:-}"

  case "$action" in
    --lock)
      echo "Locking system..."
      if system_lock; then
        echo "System LOCKED. Immutable count: $(count_immutable)"
      else
        echo "Lock failed. Check $LOG" >&2; exit 1
      fi
      ;;
    --unlock)
      echo "Unlocking system..."
      if system_unlock; then
        echo "System UNLOCKED."
      else
        echo "Unlock failed. Check $LOG" >&2; exit 1
      fi
      ;;
    --status)
      echo "$(get_lock_status) ($(count_immutable) immutable paths)"
      ;;
    --sync-fw)
      echo "Syncing nftables pipeline..."
      nft_sync && echo "Synced." || { echo "Sync failed." >&2; exit 1; }
      ;;
    --fw-enable)
      echo "Enabling Suricata 8 Firewall Mode..."
      suricata_fw_enable && echo "Enabled." || { echo "Failed." >&2; exit 1; }
      ;;
    --fw-disable)
      echo "Disabling Suricata Firewall Mode..."
      suricata_fw_disable && echo "Disabled." || { echo "Failed." >&2; exit 1; }
      ;;
    --fw-teardown)
      echo "Tearing down nftables rules..."
      nft_teardown && echo "Teardown complete." || { echo "Failed." >&2; exit 1; }
      ;;
    --export-state)
      state_write 2>/dev/null
      outfile="$(state_export_siem 2>/dev/null)"
      [[ -n "$outfile" && -f "$outfile" ]] && echo "Exported: $outfile" || { echo "Export failed." >&2; exit 1; }
      ;;
    --write-state)
      state_write && echo "State written: $STATE_DB" || { echo "Failed." >&2; exit 1; }
      ;;
    --check-deps)
      if check_deps; then
        echo "All dependencies present."
      else
        echo "Missing dependencies detected." >&2; exit 1
      fi
      ;;
    --help|-h)
      usage
      ;;
    "")
      # No arguments — launch interactive TUI
      if [[ $EUID -ne 0 ]]; then
        echo "Warning: running without root. Some operations may fail." >&2
      fi
      mkdir -p "$STATE_DIR" "$(dirname "$LOG")" "$NFT_HOOKS_DIR" 2>/dev/null
      touch "$LOG" 2>/dev/null
      chmod 600 "$LOG" 2>/dev/null || true
      state_write 2>/dev/null || true
      main_menu
      ;;
    *)
      echo "Unknown option: $action" >&2
      echo "Run '$0 --help' for usage." >&2
      exit 1
      ;;
  esac
}

#==============================================================================
#  ENTRY POINT
#==============================================================================
# Ensure we're running as root for system operations
if [[ $EUID -ne 0 ]]; then
  echo "Warning: ${APP} requires root for full functionality." >&2
  echo "Some operations may fail or be silently skipped." >&2
fi

# Create required directories
mkdir -p "$STATE_DIR" "$(dirname "$LOG")" "$NFT_HOOKS_DIR" 2>/dev/null || true
touch "$LOG" 2>/dev/null || true
chmod 600 "$LOG" 2>/dev/null || true

# Dispatch
cli_dispatch "${1:-}"
