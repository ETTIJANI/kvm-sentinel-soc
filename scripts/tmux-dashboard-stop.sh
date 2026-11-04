#!/usr/bin/env bash
# =============================================================================
# tmux-dashboard-stop.sh — stop the dashboard and the processes it started.
#
# Safety model:
#   * only PIDs recorded by tmux-dashboard.sh are touched
#   * each pidfile stores "PID STARTTIME"; a mismatch means the PID was reused,
#     and the process is left alone
#   * SIGTERM first, SIGKILL only after --timeout seconds
#   * the libvirt guests and the Docker stacks keep running unless you ask for
#     --stop-stacks / --stop-vms
#
# Usage:
#   ./scripts/tmux-dashboard-stop.sh                 stop the dashboard only
#   ./scripts/tmux-dashboard-stop.sh --stop-stacks   also compose down on both guests
#   ./scripts/tmux-dashboard-stop.sh --stop-vms      also shut the guests down
#   ./scripts/tmux-dashboard-stop.sh --dry-run       show what would be stopped
#   ./scripts/tmux-dashboard-stop.sh --help
# =============================================================================
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd -P)"
SELF="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

init_config() {
  SESSION="${DASH_SESSION:-kvm-sentinel}"
  LOG_DIR="${DASH_LOG_DIR:-$REPO_ROOT/logs/tmux-dashboard}"
  RUN_DIR="${DASH_RUN_DIR:-$LOG_DIR/run/$SESSION}"
  PID_DIR="$RUN_DIR/pids"
  VM1_SSH_HOST="${DASH_VM1_HOST:-10.10.0.10}"
  VM1_SSH_PORT="${DASH_VM1_PORT:-22}"
  VM1_SSH_USER="${DASH_VM1_USER:-soc}"
  VM1_PASSWORD="${DASH_VM1_PASSWORD:-}"
  VM1_COMPOSE_DIR="${DASH_VM1_COMPOSE_DIR:-/opt/honeypot}"
  VM2_SSH_HOST="${DASH_VM2_HOST:-192.168.122.20}"
  VM2_SSH_PORT="${DASH_VM2_PORT:-22}"
  VM2_SSH_USER="${DASH_VM2_USER:-soc}"
  VM2_PASSWORD="${DASH_VM2_PASSWORD:-}"
  VM2_COMPOSE_DIR="${DASH_VM2_COMPOSE_DIR:-/opt/soc}"
  SSH_KEY="${DASH_SSH_KEY:-}"

  if [[ -n ${NO_COLOR:-} || -n ${QUIET:-} ]]; then
    C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
  else
    C_RESET=$'\033[0m'; C_INFO=$'\033[1;34m'; C_OK=$'\033[1;32m'
    C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
  fi
}

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
info() { ((QUIET)) || printf '%s[%s] INFO%s %s\n' "$C_INFO" "$(ts)" "$C_RESET" "$*"; }
ok() { ((QUIET)) || printf '%s[%s]  OK %s %s\n' "$C_OK" "$(ts)" "$C_RESET" "$*"; }
warn() { printf '%s[%s] WARN%s %s\n' "$C_WARN" "$(ts)" "$C_RESET" "$*" >&2; }
die() { printf '%s[%s] FAIL%s %s\n' "$C_ERR" "$(ts)" "$C_RESET" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

load_env() {
  local file="$REPO_ROOT/.env" line key value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[2]}"; value="${BASH_REMATCH[3]}"
      value="${value%\"}"; value="${value#\"}"; value="${value%\'}"; value="${value#\'}"
      if [[ -z ${!key+x} ]]; then printf -v "$key" '%s' "$value"; export "$key"; fi
    fi
  done <"$file"
}

proc_starttime() {
  [[ -r "/proc/$1/stat" ]] || return 1
  sed 's/^.*) //' "/proc/$1/stat" | awk '{print $20}'
}

tcp_open() {
  timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null
}

ssh_reachable() {
  case "$1" in
    vm1) tcp_open "$VM1_SSH_HOST" "$VM1_SSH_PORT" ;;
    vm2) tcp_open "$VM2_SSH_HOST" "$VM2_SSH_PORT" ;;
    *) return 1 ;;
  esac
}

build_ssh() {
  local node="$1" host port user password
  case "$node" in
    vm1) host="$VM1_SSH_HOST"; port="$VM1_SSH_PORT"; user="$VM1_SSH_USER"; password="$VM1_PASSWORD" ;;
    vm2) host="$VM2_SSH_HOST"; port="$VM2_SSH_PORT"; user="$VM2_SSH_USER"; password="$VM2_PASSWORD" ;;
    *) return 1 ;;
  esac
  local -a opts=(-o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR)
  if [[ -n "$SSH_KEY" ]]; then
    opts+=(-i "$SSH_KEY")
  fi
  if [[ -n "$password" ]] && have sshpass; then
    SSH_ARGV=(sshpass -p "$password" ssh "${opts[@]}" -p "$port" "$user@$host")
  else
    SSH_ARGV=(ssh "${opts[@]}" -o BatchMode=yes -p "$port" "$user@$host")
  fi
}

remote_compose() {
  local node="$1" dir sub
  local IFS=' '
  shift
  if [[ "$node" == vm1 ]]; then dir="$VM1_COMPOSE_DIR"; else dir="$VM2_COMPOSE_DIR"; fi
  sub="docker compose $*"
  printf 'cd %q && { sudo -n %s 2>/dev/null || %s; }' "$dir" "$sub" "$sub"
}

usage() {
  sed -n '3,18p' "$SELF" | sed 's/^# \{0,1\}//'
}

# --------------------------------------------------------------------------- #
# process teardown
# --------------------------------------------------------------------------- #
stop_process() {
  local name="$1" pid="$2" start="$3" current waited=0
  if ! kill -0 "$pid" 2>/dev/null; then
    info "$name: pid $pid already gone"
    return 0
  fi
  current="$(proc_starttime "$pid" || echo "")"
  if [[ "$current" != "$start" ]]; then
    warn "$name: pid $pid was reused by another process; leaving it alone"
    return 0
  fi
  if ((DRY_RUN)); then
    info "would stop $name (pid $pid)"
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null && ((waited < TIMEOUT * 2)); do
    sleep 0.5
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    warn "$name did not exit within ${TIMEOUT}s; sending SIGKILL"
    kill -KILL "$pid" 2>/dev/null || true
  fi
  ok "$name stopped (pid $pid)"
}

stop_components() {
  local pidfile pid start stopped=0
  shopt -s nullglob
  local -a pidfiles=("$PID_DIR"/*.pid)
  shopt -u nullglob
  if ((${#pidfiles[@]} == 0)); then
    info "no recorded component PIDs under $PID_DIR"
  fi
  for pidfile in "${pidfiles[@]}"; do
    IFS=' ' read -r pid start <"$pidfile" || true
    if [[ -z "${pid:-}" || -z "${start:-}" ]]; then
      rm -f "$pidfile"
      continue
    fi
    stop_process "$(basename -- "$pidfile" .pid)" "$pid" "$start"
    ((DRY_RUN)) || rm -f "$pidfile"
    stopped=$((stopped + 1))
  done
  ((QUIET)) || info "$stopped recorded component(s) processed"
}

stop_session() {
  if ! have tmux; then
    return 0
  fi
  if ! tmux has-session -t "=$SESSION" 2>/dev/null; then
    info "tmux session '$SESSION' is not running"
    return 0
  fi
  if ((DRY_RUN)); then
    info "would kill tmux session '$SESSION'"
    return 0
  fi
  tmux kill-session -t "=$SESSION"
  ok "tmux session '$SESSION' closed"
}

stop_stacks() {
  local node
  for node in vm1 vm2; do
    if ! ssh_reachable "$node"; then
      warn "$node unreachable: stack left as is"
      continue
    fi
    info "compose down on $node"
    build_ssh "$node"
    local command
    command="$(remote_compose "$node" down --remove-orphans)"
    if ((DRY_RUN)); then
      info "would run on $node: $command"
      continue
    fi
    if timeout 180 "${SSH_ARGV[@]}" "$command" >>"$LOG_DIR/stop-stacks.log" 2>&1; then
      ok "$node stack stopped"
    else
      warn "$node compose down failed; see $LOG_DIR/stop-stacks.log"
    fi
  done
}

stop_vms() {
  local dom state waited
  if ! have virsh; then
    warn "virsh not installed: cannot stop the guests"
    return 0
  fi
  for dom in vm-honeypot vm-soc; do
    state="$(virsh -c qemu:///system domstate "$dom" 2>/dev/null || echo undefined)"
    [[ "$state" == "running" ]] || { info "$dom is not running"; continue; }
    if ((DRY_RUN)); then
      info "would shut down $dom"
      continue
    fi
    if ! sudo -n virsh shutdown "$dom" >/dev/null 2>&1; then
      warn "cannot shut down $dom (passwordless sudo required)"
      continue
    fi
    waited=0
    while [[ "$(virsh -c qemu:///system domstate "$dom" 2>/dev/null)" == "running" ]] \
          && ((waited < TIMEOUT)); do
      sleep 1
      waited=$((waited + 1))
    done
    if [[ "$(virsh -c qemu:///system domstate "$dom" 2>/dev/null)" == "running" ]]; then
      if ((FORCE)); then
        sudo -n virsh destroy "$dom" >/dev/null 2>&1 && warn "$dom destroyed (forced)"
      else
        warn "$dom still running after ${TIMEOUT}s (use --force to destroy)"
      fi
    else
      ok "$dom shut down"
    fi
  done
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
DRY_RUN=0
FORCE=0
QUIET=0
TIMEOUT=15
STOP_STACKS=0
STOP_VMS=0

parse_args() {
  while (($#)); do
    case "$1" in
      --session) export DASH_SESSION="${2:?--session needs a name}"; shift 2 ;;
      --stop-stacks) STOP_STACKS=1; shift ;;
      --stop-vms) STOP_VMS=1; shift ;;
      --force) FORCE=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --quiet) QUIET=1; shift ;;
      --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift 2 ;;
      --no-color) export NO_COLOR=1; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a number of seconds"
}

main() {
  parse_args "$@"
  load_env
  init_config

  info "stopping dashboard session '$SESSION'"
  stop_components
  stop_session
  if ((STOP_STACKS)); then stop_stacks; fi
  if ((STOP_VMS)); then stop_vms; fi

  if ((DRY_RUN)); then
    info "dry run: nothing was changed"
  else
    ok "dashboard stopped (guests and stacks kept unless --stop-stacks/--stop-vms)"
  fi
}

main "$@"
