#!/usr/bin/env bash
#
# shutdown-lab.sh — gracefully stop the KVM-Sentinel-SOC lab without deleting it.
#
# This is deliberately the opposite of cleanup-lab.sh:
#   * guests are stopped with ACPI `virsh shutdown`, never `destroy`
#   * guest stacks use `docker compose stop`, never `down -v`
#   * the host controller container is stopped, not removed
#   * domains, QCOW2 overlays, seed ISOs, libvirt networks, snapshots,
#     Docker volumes, incident reports and audit state are all preserved
#
# Use cleanup-lab.sh only when you intentionally want a destructive teardown.
#
# Usage:
#   ./host/provisioning/shutdown-lab.sh
#   ./host/provisioning/shutdown-lab.sh --dry-run
#   ./host/provisioning/shutdown-lab.sh --timeout 180
#   ./host/provisioning/shutdown-lab.sh --skip-stacks
#   ./host/provisioning/shutdown-lab.sh --stop-dashboard
#   ./host/provisioning/shutdown-lab.sh --help
#
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
SELF="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

LAB_URI="${LAB_LIBVIRT_URI:-qemu:///system}"
VM1="${LAB_VM1:-vm-honeypot}"
VM2="${LAB_VM2:-vm-soc}"
CONTROLLER_CONTAINER="${LAB_CONTROLLER_CONTAINER:-sentinel-daemon}"
SSH_KEY="${LAB_SSH_KEY:-${DASH_SSH_KEY:-}}"

VM1_SSH_HOST="${LAB_VM1_HOST:-${DASH_VM1_HOST:-10.10.0.10}}"
VM1_SSH_PORT="${LAB_VM1_PORT:-${DASH_VM1_PORT:-22}}"
VM1_SSH_USER="${LAB_VM1_USER:-${DASH_VM1_USER:-soc}}"
VM1_PASSWORD="${LAB_VM1_PASSWORD:-${DASH_VM1_PASSWORD:-}}"
VM1_COMPOSE_DIR="${LAB_VM1_COMPOSE_DIR:-${DASH_VM1_COMPOSE_DIR:-/opt/honeypot}}"

VM2_SSH_HOST="${LAB_VM2_HOST:-${DASH_VM2_HOST:-192.168.122.20}}"
VM2_SSH_PORT="${LAB_VM2_PORT:-${DASH_VM2_PORT:-22}}"
VM2_SSH_USER="${LAB_VM2_USER:-${DASH_VM2_USER:-soc}}"
VM2_PASSWORD="${LAB_VM2_PASSWORD:-${DASH_VM2_PASSWORD:-}}"
VM2_COMPOSE_DIR="${LAB_VM2_COMPOSE_DIR:-${DASH_VM2_COMPOSE_DIR:-/opt/soc}}"

TIMEOUT="${LAB_SHUTDOWN_TIMEOUT:-120}"
DRY_RUN=0
STOP_STACKS=1
STOP_CONTROLLER=1
STOP_DASHBOARD=1
DISABLE_LIVE_FIRE=1

if [[ -t 1 ]]; then
  C_RESET=$'\033[0m'; C_INFO=$'\033[1;34m'; C_OK=$'\033[1;32m'
  C_WARN=$'\033[1;33m'; C_ERR=$'\033[1;31m'
else
  C_RESET=""; C_INFO=""; C_OK=""; C_WARN=""; C_ERR=""
fi

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
info() { printf '%s[%s] INFO%s %s\n' "$C_INFO" "$(ts)" "$C_RESET" "$*"; }
ok()   { printf '%s[%s]  OK %s %s\n' "$C_OK" "$(ts)" "$C_RESET" "$*"; }
warn() { printf '%s[%s] WARN%s %s\n' "$C_WARN" "$(ts)" "$C_RESET" "$*" >&2; }
die()  { printf '%s[%s] FAIL%s %s\n' "$C_ERR" "$(ts)" "$C_RESET" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

trap 'warn "interrupted; no lab data was deleted"; exit 130' INT TERM

usage() {
  cat <<EOF
KVM-Sentinel-SOC — graceful shutdown (data-preserving)

Usage: ./host/provisioning/shutdown-lab.sh [options]

Options:
  --timeout N       seconds to wait for each guest to power off (default: 120)
  --dry-run         print actions without changing anything
  --skip-stacks     do not stop guest Docker stacks first
  --keep-dashboard  leave the tmux dashboard session running
  --keep-live-fire  leave classroom DNAT rules in place
  --help            this message

Preserved:
  domains and QCOW2 overlays, seed ISOs, snapshots, libvirt networks,
  guest Docker containers/volumes, reports and controller audit state.

Never done by this script:
  virsh destroy / undefine, docker compose down, docker rm, rm, or volume deletion.
EOF
}

load_env() {
  local file="$REPO_ROOT/.env" line key value
  [[ -r "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
      key="${BASH_REMATCH[2]}"
      value="${BASH_REMATCH[3]}"
      value="${value%\"}"; value="${value#\"}"
      value="${value%\'}"; value="${value#\'}"
      if [[ -z ${!key+x} ]]; then
        printf -v "$key" '%s' "$value"
        export "$key"
      fi
    fi
  done <"$file"
}

parse_args() {
  while (($#)); do
    case "$1" in
      --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift 2 ;;
      --dry-run) DRY_RUN=1; shift ;;
      --skip-stacks) STOP_STACKS=0; shift ;;
      --stop-dashboard) STOP_DASHBOARD=1; shift ;;
      --keep-dashboard) STOP_DASHBOARD=0; shift ;;
      --keep-live-fire) DISABLE_LIVE_FIRE=0; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
  done
  [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || die "--timeout must be a number of seconds"
}

tcp_open() {
  timeout 3 bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$1" "$2" 2>/dev/null
}

build_ssh() {
  local node="$1" host port user password
  case "$node" in
    vm1) host="$VM1_SSH_HOST"; port="$VM1_SSH_PORT"; user="$VM1_SSH_USER"; password="$VM1_PASSWORD" ;;
    vm2) host="$VM2_SSH_HOST"; port="$VM2_SSH_PORT"; user="$VM2_SSH_USER"; password="$VM2_PASSWORD" ;;
    *) die "unknown SSH node: $node" ;;
  esac

  local -a opts=(-o ConnectTimeout=6 -o ServerAliveInterval=15 -o ServerAliveCountMax=3
                 -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR)
  if [[ -n "$SSH_KEY" ]]; then
    opts+=(-i "$SSH_KEY")
  fi
  if [[ -n "$password" ]] && have sshpass; then
    SSH_ARGV=(sshpass -p "$password" ssh "${opts[@]}" -p "$port" "$user@$host")
  else
    SSH_ARGV=(ssh "${opts[@]}" -o BatchMode=yes -p "$port" "$user@$host")
  fi
}

remote_compose_stop() {
  local dir="$1"
  printf 'cd %q && { sudo -n docker compose stop 2>/dev/null || docker compose stop; }' "$dir"
}

stop_guest_stack() {
  local node="$1" host port dir
  case "$node" in
    vm1) host="$VM1_SSH_HOST"; port="$VM1_SSH_PORT"; dir="$VM1_COMPOSE_DIR" ;;
    vm2) host="$VM2_SSH_HOST"; port="$VM2_SSH_PORT"; dir="$VM2_COMPOSE_DIR" ;;
  esac

  if ! tcp_open "$host" "$port"; then
    info "$node SSH is not reachable (guest may already be off)"
    return 0
  fi

  build_ssh "$node"
  if ! timeout 8 "${SSH_ARGV[@]}" true >/dev/null 2>&1; then
    warn "$node SSH authentication failed; skipping compose stop (ACPI shutdown will still stop the stack)"
    return 0
  fi

  local command
  command="$(remote_compose_stop "$dir")"
  if ((DRY_RUN)); then
    info "would stop $node stack with: docker compose stop"
    return 0
  fi

  info "stopping $node Docker stack (containers and volumes preserved)"
  if timeout 180 "${SSH_ARGV[@]}" "$command"; then
    ok "$node stack stopped"
  else
    warn "$node compose stop failed or timed out; ACPI shutdown will still run"
  fi
}

stop_controller() {
  if ! have docker; then
    warn "docker not found: controller container not checked"
    return 0
  fi
  if ! docker inspect "$CONTROLLER_CONTAINER" >/dev/null 2>&1; then
    info "controller container '$CONTROLLER_CONTAINER' is not present"
    return 0
  fi

  local state
  state="$(docker inspect -f '{{.State.Status}}' "$CONTROLLER_CONTAINER" 2>/dev/null || echo unknown)"
  if [[ "$state" != "running" ]]; then
    info "controller container '$CONTROLLER_CONTAINER' is already $state"
    return 0
  fi
  if ((DRY_RUN)); then
    info "would stop controller container '$CONTROLLER_CONTAINER'"
    return 0
  fi

  info "stopping controller container '$CONTROLLER_CONTAINER'"
  if docker stop --time 20 "$CONTROLLER_CONTAINER" >/dev/null; then
    ok "controller stopped; container retained"
  else
    warn "controller container did not stop cleanly; it was not removed"
  fi
}

stop_dashboard() {
  ((STOP_DASHBOARD)) || return 0
  if [[ ! -x "$REPO_ROOT/scripts/tmux-dashboard-stop.sh" ]]; then
    warn "dashboard stop script not found; skipping"
    return 0
  fi
  if ! have tmux; then
    info "tmux is not installed; dashboard not running"
    return 0
  fi
  if ! tmux has-session -t "${DASH_SESSION:-kvm-sentinel}" 2>/dev/null; then
    info "tmux dashboard is not running"
    return 0
  fi
  if [[ -n "${TMUX:-}" ]]; then
    warn "running inside tmux; skipping dashboard stop to avoid closing this pane"
    return 0
  fi

  if ((DRY_RUN)); then
    info "would stop the tmux dashboard session"
  else
    "$REPO_ROOT/scripts/tmux-dashboard-stop.sh" --quiet || warn "dashboard stop reported a problem"
  fi
}

disable_live_fire() {
  ((DISABLE_LIVE_FIRE)) || return 0
  [[ -x "$SCRIPT_DIR/enable-live-fire.sh" ]] || return 0

  if ! sudo -n true 2>/dev/null; then
    warn "live-fire rules need root; leaving them unchanged (use: sudo $SCRIPT_DIR/enable-live-fire.sh disable)"
    return 0
  fi
  if ((DRY_RUN)); then
    info "would disable classroom live-fire DNAT rules"
    return 0
  fi

  if sudo -n "$SCRIPT_DIR/enable-live-fire.sh" disable >/dev/null 2>&1; then
    ok "live-fire DNAT rules disabled"
  else
    warn "could not disable live-fire rules; check them with: sudo $SCRIPT_DIR/enable-live-fire.sh status"
  fi
}

virsh_domstate() {
  virsh -c "$LAB_URI" domstate "$1" 2>/dev/null || true
}

shutdown_vm() {
  local dom="$1"
  if virsh -c "$LAB_URI" shutdown "$dom" >/dev/null 2>&1; then
    return 0
  fi
  if sudo -n true 2>/dev/null; then
    sudo -n virsh -c "$LAB_URI" shutdown "$dom" >/dev/null 2>&1
  else
    return 1
  fi
}

shutdown_vms() {
  if ! have virsh; then
    warn "virsh not found: cannot shut down guests"
    return 1
  fi

  local dom state started=0 unresolved=0
  for dom in "$VM1" "$VM2"; do
    state="$(virsh_domstate "$dom")"
    case "$state" in
      running)
        if ((DRY_RUN)); then
          info "would gracefully shut down $dom"
          started=1
        elif shutdown_vm "$dom"; then
          info "graceful shutdown requested for $dom"
          started=1
        else
          warn "could not request shutdown for $dom"
          unresolved=1
        fi
        ;;
      "in shutdown")
        info "$dom is already shutting down"
        started=1
        ;;
      "shut off")
        info "$dom is already shut off"
        ;;
      "")
        warn "$dom is not defined under $LAB_URI"
        unresolved=1
        ;;
      *)
        warn "$dom is in state '$state'; not forcing a shutdown"
        unresolved=1
        ;;
    esac
  done

  ((started)) || return "$unresolved"
  ((DRY_RUN)) && return 0

  local waited=0 all_off
  while ((waited < TIMEOUT)); do
    all_off=1
    for dom in "$VM1" "$VM2"; do
      state="$(virsh_domstate "$dom")"
      if [[ "$state" != "shut off" ]]; then
        all_off=0
      fi
    done
    ((all_off)) && break
    sleep 2
    waited=$((waited + 2))
  done

  local rc=0
  for dom in "$VM1" "$VM2"; do
    state="$(virsh_domstate "$dom")"
    if [[ "$state" == "shut off" ]]; then
      ok "$dom shut down"
    else
      warn "$dom still reports '$state' after ${TIMEOUT}s; no force-destroy was performed"
      rc=1
    fi
  done
  return "$rc"
}

print_preserved() {
  local dom state
  printf '\n%sPreserved (not deleted):%s\n' "$C_INFO" "$C_RESET"
  for dom in "$VM1" "$VM2"; do
    state="$(virsh_domstate "$dom")"
    printf '  %-14s state=%s\n' "$dom" "${state:-undefined}"
    if [[ "$state" != "" ]]; then
      while IFS= read -r snapshot; do
        [[ -n "$snapshot" ]] && printf '                 snapshot: %s\n' "$snapshot"
      done < <(virsh -c "$LAB_URI" snapshot-list "$dom" --name 2>/dev/null || true)
      virsh -c "$LAB_URI" domblklist "$dom" --details 2>/dev/null \
        | awk '$1 == "file" {printf "                 disk: %s\n", $4}' || true
    fi
  done
  printf '  %-14s container=%s\n' "controller" "$CONTROLLER_CONTAINER"
  printf '  %-14s network=%s\n' "libvirt" "left defined"
}

main() {
  parse_args "$@"
  load_env

  info "graceful lab shutdown; this script never deletes disks, snapshots, volumes, or reports"

  if ((STOP_STACKS)); then
    stop_guest_stack vm1
    stop_guest_stack vm2
  else
    info "--skip-stacks: guest Docker stacks left running until ACPI shutdown"
  fi

  if ((STOP_CONTROLLER)); then
    stop_controller
  fi

  disable_live_fire
  stop_dashboard

  if ! shutdown_vms; then
    print_preserved
    warn "lab is not fully stopped; fix the reported guest state and re-run (no data was deleted)"
    exit 1
  fi

  print_preserved
  if ((DRY_RUN)); then
    ok "dry run complete; nothing was changed"
  else
    ok "lab stopped gracefully; all disks, snapshots, volumes, and reports retained"
  fi
}

main "$@"
