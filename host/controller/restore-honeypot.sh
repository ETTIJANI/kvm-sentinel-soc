#!/usr/bin/env bash
#
# restore-honeypot.sh — undo a quarantine, between two classroom demos.
#
# The approval daemon takes the honeypot's virtual NIC down and leaves a live
# snapshot behind. This script brings the NIC back up, and optionally reverts
# the guest to the pristine 'clean-baseline' snapshot so the next demo starts
# from a known state.
#
# Referenced by: docs/04-CLASSROOM-LIVE-FIRE.md
#
set -Eeuo pipefail
IFS=$'\n\t'

DOMAIN="${HONEYPOT_DOMAIN:-vm-honeypot}"
IFACE_MAC="${HONEYPOT_IFACE_MAC:-}"
SNAPSHOT="clean-baseline"
ACTION="status"

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

trap 'die "unexpected failure on line $LINENO (command: $BASH_COMMAND)"' ERR

usage() {
  cat <<EOF
KVM-Sentinel-SOC — honeypot restore

Usage: sudo ./host/controller/restore-honeypot.sh [options]

Options:
  --status            show domain state, interfaces and link state (default)
  --list              list snapshots of ${DOMAIN}
  --snapshot NAME     snapshot to revert to (default: clean-baseline)
  --revert            revert to the snapshot and bring the isolated NIC back up
  --help              this message

Environment:
  HONEYPOT_DOMAIN     libvirt domain name (default: vm-honeypot)
  HONEYPOT_IFACE_MAC  force the interface MAC instead of auto-detecting it
EOF
}

while (($#)); do
  case "$1" in
    --status) ACTION="status"; shift ;;
    --list) ACTION="list"; shift ;;
    --snapshot) SNAPSHOT="${2:?--snapshot needs a name}"; ACTION="revert"; shift 2 ;;
    --revert) ACTION="revert"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "run with sudo: sudo $0 $*"
command -v virsh >/dev/null 2>&1 || die "virsh not found in PATH"
virsh -c qemu:///system dominfo "$DOMAIN" >/dev/null 2>&1 \
  || die "domain $DOMAIN is not defined (run ./host/provisioning/deploy-lab.sh first)"

# The isolated interface is the one whose Source is backend-isolated. Fall back
# to the first NIC if the network was renamed, and to HONEYPOT_IFACE_MAC if the
# listing cannot be parsed at all.
resolve_mac() {
  if [[ -n "$IFACE_MAC" ]]; then
    printf '%s' "$IFACE_MAC"
    return 0
  fi
  local mac
  mac="$(virsh -c qemu:///system domiflist "$DOMAIN" 2>/dev/null \
    | awk '/backend-isolated/ { print $NF; exit }')"
  if [[ -z "$mac" ]]; then
    mac="$(virsh -c qemu:///system domiflist "$DOMAIN" 2>/dev/null \
      | awk '/^[[:space:]]*[a-z]/ && $NF ~ /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/ { print $NF; exit }')"
  fi
  [[ -n "$mac" ]] || die "could not determine the isolated interface MAC; set HONEYPOT_IFACE_MAC"
  printf '%s' "$mac"
}

show_status() {
  local state mac link
  state="$(virsh -c qemu:///system domstate "$DOMAIN" 2>/dev/null | head -n1)"
  mac="$(resolve_mac)"

  printf '\n%sHoneypot status%s\n\n' "$C_INFO" "$C_RESET"
  printf '  domain    : %s\n' "$DOMAIN"
  printf '  state     : %s\n' "$state"
  printf '  interface : %s\n\n' "$mac"

  printf '  interfaces (virsh domiflist):\n'
  virsh -c qemu:///system domiflist "$DOMAIN" | sed 's/^/    /'

  link="$(virsh -c qemu:///system domif-getlink "$DOMAIN" "$mac" 2>/dev/null | awk '{ print $2 }')"
  printf '\n  link state: %s\n\n' "${link:-unknown}"
  if [[ "$link" == "down" ]]; then
    printf '  %sthe honeypot is QUARANTINED%s — run: sudo %s --revert\n\n' "$C_WARN" "$C_RESET" "$0"
  else
    printf '  %shoneypot is reachable%s\n\n' "$C_OK" "$C_RESET"
  fi
}

case "$ACTION" in
  list)
    info "snapshots of $DOMAIN"
    virsh -c qemu:///system snapshot-list "$DOMAIN"
    ;;

  status)
    show_status
    ;;

  revert)
    info "reverting $DOMAIN to snapshot '$SNAPSHOT'"
    if ! virsh -c qemu:///system snapshot-info "$DOMAIN" "$SNAPSHOT" >/dev/null 2>&1; then
      die "snapshot '$SNAPSHOT' does not exist on $DOMAIN (see $0 --list)"
    fi
    virsh -c qemu:///system snapshot-revert "$DOMAIN" --snapshotname "$SNAPSHOT" --running
    ok "reverted to '$SNAPSHOT'"

    mac="$(resolve_mac)"
    info "bringing the isolated interface back up ($mac)"
    virsh -c qemu:///system domif-setlink "$DOMAIN" "$mac" up
    sleep 2

    link="$(virsh -c qemu:///system domif-getlink "$DOMAIN" "$mac" 2>/dev/null | awk '{ print $2 }')"
    [[ "$link" == "up" ]] || die "interface $mac is still '$link' after domif-setlink up"

    ok "honeypot back online — ready for the next demo"
    printf '\n  verify from this host:\n'
    printf '    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.10.0.10   # password: toor\n'
    printf '    (or, during live fire: ssh root@<HOST_LAN_IP> -p 2222)\n\n'
    ;;
esac
