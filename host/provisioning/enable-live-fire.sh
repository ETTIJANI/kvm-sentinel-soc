#!/usr/bin/env bash
#
# enable-live-fire.sh — expose the SSH honeypot to the classroom LAN.
#
# Publishes TCP <port> on the host's LAN address and DNATs it to
# 10.10.0.10:2222 (vm-honeypot). The four rules are tagged with the iptables
# comment "kvm-sentinel-livefire" so they can be removed deterministically,
# whatever the interface/port used at enable time.
#
# Why the MASQUERADE rule is mandatory:
#   vm-honeypot has no default route (isolated network). Without source-NAT to
#   10.10.0.1, its SYN-ACK to a classroom client would be unroutable and the
#   TCP handshake would hang forever.
#
# Referenced by: docs/04-CLASSROOM-LIVE-FIRE.md, docs/03-INSTALL-WINDOWS-WSL2.md
#
set -Eeuo pipefail
IFS=$'\n\t'

COMMENT="kvm-sentinel-livefire"
HONEYPOT_IP="10.10.0.10"
HONEYPOT_PORT="2222"
HOST_PORT="2222"
WAN_IF=""
ACTION=""

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
KVM-Sentinel-SOC — classroom live-fire forwarder

Usage: sudo ./host/provisioning/enable-live-fire.sh {enable|disable|status} [options]

Options:
  --host-port N   TCP port exposed on the physical host (default: 2222)
  --wan-if IF     LAN-facing interface (default: auto-detect via the default route)
  --help          this message

When enabled, students run:
  ssh root@<HOST_LAN_IP> -p <host-port>          # password: toor (fake)
EOF
}

detect_wan_if() {
  local iface
  iface="$(ip route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
  [[ -n "$iface" ]] || die "could not detect the LAN interface; pass --wan-if"
  printf '%s' "$iface"
}

wan_ip() {
  ip -4 -o addr show dev "$WAN_IF" 2>/dev/null | awk '{ print $4 }' | cut -d/ -f1 | head -n1
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "run with sudo: sudo $0 $ACTION ${*:-}"
}

require_iptables() {
  command -v iptables >/dev/null 2>&1 \
    || die "iptables not found. On NixOS install pkgs.iptables (nft-backed); on Debian/Ubuntu: apt install iptables"
}

rules_present() {
  iptables -t nat -S 2>/dev/null | grep -q -- "$COMMENT" \
    || iptables -S 2>/dev/null | grep -q -- "$COMMENT"
}

verify_edge() {
  virsh -c qemu:///system domstate vm-honeypot 2>/dev/null | grep -q '^running' \
    || die "vm-honeypot is not running (virsh domstate vm-honeypot). Deploy or start it first."
  if ! timeout 3 bash -c "exec 3<>/dev/tcp/$HONEYPOT_IP/$HONEYPOT_PORT" 2>/dev/null; then
    die "nothing answers on ${HONEYPOT_IP}:${HONEYPOT_PORT}. Is the honeypot container up? (ssh soc@10.10.0.10 'cd /opt/honeypot && docker compose ps')"
  fi
}

flush_rules() {
  local table="$1" line removed=0
  local -a parts
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    # iptables -S prints "-A CHAIN <spec>" with quoted string args such as
    # --comment "kvm-sentinel-livefire". -D needs the unquoted value: passing the
    # quote characters matches no rule and leaves the trap published.
    line="${line//\"/}"
    IFS=' ' read -r -a parts <<<"${line/-A /-D }"
    if [[ "$table" == "nat" ]]; then
      iptables -t nat "${parts[@]}" 2>/dev/null && removed=$((removed + 1)) \
        || warn "could not delete nat rule: $line"
    else
      iptables "${parts[@]}" 2>/dev/null && removed=$((removed + 1)) \
        || warn "could not delete filter rule: $line"
    fi
  done < <(if [[ "$table" == "nat" ]]; then iptables -t nat -S 2>/dev/null; else iptables -S 2>/dev/null; fi | grep -- "$COMMENT" || true)
  printf '%s' "$removed"
}

do_enable() {
  require_root
  require_iptables
  WAN_IF="${WAN_IF:-$(detect_wan_if)}"
  ip link show dev "$WAN_IF" >/dev/null 2>&1 || die "interface $WAN_IF does not exist"

  local lan_ip
  lan_ip="$(wan_ip)"
  [[ -n "$lan_ip" ]] || die "interface $WAN_IF has no IPv4 address"

  verify_edge

  if rules_present; then
    warn "live-fire rules already present; removing them first (idempotent enable)"
    do_disable >/dev/null
  fi

  info "enabling IPv4 forwarding"
  sysctl -qw net.ipv4.ip_forward=1
  if ! grep -rqs 'net.ipv4.ip_forward' /etc/sysctl.d /etc/sysctl.conf 2>/dev/null; then
    warn "ip_forward is not persisted; add 'net.ipv4.ip_forward = 1' to /etc/sysctl.d/99-kvm-sentinel.conf"
  fi

  info "installing DNAT ${lan_ip}:${HOST_PORT} -> ${HONEYPOT_IP}:${HONEYPOT_PORT} on ${WAN_IF}"
  iptables -t nat -I PREROUTING 1 -i "$WAN_IF" -p tcp --dport "$HOST_PORT" \
    -m comment --comment "$COMMENT" -j DNAT --to-destination "${HONEYPOT_IP}:${HONEYPOT_PORT}"
  iptables -I FORWARD 1 -i "$WAN_IF" -o virbr1 -p tcp -d "$HONEYPOT_IP" --dport "$HONEYPOT_PORT" \
    -m comment --comment "$COMMENT" -j ACCEPT
  iptables -I FORWARD 1 -i virbr1 -o "$WAN_IF" -p tcp -s "$HONEYPOT_IP" --sport "$HONEYPOT_PORT" \
    -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$COMMENT" -j ACCEPT
  iptables -t nat -I POSTROUTING 1 -o virbr1 -p tcp -d "$HONEYPOT_IP" --dport "$HONEYPOT_PORT" \
    -m comment --comment "$COMMENT" -j MASQUERADE

  ok "live fire enabled"
  cat <<EOF

  Students can now attack the honeypot from the classroom LAN:

      ssh root@${lan_ip} -p ${HOST_PORT}

  Automated brute force (hydra, on the student machine):
      hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 ssh://${lan_ip}:${HOST_PORT}

  Expected on the SOC side: alert on the host controller, Grafana spike at
  http://192.168.122.20:3000, and an incident report in vm2-soc/reports/.

  ${C_WARN}WARNING:${C_RESET} this exposes a deliberately weak fake SSH server to your whole
  LAN. Run 'sudo $0 disable' as soon as the demonstration is over.
EOF
}

do_disable() {
  require_root
  require_iptables
  local nat_removed filter_removed
  nat_removed="$(flush_rules nat)"
  filter_removed="$(flush_rules filter)"
  if [[ "$nat_removed" == "0" && "$filter_removed" == "0" ]]; then
    info "no live-fire rules present"
  else
    ok "removed ${nat_removed} nat rule(s) and ${filter_removed} filter rule(s)"
  fi
}

do_status() {
  require_root
  require_iptables
  WAN_IF="${WAN_IF:-$(detect_wan_if)}"

  local lan_ip
  lan_ip="$(wan_ip)"
  printf '\n%sKVM-Sentinel-SOC live fire — status%s\n\n' "$C_INFO" "$C_RESET"
  printf '  interface        : %s\n' "$WAN_IF"
  printf '  host address     : %s\n' "${lan_ip:-<none>}"
  printf '  forward          : %s:%s -> %s:%s\n' "${lan_ip:-?}" "$HOST_PORT" "$HONEYPOT_IP" "$HONEYPOT_PORT"
  printf '  ip_forward       : %s\n\n' "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"

  printf '  nat rules:\n'
  iptables -t nat -S 2>/dev/null | grep -- "$COMMENT" | sed 's/^/    /' || printf '    (none)\n'
  printf '\n  filter rules:\n'
  iptables -S 2>/dev/null | grep -- "$COMMENT" | sed 's/^/    /' || printf '    (none)\n'

  if rules_present; then
    printf '\n  state            : %sENABLED%s\n' "$C_OK" "$C_RESET"
    printf '\n  student command  : ssh root@%s -p %s\n\n' "${lan_ip:-<LAN_IP>}" "$HOST_PORT"
  else
    printf '\n  state            : %sDISABLED%s\n\n' "$C_WARN" "$C_RESET"
  fi
}

# ------------------------------------------------------------------ arg parse
(($#)) || { usage; exit 1; }
case "$1" in
  enable|disable|status) ACTION="$1"; shift ;;
  --help|-h) usage; exit 0 ;;
  *) die "unknown action: $1 (expected enable, disable or status)" ;;
esac

while (($#)); do
  case "$1" in
    --host-port) HOST_PORT="${2:?--host-port needs a value}"; shift 2 ;;
    --wan-if) WAN_IF="${2:?--wan-if needs a value}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[[ "$HOST_PORT" =~ ^[0-9]+$ ]] || die "--host-port must be numeric"
(( HOST_PORT > 0 && HOST_PORT < 65536 )) || die "--host-port out of range"

case "$ACTION" in
  enable) do_enable ;;
  disable) do_disable ;;
  status) do_status ;;
esac
