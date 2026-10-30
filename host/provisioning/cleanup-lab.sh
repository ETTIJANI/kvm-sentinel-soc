#!/usr/bin/env bash
#
# cleanup-lab.sh — tear the KVM-Sentinel-SOC lab down and leave the host clean.
#
# Removes: both domains, their QCOW2 overlays, the seed ISOs, the rendered
# cloud-init files, the backend-isolated network and the live-fire iptables
# rules. Keeps (by default) downloaded base images, incident reports and the
# Grafana/Loki/Ollama volumes inside the guests (they disappear with the disks).
#
# Referenced by: docs/01-INSTALL-NIXOS.md, docs/02-INSTALL-UBUNTU-DEBIAN.md
#
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
IMAGE_DIR="$SCRIPT_DIR/images"
SEED_DIR="$SCRIPT_DIR/seeds"
BUILD_DIR="$SCRIPT_DIR/build"

VM1="vm-honeypot"
VM2="vm-soc"

FORCE=0
KEEP_REPORTS=0
KEEP_IMAGES=0

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
KVM-Sentinel-SOC — lab teardown

Usage: sudo ./host/provisioning/cleanup-lab.sh [options]

Options:
  --force          do not ask for confirmation
  --keep-reports   keep vm2-soc/reports/*.md and *.json
  --keep-images    keep the QCOW2 overlays (domains are still undefined)
  --help           this message

Always kept: the downloaded Ubuntu base image (~600 MiB, expensive to refetch)
and vm-soc/reports/.gitkeep.
EOF
}

while (($#)); do
  case "$1" in
    --force) FORCE=1; shift ;;
    --keep-reports) KEEP_REPORTS=1; shift ;;
    --keep-images) KEEP_IMAGES=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[[ ${EUID} -eq 0 ]] || die "run with sudo: sudo $0 $*"
command -v virsh >/dev/null 2>&1 || die "virsh not found"

if (( FORCE == 0 )); then
  printf 'This destroys %s and %s and deletes their disks. Type "yes" to continue: ' "$VM1" "$VM2"
  read -r answer
  [[ "$answer" == "yes" ]] || die "aborted by operator"
fi

# ------------------------------------------------------------------- domains
for domain in "$VM1" "$VM2"; do
  if virsh -c qemu:///system dominfo "$domain" >/dev/null 2>&1; then
    info "destroying $domain"
    virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1 || warn "$domain was not running"
    if virsh -c qemu:///system undefine "$domain" --nvram --remove-all-storage >/dev/null 2>&1; then
      ok "$domain undefined (with NVRAM and managed volumes)"
    elif virsh -c qemu:///system undefine "$domain" --nvram >/dev/null 2>&1; then
      ok "$domain undefined (with NVRAM)"
    else
      virsh -c qemu:///system undefine "$domain" >/dev/null 2>&1 || die "could not undefine $domain"
      ok "$domain undefined"
    fi
  else
    info "$domain is not defined — nothing to do"
  fi
done

# ---------------------------------------------------------------- live fire
if [[ -x "$SCRIPT_DIR/enable-live-fire.sh" ]]; then
  "$SCRIPT_DIR/enable-live-fire.sh" disable || warn "live-fire rules could not be fully removed"
fi

# ------------------------------------------------------------------ network
if virsh -c qemu:///system net-info backend-isolated >/dev/null 2>&1; then
  info "removing libvirt network backend-isolated"
  virsh -c qemu:///system net-destroy backend-isolated >/dev/null 2>&1 || true
  virsh -c qemu:///system net-undefine backend-isolated >/dev/null 2>&1 \
    || warn "could not undefine backend-isolated (a guest may still use it)"
  ok "network backend-isolated removed"
else
  info "network backend-isolated is not defined"
fi

# -------------------------------------------------------------------- files
if (( KEEP_IMAGES == 0 )); then
  for overlay in "$IMAGE_DIR/$VM1.qcow2" "$IMAGE_DIR/$VM2.qcow2"; do
    if [[ -f "$overlay" ]]; then
      rm -f -- "$overlay"
      ok "removed $overlay"
    fi
  done
else
  warn "--keep-images: QCOW2 overlays kept in $IMAGE_DIR"
fi

rm -f -- "$SEED_DIR"/*.iso "$BUILD_DIR"/*-user-data "$BUILD_DIR"/SHA256SUMS 2>/dev/null || true
ok "seed ISOs and rendered cloud-init files removed"

if (( KEEP_REPORTS == 0 )); then
  shopt -s nullglob
  reports=("$REPO_ROOT"/vm2-soc/reports/*.md "$REPO_ROOT"/vm2-soc/reports/*.json)
  shopt -u nullglob
  if ((${#reports[@]})); then
    rm -f -- "${reports[@]}"
    ok "removed ${#reports[@]} incident report file(s)"
  fi
else
  warn "--keep-reports: incident reports kept in $REPO_ROOT/vm2-soc/reports"
fi

# ------------------------------------------------------------------ summary
cat <<EOF

${C_OK}Lab torn down.${C_RESET}

  Kept:
    $IMAGE_DIR/$VM1.qcow2 (base image, if it was downloaded)
    $REPO_ROOT/vm2-soc/reports/ (unless --keep-reports was not used)
    libvirt network 'default' (shared with other projects)

  Redeploy with:
    sudo $REPO_ROOT/host/provisioning/deploy-lab.sh
EOF
