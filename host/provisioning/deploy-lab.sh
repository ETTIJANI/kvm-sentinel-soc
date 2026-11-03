#!/usr/bin/env bash
#
# deploy-lab.sh — build the KVM-Sentinel-SOC lab from a bare libvirt host.
#
# Creates:
#   * the isolated libvirt network backend-isolated (virbr1, 10.10.0.0/24)
#   * two Ubuntu 24.04 cloud-image guests backed by QCOW2 overlays
#       vm-honeypot : 1 GiB / 1 vCPU / 10 GiB  (10.10.0.10)
#       vm-soc      : 4 GiB / 4 vCPU / 15 GiB  (192.168.122.20 + 10.10.0.20)
#   * NoCloud seed ISOs rendered from cloud-init-vm1/ and cloud-init-vm2/
#
# Why vm-honeypot gets a temporary second NIC:
#   The trap VM must end up with NO route to the internet. But cloud-init has
#   to pull Docker images and build the honeypot/simulator images on first
#   boot. So the guest is created with a bootstrap NIC on the NAT network,
#   and that NIC is detached only once cloud-init reports completion on
#   10.10.0.10:9999 (one-shot beacon, written after the image builds).
#   Port 22 on that VM stays the management sshd; the trap listens on 2222.
#   Use --keep-bootstrap-nic to keep it for debugging (the lab is then no
#   longer isolated — never do that during a demo).
#
# Referenced by: docs/01-INSTALL-NIXOS.md, docs/02-INSTALL-UBUNTU-DEBIAN.md,
#                docs/03-INSTALL-WINDOWS-WSL2.md
#
set -Eeuo pipefail
IFS=$'\n\t'
umask 022

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd -P)"
NET_XML="$REPO_ROOT/host/networks/backend-isolated.xml"
IMAGE_DIR="$SCRIPT_DIR/images"
SEED_DIR="$SCRIPT_DIR/seeds"
BUILD_DIR="$SCRIPT_DIR/build"

IMAGE_NAME="noble-server-cloudimg-amd64.img"
BASE_IMAGE="$IMAGE_DIR/$IMAGE_NAME"
IMAGE_URL="https://cloud-images.ubuntu.com/noble/current/$IMAGE_NAME"
SUMS_URL="https://cloud-images.ubuntu.com/noble/current/SHA256SUMS"

VM1="vm-honeypot"
VM2="vm-soc"
VM1_MAC_LAN="52:54:00:10:10:01"
VM1_MAC_BOOTSTRAP="52:54:00:bb:00:01"
VM2_MAC_LAN="52:54:00:ac:12:20"
VM2_MAC_BACKEND="52:54:00:10:10:02"
VM1_BACKEND_IP="10.10.0.10"
VM2_NAT_IP="192.168.122.20"
VM2_BACKEND_IP="10.10.0.20"

FORCE=0
SKIP_DOWNLOAD=0
KEEP_BOOTSTRAP=0
BASELINE_SNAPSHOT=1
WAIT_TIMEOUT=1800
SSH_KEY_FILE=""

# ------------------------------------------------------------------- helpers
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
KVM-Sentinel-SOC — lab provisioning

Usage: ./host/provisioning/deploy-lab.sh [options]

  Runs as root or, on hosts where polkit lets members of the 'libvirtd'
  group manage qemu:///system (NixOS default), as that unprivileged user.

Options:
  --force                 destroy existing lab domains/overlays and redeploy
  --skip-download         do not download the base image (must already exist)
  --keep-bootstrap-nic    keep vm-honeypot's temporary NAT NIC (NOT isolated)
  --ssh-key FILE          public key injected into the 'soc' user (default:
                          ~/.ssh/id_ed25519.pub, ~/.ssh/id_rsa.pub if present)
  --no-baseline-snapshot  skip the 'clean-baseline' snapshot of vm-honeypot
  --wait-timeout SECONDS  max time to wait for the guests (default: ${WAIT_TIMEOUT})
  --help                  this message

After a successful run:
  sudo python3 host/controller/approval_daemon.py
  ssh soc@${VM1_BACKEND_IP}        # password: sentinel
EOF
}

require_privileges() {
  if [[ ${EUID} -eq 0 ]]; then
    return 0
  fi
  # Unprivileged operation is supported when polkit authorises this user to
  # manage qemu:///system (a 'libvirtd' group member on NixOS). Every libvirt
  # call below uses the system connection, so the hypervisor still runs the
  # guests as its own service account.
  if ! virsh -c qemu:///system uri >/dev/null 2>&1; then
    die "cannot talk to qemu:///system. Run with sudo, or join the 'libvirtd' group and re-login."
  fi
  if [[ " $(id -nG) " != *" libvirtd "* ]]; then
    die "$(id -un) is not in the 'libvirtd' group; run with sudo: sudo $0 $*"
  fi
  info "unprivileged mode: managing qemu:///system through libvirt/polkit"
}

# On rootless NixOS, qemu:///system launches guests as the qemu-libvirtd
# service account while the lab lives under $HOME (usually mode 0700). Grant
# that account traverse access to the home directory and read/write access to
# the disks this run just created. No-op as root or when the account is absent.
grant_qemu_access() {
  (( EUID == 0 )) && return 0
  getent passwd qemu-libvirtd >/dev/null 2>&1 || return 0
  if ! command -v setfacl >/dev/null 2>&1; then
    warn "setfacl not found; if a domain fails with EACCES, install 'acl' or run with sudo"
    return 0
  fi

  setfacl -m u:qemu-libvirtd:--x "$HOME" 2>/dev/null \
    || warn "could not add a traverse ACL on $HOME"
  local path="$REPO_ROOT"
  while [[ "$path" != "$HOME" && "$path" != "/" ]]; do
    setfacl -m u:qemu-libvirtd:r-x "$path" 2>/dev/null || true
    path="$(dirname -- "$path")"
  done

  local dir file
  for dir in "$IMAGE_DIR" "$SEED_DIR" "$BUILD_DIR"; do
    [[ -d "$dir" ]] && setfacl -m u:qemu-libvirtd:r-x "$dir" 2>/dev/null || true
  done
  [[ -f "$BASE_IMAGE" ]] && setfacl -m u:qemu-libvirtd:r-- "$BASE_IMAGE" 2>/dev/null || true
  for file in "$IMAGE_DIR/$VM1.qcow2" "$IMAGE_DIR/$VM2.qcow2"; do
    [[ -f "$file" ]] && setfacl -m u:qemu-libvirtd:rw- "$file" 2>/dev/null || true
  done
  ok "granted qemu-libvirtd access to the lab disks (rootless hypervisor)"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

# ------------------------------------------------------------------ arg parse
while (($#)); do
  case "$1" in
    --force) FORCE=1; shift ;;
    --skip-download) SKIP_DOWNLOAD=1; shift ;;
    --keep-bootstrap-nic) KEEP_BOOTSTRAP=1; shift ;;
    --ssh-key) SSH_KEY_FILE="${2:?--ssh-key needs a file}"; shift 2 ;;
    --no-baseline-snapshot) BASELINE_SNAPSHOT=0; shift ;;
    --wait-timeout) WAIT_TIMEOUT="${2:?--wait-timeout needs a value}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
done

[[ "$WAIT_TIMEOUT" =~ ^[0-9]+$ ]] || die "--wait-timeout must be a number of seconds"
require_privileges "$@"

# ------------------------------------------------------------------ preflight
preflight() {
  info "preflight checks"
  local missing=()
  for bin in virsh qemu-img virt-install curl python3 sha256sum awk df ip; do
    command -v "$bin" >/dev/null 2>&1 || missing+=("$bin")
  done
  if ((${#missing[@]})); then
    die "missing required commands: ${missing[*]} (install libvirt, qemu, virtinst, cloud-image-utils, curl)"
  fi
  if ! command -v cloud-localds >/dev/null 2>&1 && ! command -v genisoimage >/dev/null 2>&1 && \
     ! command -v mkisofs >/dev/null 2>&1; then
    die "need cloud-localds (cloud-image-utils) or genisoimage (cdrkit/genisoimage) to build the seed ISOs"
  fi

  [[ -w "$(dirname "$IMAGE_DIR")" ]] || die "$(dirname "$IMAGE_DIR") is not writable; run with sudo"
  mkdir -p "$IMAGE_DIR" "$SEED_DIR" "$BUILD_DIR"

  if [[ ! -e /dev/kvm ]]; then
    die "/dev/kvm is missing. Enable Intel VT-x/AMD-V in firmware, load kvm_intel, and on Windows 11 set '[wsl2] nestedVirtualization=true' (see docs/03-INSTALL-WINDOWS-WSL2.md)."
  fi
  if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
    die "/dev/kvm exists but is not readable/writable by this user. Add yourself to the 'kvm' group and re-login."
  fi

  local ram_mb
  ram_mb="$(awk '/^MemAvailable:/ { printf "%d", $2 / 1024 }' /proc/meminfo)"
  if (( ram_mb < 7000 )); then
    die "only ${ram_mb} MiB RAM available, the lab needs ~5500 MiB (1024 + 4096 + QEMU overhead). Close applications and retry."
  fi
  local disk_mb
  disk_mb="$(df -Pm "$IMAGE_DIR" | awk 'NR==2 { print $4 }')"
  if (( disk_mb < 25000 )); then
    die "only ${disk_mb} MiB free under $IMAGE_DIR, need >= 25000 MiB (base image + 2 overlays)"
  fi

  if ! virsh -c qemu:///system uri >/dev/null 2>&1; then
    die "cannot talk to qemu:///system. Is libvirtd running? Are you in the 'libvirtd' group? (sudo usermod -aG libvirtd \$USER && newgrp libvirtd)"
  fi
  ok "preflight passed (${ram_mb} MiB RAM available, ${disk_mb} MiB disk free)"
}

# ------------------------------------------------------------------- networks
ensure_networks() {
  info "ensuring libvirt networks"

  if ! virsh -c qemu:///system net-info default >/dev/null 2>&1; then
    warn "libvirt network 'default' is not defined; virt-install will fail for the bootstrap NIC"
  elif [[ "$(virsh -c qemu:///system net-info default | awk '/^Active:/ { print $2 }')" != "yes" ]]; then
    info "starting libvirt network 'default'"
    virsh -c qemu:///system net-start default >/dev/null
    virsh -c qemu:///system net-autostart default >/dev/null
  fi

  if ! virsh -c qemu:///system net-info backend-isolated >/dev/null 2>&1; then
    info "defining backend-isolated from $NET_XML"
    virsh -c qemu:///system net-define "$NET_XML" >/dev/null
    virsh -c qemu:///system net-autostart backend-isolated >/dev/null
    virsh -c qemu:///system net-start backend-isolated >/dev/null
  elif [[ "$(virsh -c qemu:///system net-info backend-isolated | awk '/^Active:/ { print $2 }')" != "yes" ]]; then
    info "starting backend-isolated"
    virsh -c qemu:///system net-start backend-isolated >/dev/null
  fi

  # The bridge address is what the host uses to reach the guests (and what the
  # MASQUERADE rule rewrites to). Give libvirt a moment to apply it.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    ip -4 addr show virbr1 2>/dev/null | grep -F "10.10.0.1" >/dev/null 2>&1 && break
    sleep 1
  done
  ip -4 addr show virbr1 2>/dev/null | grep -F "10.10.0.1" >/dev/null 2>&1 \
    || die "virbr1 does not carry 10.10.0.1 — inspect 'virsh net-dumpxml backend-isolated' and 'ip addr show virbr1'"

  ok "networks ready (virbr0 192.168.122.0/24 NAT, virbr1 10.10.0.0/24 isolated)"
}

# ---------------------------------------------------------------------- image
fetch_base_image() {
  if [[ -f "$BASE_IMAGE" ]]; then
    ok "base image already present: $BASE_IMAGE"
    return
  fi
  (( SKIP_DOWNLOAD == 0 )) || die "--skip-download given but $BASE_IMAGE does not exist"

  info "downloading Ubuntu 24.04 cloud image (~600 MiB)"
  curl -fL --retry 3 --retry-delay 3 --progress-bar -o "$BASE_IMAGE.part" "$IMAGE_URL"

  info "verifying SHA256"
  curl -fsSL --retry 3 -o "$BUILD_DIR/SHA256SUMS" "$SUMS_URL"
  local expected actual
  expected="$(awk -v f="$IMAGE_NAME" '{ n=$2; sub(/^\*/, "", n); if (n == f) { print $1; exit } }' "$BUILD_DIR/SHA256SUMS")"
  if [[ -z "$expected" ]]; then
    warn "no checksum entry for $IMAGE_NAME in SHA256SUMS — skipping verification"
  else
    actual="$(sha256sum "$BASE_IMAGE.part" | awk '{ print $1 }')"
    [[ "$actual" == "$expected" ]] || die "SHA256 mismatch for $IMAGE_NAME (expected $expected, got $actual)"
    ok "SHA256 verified"
  fi
  mv -f "$BASE_IMAGE.part" "$BASE_IMAGE"
}

# ------------------------------------------------------------------- overlays
create_overlays() {
  local domain="$1" overlay="$2" size="$3"
  if [[ -f "$overlay" ]]; then
    if (( FORCE == 0 )); then
      die "$overlay already exists. Re-run with --force (destroys the lab VMs) or run ./host/provisioning/cleanup-lab.sh"
    fi
    info "removing existing overlay $overlay (--force)"
    rm -f -- "$overlay"
  fi
  qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$overlay" "$size" >/dev/null
  ok "overlay $domain -> $overlay ($size, backing file $IMAGE_NAME)"
}

# -------------------------------------------------------------- user-data
# Renders a cloud-init template into $BUILD_DIR/<vm>-user-data.
#   __SSH_AUTHORIZED_KEYS__ -> the collected public keys (or the line is removed)
#   __PAYLOAD_FILES__       -> write_files entries for the whole payload tree,
#                              base64 encoded, injected so that the repository
#                              stays the single source of truth for the guest
#                              configuration (no copy of the stack in the seed).
SSH_KEYS=()
collect_ssh_keys() {
  if [[ -n "$SSH_KEY_FILE" ]]; then
    [[ -f "$SSH_KEY_FILE" ]] || die "--ssh-key $SSH_KEY_FILE does not exist"
    SSH_KEYS+=("$(<"$SSH_KEY_FILE")")
    return 0
  fi
  local candidate
  for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
    [[ -f "$candidate" ]] || continue
    SSH_KEYS+=("$(<"$candidate")")
  done
}

render_user_data() {
  local vm="$1" template="$2" payload_root="$3" payload_dest="$4" out="$5"

  [[ -f "$template" ]] || die "missing cloud-init template: $template"
  [[ -d "$payload_root" ]] || die "missing payload directory: $payload_root"

  python3 - "$template" "$out" "$payload_root" "$payload_dest" ${SSH_KEYS[@]+"${SSH_KEYS[@]}"} <<'PY'
import base64
import json
import os
import sys
from pathlib import Path

template_path, out_path, payload_root, payload_dest, *keys = sys.argv[1:]

text = Path(template_path).read_text(encoding="utf-8")

for token in ("__SSH_AUTHORIZED_KEYS__", "__PAYLOAD_FILES__"):
    if token not in text:
        sys.exit(f"template {template_path} is missing the {token} token")

SKIP_DIRS = {"__pycache__", ".git", "logs", "state", "seeds", "images", "build"}
SKIP_SUFFIX = {".pyc", ".pyo", ".qcow2", ".iso", ".part"}
EXEC_NAMES = {"main.py", "approval_daemon.py", "simulate_attack.py", "entrypoint.sh"}

entries: list[str] = []
root = Path(payload_root)
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
    for name in sorted(filenames):
        path = Path(dirpath) / name
        rel = path.relative_to(root).as_posix()
        if name in {".gitkeep", ".DS_Store"}:
            continue
        if rel.startswith("reports/") and path.suffix in {".md", ".json"}:
            continue
        if path.suffix in SKIP_SUFFIX:
            continue
        mode = "0755" if (rel.endswith(".sh") or name in EXEC_NAMES) else "0644"
        b64 = base64.b64encode(path.read_bytes()).decode("ascii")
        entries.append(
            f"  - path: {payload_dest}/{rel}\n"
            f"    permissions: '{mode}'\n"
            f"    encoding: b64\n"
            f"    content: {b64}\n"
        )

if not entries:
    sys.exit(f"payload tree {payload_root} produced no write_files entries")

inline_keys = "[" + ", ".join(json.dumps(k) for k in keys) + "]" if keys else "[]"

out_lines: list[str] = []
for line in text.splitlines(keepends=True):
    stripped = line.strip()
    # templates document their own tokens in comments; keep those verbatim
    if stripped.startswith("#"):
        out_lines.append(line)
        continue
    if "__PAYLOAD_FILES__" in line:
        if stripped != "__PAYLOAD_FILES__":
            sys.exit(f"mis-indented __PAYLOAD_FILES__ in {template_path}: {line!r}")
        out_lines.extend(entries)
    elif "__SSH_AUTHORIZED_KEYS__" in line:
        if keys:
            out_lines.append(line.replace("__SSH_AUTHORIZED_KEYS__", inline_keys))
        # with no key available the whole line is dropped: an empty
        # ssh_authorized_keys key would be YAML null and cloud-init rejects it
    else:
        out_lines.append(line)

for number, line in enumerate(out_lines, start=1):
    if line.lstrip().startswith("#"):
        continue
    for token in ("__SSH_AUTHORIZED_KEYS__", "__PAYLOAD_FILES__"):
        if token in line:
            sys.exit(f"token {token} still present at line {number} after rendering {template_path}")

rendered = "".join(out_lines)

Path(out_path).write_text(rendered, encoding="utf-8")
print(f"rendered {template_path} -> {out_path} ({len(entries)} payload files, {len(keys)} ssh key(s))",
      file=sys.stderr)
PY

  [[ -s "$out" ]] || die "rendering produced an empty file: $out"
}

build_seed() {
  local vm="$1" cidir="$2"
  local seed="$SEED_DIR/$vm-seed.iso"
  local user_data="$BUILD_DIR/$vm-user-data"
  local meta_data="$SCRIPT_DIR/$cidir/meta-data"
  local net_config="$SCRIPT_DIR/$cidir/network-config"

  rm -f -- "$seed"
  if command -v cloud-localds >/dev/null 2>&1; then
    cloud-localds --network-config="$net_config" "$seed" "$user_data" "$meta_data"
  else
    local tmp
    tmp="$(mktemp -d)"
    cp "$user_data" "$tmp/user-data"
    cp "$meta_data" "$tmp/meta-data"
    cp "$net_config" "$tmp/network-config"
    if command -v genisoimage >/dev/null 2>&1; then
      genisoimage -quiet -output "$seed" -volid cidata -joliet -rock "$tmp"
    else
      mkisofs -quiet -output "$seed" -volid cidata -joliet -rock "$tmp"
    fi
    rm -rf -- "$tmp"
  fi
  [[ -s "$seed" ]] || die "seed ISO was not created: $seed"
  ok "seed ISO $seed ($(du -h "$seed" | cut -f1))"
}

# ------------------------------------------------------------------- domains
domain_exists() {
  virsh -c qemu:///system dominfo "$1" >/dev/null 2>&1
}

create_vm1() {
  if domain_exists "$VM1"; then
    die "$VM1 is already defined. Use --force (destroys it) or cleanup-lab.sh."
  fi
  info "creating $VM1 (1 GiB / 1 vCPU)"
  virt-install \
    --connect qemu:///system \
    --name "$VM1" \
    --description "KVM-Sentinel-SOC SSH honeypot (isolated 10.10.0.10)" \
    --memory 1024 \
    --vcpus 1 \
    --cpu host-passthrough \
    --osinfo ubuntu24.04 \
    --import \
    --disk path="$IMAGE_DIR/$VM1.qcow2",format=qcow2,bus=virtio,cache=none,discard=unmap \
    --disk path="$SEED_DIR/$VM1-seed.iso",device=cdrom \
    --network network=default,model=virtio,mac="$VM1_MAC_BOOTSTRAP" \
    --network network=backend-isolated,model=virtio,mac="$VM1_MAC_LAN" \
    --graphics none \
    --console pty,target_type=serial \
    --noautoconsole \
    --autostart \
    --wait 0 >/dev/null
  ok "$VM1 defined (bootstrap NIC + isolated NIC)"
}

create_vm2() {
  if domain_exists "$VM2"; then
    die "$VM2 is already defined. Use --force (destroys it) or cleanup-lab.sh."
  fi
  info "creating $VM2 (4 GiB / 4 vCPU)"
  virt-install \
    --connect qemu:///system \
    --name "$VM2" \
    --description "KVM-Sentinel-SOC brain: Loki, Grafana, Ollama, AI agents" \
    --memory 4096 \
    --vcpus 4,sockets=1,cores=4,threads=1 \
    --cpu host-passthrough \
    --osinfo ubuntu24.04 \
    --import \
    --disk path="$IMAGE_DIR/$VM2.qcow2",format=qcow2,bus=virtio,cache=none,discard=unmap \
    --disk path="$SEED_DIR/$VM2-seed.iso",device=cdrom \
    --network network=default,model=virtio,mac="$VM2_MAC_LAN" \
    --network network=backend-isolated,model=virtio,mac="$VM2_MAC_BACKEND" \
    --graphics none \
    --console pty,target_type=serial \
    --noautoconsole \
    --autostart \
    --wait 0 >/dev/null
  ok "$VM2 defined (NAT + isolated)"
}

destroy_existing() {
  (( FORCE == 1 )) || return 0
  local domain
  for domain in "$VM1" "$VM2"; do
    if domain_exists "$domain"; then
      info "--force: destroying and undefining $domain"
      virsh -c qemu:///system destroy "$domain" >/dev/null 2>&1 || true
      virsh -c qemu:///system undefine "$domain" --nvram >/dev/null 2>&1 \
        || virsh -c qemu:///system undefine "$domain" >/dev/null 2>&1 || true
    fi
  done
}

# ----------------------------------------------------------------- readiness
wait_for_port() {
  local host="$1" port="$2" label="$3"
  local deadline=$((SECONDS + WAIT_TIMEOUT))
  local last_note=0

  info "waiting for $label at $host:$port (timeout ${WAIT_TIMEOUT}s)"
  while true; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
      ok "$label is up on $host:$port"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      warn "$label did not come up within ${WAIT_TIMEOUT}s"
      return 1
    fi
    if (( SECONDS - last_note >= 30 )); then
      last_note=$SECONDS
      info "  ...still waiting for $label ($((deadline - SECONDS))s left)"
    fi
    sleep 5
  done
}

wait_for_cloud_init() {
  local deadline=$((SECONDS + WAIT_TIMEOUT))
  local last_note=0

  info "waiting for $VM1 cloud-init (Docker install + image builds) before NIC detach"
  while true; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/$VM1_BACKEND_IP/9999" 2>/dev/null; then
      ok "$VM1 cloud-init finished (ready beacon consumed)"
      return 0
    fi
    if (( SECONDS >= deadline )); then
      warn "$VM1 cloud-init did not finish within ${WAIT_TIMEOUT}s"
      return 1
    fi
    if (( SECONDS - last_note >= 30 )); then
      last_note=$SECONDS
      info "  ...still waiting for $VM1 cloud-init ($((deadline - SECONDS))s left)"
    fi
    sleep 5
  done
}

detach_bootstrap_nic() {
  if (( KEEP_BOOTSTRAP == 1 )); then
    warn "--keep-bootstrap-nic: $VM1 keeps its NAT NIC. The honeypot is NOT isolated."
    return 0
  fi
  info "detaching $VM1 bootstrap NIC ($VM1_MAC_BOOTSTRAP) — the trap is now isolated"
  virsh -c qemu:///system detach-interface "$VM1" network --mac "$VM1_MAC_BOOTSTRAP" --config >/dev/null \
    || warn "persistent detach failed; trying live detach only"
  virsh -c qemu:///system detach-interface "$VM1" network --mac "$VM1_MAC_BOOTSTRAP" >/dev/null \
    || warn "live detach failed; check 'virsh domiflist $VM1'"

  local remaining
  remaining="$(virsh -c qemu:///system domiflist "$VM1" 2>/dev/null | grep -c 'backend-isolated' || true)"
  if [[ "$remaining" == "0" ]]; then
    die "$VM1 lost its isolated NIC during detach — run ./host/provisioning/cleanup-lab.sh and redeploy"
  fi
  ok "$VM1 now has a single NIC on backend-isolated"
}

create_baseline_snapshot() {
  (( BASELINE_SNAPSHOT == 1 )) || { info "skipping baseline snapshot (--no-baseline-snapshot)"; return 0; }
  if virsh -c qemu:///system snapshot-list "$VM1" --name 2>/dev/null | grep -x 'clean-baseline' >/dev/null 2>&1; then
    ok "baseline snapshot 'clean-baseline' already exists"
    return 0
  fi
  info "creating baseline snapshot 'clean-baseline' (used by restore-honeypot.sh --revert)"
  virsh -c qemu:///system snapshot-create-as "$VM1" --name clean-baseline \
    --description "Pristine lab state (KVM-Sentinel-SOC)" --atomic >/dev/null \
    || warn "could not create the baseline snapshot; restore-honeypot.sh --revert will be unavailable"
  ok "baseline snapshot ready"
}

# -------------------------------------------------------------------- summary
summary() {
  cat <<EOF

${C_OK}KVM-Sentinel-SOC is deployed.${C_RESET}

  ${C_INFO}Guests${C_RESET}
    vm-honeypot   1 vCPU / 1024 MiB   eth0 ${VM1_BACKEND_IP}/24   (isolated, no default route)
    vm-soc        4 vCPU / 5120 MiB   eth0 ${VM2_NAT_IP}/24  eth1 ${VM2_BACKEND_IP}/24

  ${C_INFO}Access${C_RESET}
    SSH into the SOC brain    ssh soc@${VM2_NAT_IP}        (password: sentinel)
    SSH into the honeypot     ssh soc@${VM1_BACKEND_IP}    (password: sentinel)
    The trap itself           ssh -p 2222 root@${VM1_BACKEND_IP}   (password: toor — intentionally weak)
    Grafana                   http://${VM2_NAT_IP}:3000    (admin / sentinel)
    Loki push endpoint        http://${VM2_BACKEND_IP}:3100/loki/api/v1/push
    Ollama API                http://${VM2_NAT_IP}:11434

  ${C_INFO}Next steps${C_RESET}
    1. start the human-in-the-loop controller (on this host):
         sudo python3 host/controller/approval_daemon.py
    2. generate a first attack (on VM1):
         ssh soc@${VM1_BACKEND_IP} 'cd /opt/honeypot && docker compose run --rm simulator'
    3. open the SOC dashboard: http://${VM2_NAT_IP}:3000
    4. classroom live fire (exposes 2222 to your LAN):
         sudo ./host/provisioning/enable-live-fire.sh enable

  ${C_INFO}Reset between demos${C_RESET}
       sudo ./host/controller/restore-honeypot.sh --revert
       (or: sudo ./host/provisioning/cleanup-lab.sh --force  to start over)
EOF
}

# ----------------------------------------------------------------------- main
main() {
  info "KVM-Sentinel-SOC deploy — repo $REPO_ROOT"
  preflight
  ensure_networks
  destroy_existing
  fetch_base_image
  create_overlays "$VM1" "$IMAGE_DIR/$VM1.qcow2" "10G"
  create_overlays "$VM2" "$IMAGE_DIR/$VM2.qcow2" "15G"
  grant_qemu_access

  info "rendering cloud-init user-data"
  collect_ssh_keys
  if ((${#SSH_KEYS[@]})); then
    info "injecting ${#SSH_KEYS[@]} ssh public key(s) for the 'soc' user"
  else
    warn "no ssh public key found: the guests will rely on password auth (soc/sentinel)"
  fi
  render_user_data "$VM1" "$SCRIPT_DIR/cloud-init-vm1/user-data" \
    "$REPO_ROOT/vm1-honeypot" "/opt/honeypot" "$BUILD_DIR/$VM1-user-data"
  render_user_data "$VM2" "$SCRIPT_DIR/cloud-init-vm2/user-data" \
    "$REPO_ROOT/vm2-soc" "/opt/soc" "$BUILD_DIR/$VM2-user-data"

  build_seed "$VM1" cloud-init-vm1
  build_seed "$VM2" cloud-init-vm2

  create_vm1
  create_vm2

  local failures=0
  wait_for_port "$VM1_BACKEND_IP" 22 "$VM1 sshd (management)" || failures=$((failures + 1))
  wait_for_cloud_init || failures=$((failures + 1))
  wait_for_port "$VM2_NAT_IP" 3000 "$VM2 Grafana" || failures=$((failures + 1))
  wait_for_port "$VM2_NAT_IP" 11434 "$VM2 Ollama" || failures=$((failures + 1))

  if (( failures > 0 )); then
    warn "$failures readiness check(s) failed. Inspect with:"
    warn "  virsh -c qemu:///system console $VM1   (Ctrl-] to leave)"
    warn "  ssh soc@${VM2_NAT_IP} 'sudo cloud-init status --long; sudo journalctl -u cloud-init -n 80 --no-pager'"
    warn "  ssh soc@${VM1_BACKEND_IP} 'sudo journalctl -u cloud-init -n 80 --no-pager'"
    die "deployment incomplete — the VMs keep running so you can debug them"
  fi

  detach_bootstrap_nic
  create_baseline_snapshot
  summary
}

main "$@"
