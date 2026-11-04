# 01 — Installing KVM-Sentinel-SOC on NixOS

Target: the reference host, an **Intel Core i7-1160G7** laptop with **16 GiB RAM**
(≈11–12 GiB free) running **NixOS 25.05+** with flakes enabled. The unprivileged path below was
validated on NixOS 26.05.

The repository provides a proper NixOS module (`host/nixos/virtualization.nix`) and a dev shell
(`host/nixos/flake.nix`). Nothing is imperative: no `apt install`, no manual `systemctl enable`.

---

## 1. Prerequisites

1. **Virtualization enabled in firmware** — `Intel VT-x` (and IOMMU if the firmware exposes it).
2. **NixOS 25.05** installed and booting, with `nix-command` and `flakes` enabled:

   ```nix
   # /etc/nixos/configuration.nix
   nix.settings.experimental-features = [ "nix-command" "flakes" ];
   ```

3. **~20 GiB free** on the filesystem that will hold the images (the base cloud image is ~600 MiB,
   the two overlays grow on demand up to 10 + 15 GiB).
4. The repository cloned somewhere stable, for example `/home/alice/kvm-sentinel-soc`.

---

## 2. Import the module

Edit `/etc/nixos/configuration.nix` and reference the module by **absolute path** (the file lives in
your home, not in `/etc/nixos`):

```nix
{ config, pkgs, ... }:

{
  imports = [
    ./hardware-configuration.nix
    /home/alice/kvm-sentinel-soc/host/nixos/virtualization.nix
  ];

  # Tell the module who you are: this adds you to libvirtd and kvm.
  kvmSentinel = {
    enable         = true;
    user           = "alice";
    liveFirePort   = 2222;   # classroom DNAT entry point
    controllerPort = 5000;   # approval daemon webhook
  };

  # Unchanged system settings...
  networking.hostName = "hypervisor";
}
```

If you prefer to copy the module instead of referencing it, copy
`virtualization.nix` into `/etc/nixos/` and import `./virtualization.nix`.

### What the module enables

| Setting | Effect |
|---|---|
| `virtualisation.libvirtd` | libvirtd, QEMU/KVM, swtpm, `qemu:///system` |
| `boot.kernelModules` | `kvm-intel`, `vhost_net`, `tun`, `bridge`, `br_netfilter` |
| `net.ipv4.ip_forward = 1` | needed by the classroom DNAT and by `virbr0` NAT |
| `networking.firewall.allowedTCPPorts` | `2222` (live fire) and `5000` (webhook) |
| `networking.firewall.trustedInterfaces` | `virbr0`, `virbr1` |
| `extraForwardRules` | accepts forwarding into/out of the two libvirt bridges and TCP/22 to `10.10.0.10` |
| `environment.systemPackages` | `virsh`, `virt-install`, `qemu-img`, `cloud-localds`, `genisoimage`, `iptables`, `socat`, python with `requests`/`flask`/`rich` |

The isolated network `backend-isolated` is **not** declared in Nix. It is defined from
`host/networks/backend-isolated.xml` by `deploy-lab.sh`, so the exact same XML is used on NixOS,
Ubuntu/Debian and WSL2 hosts.

---

## 3. Apply and reboot

```bash
sudo nixos-rebuild switch --flake /etc/nixos#hypervisor
# or, without flakes for the system itself:
sudo nixos-rebuild switch
```

A reboot is the cleanest way to pick up the `kvm-intel` module and the `libvirtd` group membership:

```bash
sudo reboot
```

---

## 4. Verify the hypervisor

```bash
# KVM is exposed to userspace
ls -l /dev/kvm                      # crw-rw---- root kvm

# your session has the groups
id -nG | tr ' ' '\n' | grep -E 'libvirtd|kvm'

# libvirtd answers on the system connection
virsh -c qemu:///system uri         # qemu:///system

# the NAT network exists (isolated one appears after the first deploy)
virsh -c qemu:///system net-list --all

# nothing running yet
virsh -c qemu:///system list --all
```

If `virsh` says *permission denied*, your shell predates the group change: log out and back in, or
`newgrp libvirtd`.

---

## 5. Work from the flake dev shell

The module installs the tools system-wide, but the dev shell is the reproducible way to get exactly
the versions used by the project (including `shellcheck` for the scripts):

```bash
cd ~/kvm-sentinel-soc
nix develop ./host/nixos

# inside the shell
virsh -c qemu:///system list --all
python3 -c "import flask, rich, requests; print('controller deps ok')"
```

The shell prints the four commands of the demo. `sudo` inside `nix develop` keeps the shell's
`PATH` only if you use `sudo --preserve-env=PATH` or run the scripts by absolute path; the scripts
themselves only need binaries that are also installed system-wide by the module, so plain `sudo`
works.

---

## 6. Firewall notes (nftables vs iptables-nft)

NixOS 25.05 programs the firewall with **nftables**, while `enable-live-fire.sh` speaks
**iptables-nft**. Both land in the kernel's netfilter hooks; the module therefore adds explicit
`extraForwardRules` accepts for the bridges. What you should know:

* `2222/tcp` and `5000/tcp` are open on **all** interfaces because the module puts them in
  `allowedTCPPorts`. On a laptop that roams between networks this is intentional for the classroom
  demo — close them with `networking.firewall.allowedTCPPorts = [ ];` when the lab is over.
* The classroom DNAT only exists while `enable-live-fire.sh enable` is active; removing the rules is
  a single `disable`.
* If you run a third-party firewall (e.g. `firewalld`), disable it or replicate the two accepts;
  libvirt and firewalld fight over the forward chain.

Check the live rules:

```bash
sudo iptables -t nat -S | grep kvm-sentinel-livefire
sudo iptables -S | grep kvm-sentinel-livefire
sudo nft list ruleset | grep -A2 virbr
```

---

## 7. Deploy the lab

```bash
cd ~/kvm-sentinel-soc
./host/provisioning/deploy-lab.sh
```

Run it as a member of `libvirtd` and `kvm`; the script manages `qemu:///system` through polkit.
If `virsh -c qemu:///system uri` fails for your user, run the script with `sudo` or re-login after
adding the groups. The script grants the `qemu-libvirtd` account ACLs to the lab paths so the
rootless hypervisor can open the QCOW2 overlays.

First run takes 10–15 minutes: it downloads the Ubuntu 24.04 cloud image, verifies its SHA256,
creates the QCOW2 overlays, renders the cloud-init seeds from this repository, installs both guests
and waits until the management sshd (`10.10.0.10:22`), the trap (`10.10.0.10:2222`), Grafana
(`192.168.122.20:3000`) and Ollama (`192.168.122.20:11434`) answer. It then detaches the honeypot's
temporary NAT NIC and creates the `clean-baseline` snapshot.

If the host cannot pull the Ollama image/model, readiness still waits at `11434`. The agents use a
deterministic heuristic when Ollama is unavailable; pre-pull the model or plan for a manual
completion on bandwidth-constrained links.

Useful flags:

| Flag | Purpose |
|---|---|
| `--force` | destroy the existing lab and redeploy from scratch |
| `--skip-download` | reuse an already downloaded base image |
| `--keep-bootstrap-nic` | keep vm-honeypot on the NAT network (debug only — breaks isolation) |
| `--ssh-key FILE` | inject a specific public key instead of `~/.ssh/id_*.pub` |
| `--no-baseline-snapshot` | skip the `clean-baseline` snapshot |
| `--wait-timeout SECONDS` | extend the 1800 s readiness window (slow disks) |

---

## 8. Post-deploy verification

```bash
virsh -c qemu:///system list --all
virsh -c qemu:///system domiflist vm-honeypot     # one NIC, backend-isolated
virsh -c qemu:///system snapshot-list vm-honeypot # clean-baseline

ssh soc@10.10.0.10 'cd /opt/honeypot && docker compose ps'
ssh soc@192.168.122.20 'cd /opt/soc && docker compose ps'

curl -s http://192.168.122.20:3000/api/health
curl -s http://192.168.122.20:11434/api/tags
```

Then start the controller and run the first simulation:

```bash
python3 host/controller/approval_daemon.py
# in another terminal
ssh soc@10.10.0.10 'cd /opt/honeypot && docker compose run --rm simulator'
```

If `vm-soc` cannot reach `192.168.122.1:5000`, use the container fallback in §8.1.

### 8.1 Rootless NixOS deployment and the webhook firewall

The unprivileged path was validated on NixOS 26.05. A user in `libvirtd` and `kvm` can deploy and
operate the lab without `sudo`:

```bash
./host/provisioning/deploy-lab.sh
virsh -c qemu:///system list --all
```

On some NixOS hosts, the guest-to-host path to a host-bound controller on TCP `5000` is still
filtered even when `networking.firewall.allowedTCPPorts` lists `5000`. Publish the controller from
a container bound to `virbr0` instead:

```bash
PYTHON_BIN="$(readlink -f "$(command -v python3)")"
PY_TAG="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_USER_SITE="$(python3 -c 'import site; print(site.getusersitepackages())')"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/kvm-sentinel"
mkdir -p "$STATE_DIR"
docker rm -f sentinel-daemon 2>/dev/null || true
docker run -d --name sentinel-daemon --restart unless-stopped \
  -p 192.168.122.1:5000:5000 \
  -e PATH=/run/current-system/sw/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  -e HOME=/root -e SUDO_USER="$USER" -e PYTHONDONTWRITEBYTECODE=1 \
  -v /nix/store:/nix/store:ro \
  -v /run/current-system:/run/current-system:ro \
  -v /run/libvirt:/run/libvirt:ro \
  -v /var/run/libvirt:/var/run/libvirt:ro \
  -v "$PWD:/app:ro" \
  -v "$PY_USER_SITE:/root/.local/lib/python${PY_TAG}/site-packages:ro" \
  -v "$STATE_DIR:/state" \
  --entrypoint "$PYTHON_BIN" \
  alpine:latest /app/host/controller/approval_daemon.py \
  --host 0.0.0.0 --port 5000 \
  --token "${SENTINEL_TOKEN:?export SENTINEL_TOKEN first}" \
  --audit-log /state/incidents.jsonl
```

The container uses the host Nix Python and user site-packages, so a second Python image is not
needed. Docker publishes the port on `virbr0`; the audit file lives on the host at
`$STATE_DIR/incidents.jsonl`. Set `SENTINEL_TOKEN` to the same value as the token in
`/opt/soc/.env`, and change both from the demo default before exposing the lab.

Verify the guest-to-host path and the controller:

```bash
ssh soc@192.168.122.20 'curl -s http://192.168.122.1:5000/health'
curl -s http://192.168.122.1:5000/health
```

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `error: flake 'path:/etc/nixos' does not provide attribute ...` | flake not initialized in `/etc/nixos` | build with `nixos-rebuild switch` (no `--flake`), or `sudo nix flake init -e` |
| `cannot talk to qemu:///system` | session lacks `libvirtd` group | re-login; `id -nG` |
| `/dev/kvm` missing after rebuild | `kvm-intel` not loaded, VT-x off | `sudo modprobe kvm_intel`; check firmware |
| deploy dies on `virbr1 does not carry 10.10.0.1` | `backend-isolated` defined but down | `sudo virsh net-start backend-isolated` |
| `nix develop` is very slow the first time | evaluating/downloading nixpkgs | expected once; subsequent starts are cached |
| Live-fire rules disappear after reboot | iptables rules are not persistent | re-run `enable-live-fire.sh enable` (by design) |
| Grafana unreachable from another machine | NixOS firewall only opened 3000 on the host, and Grafana binds inside the VM | Grafana is meant to be reached at `192.168.122.20:3000` from the host, or via an SSH tunnel |
| deploy fails with `EACCES` opening a QCOW2 | rootless `qemu-libvirtd` cannot traverse `$HOME` | add `acl` to `systemPackages`, re-run the script, or run it with `sudo` |
| `vm-soc` cannot reach `192.168.122.1:5000` | NixOS firewall filters the host-bound controller | use the Docker-published controller in §8.1 |
| deploy waits at `11434` | Ollama image/model pull is slow or offline | pre-pull the model, or complete manually; agents fall back to heuristics |

---

## Next step

→ [04-CLASSROOM-LIVE-FIRE.md](04-CLASSROOM-LIVE-FIRE.md) — attack the honeypot from the classroom
and drive the demo. For the Ubuntu/Debian and WSL2 variants see
[02-INSTALL-UBUNTU-DEBIAN.md](02-INSTALL-UBUNTU-DEBIAN.md) and
[03-INSTALL-WINDOWS-WSL2.md](03-INSTALL-WINDOWS-WSL2.md).
