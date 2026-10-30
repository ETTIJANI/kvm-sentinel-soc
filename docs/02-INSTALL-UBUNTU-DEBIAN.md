# 02 — Installing KVM-Sentinel-SOC on Ubuntu / Debian

Target: Ubuntu 24.04 LTS or Debian 12 host with hardware virtualization, ~25 GiB free disk and
~7 GiB free RAM. This is the "classic" apt-based path; the NixOS path is in
[01-INSTALL-NIXOS.md](01-INSTALL-NIXOS.md).

---

## 1. Prerequisites

```bash
egrep -c '(vmx|svm)' /proc/cpuinfo     # must be > 0
free -h                                # >= 7 GiB available
df -h /var/lib/libvirt                 # >= 25 GiB free
```

If `(vmx|svm)` is 0, enable Intel VT-x / AMD-V in the firmware and reboot.

---

## 2. Install the virtualization stack

```bash
sudo apt update
sudo apt install -y \
  qemu-system-x86 qemu-utils \
  libvirt-daemon-system libvirt-clients \
  virtinst cloud-image-utils genisoimage \
  bridge-utils dnsmasq-base \
  iptables iproute2 curl jq \
  python3 python3-venv python3-pip \
  openssh-client rsync
```

| Package | Why |
|---|---|
| `qemu-system-x86`, `qemu-utils` | the hypervisor and `qemu-img` for QCOW2 overlays |
| `libvirt-daemon-system`, `libvirt-clients` | `libvirtd` and `virsh` |
| `virtinst` | `virt-install` |
| `cloud-image-utils` | `cloud-localds` (NoCloud seed ISOs) |
| `genisoimage` | fallback seed builder if `cloud-localds` is unavailable |
| `dnsmasq-base` | DHCP/DNS for the `default` NAT network |

---

## 3. Add yourself to the right groups

```bash
sudo usermod -aG libvirtd,kvm "$USER"
newgrp libvirtd          # or log out / log back in
id -nG | tr ' ' '\n' | grep -E 'libvirtd|kvm'
```

From now on `virsh` works without `sudo`.

---

## 4. Enable libvirtd and the NAT network

```bash
sudo systemctl enable --now libvirtd
sudo systemctl status libvirtd --no-pager

virsh -c qemu:///system net-list --all
# if 'default' is inactive:
sudo virsh net-start default
sudo virsh net-autostart default
virsh -c qemu:///system net-dumpxml default | grep -E 'ip address|forward'
# expected: ip address='192.168.122.1' netmask='255.255.255.0', forward mode='nat'
```

The isolated `backend-isolated` network is created by `deploy-lab.sh` from
`host/networks/backend-isolated.xml`.

---

## 5. Enable IPv4 forwarding (persistently)

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-kvm-sentinel.conf
sudo sysctl --system
cat /proc/sys/net/ipv4/ip_forward     # 1
```

`deploy-lab.sh` and `enable-live-fire.sh` also set it at runtime, but persisting it avoids a silent
breakage after a reboot.

---

## 6. Firewall

With **ufw** (the Debian/Ubuntu default when enabled):

```bash
# webhook: only vm-soc may call the controller
sudo ufw allow from 192.168.122.0/24 to any port 5000 proto tcp

# live fire: only your classroom subnet, adapt to your network
sudo ufw allow from 192.168.1.0/24 to any port 2222 proto tcp

# never expose these beyond the host
sudo ufw deny 3000/tcp
sudo ufw deny 3100/tcp
sudo ufw deny 11434/tcp

sudo ufw reload
sudo ufw status numbered
```

If ufw is disabled, no action is needed — but note that the classroom DNAT will still work, because
it is installed directly in iptables.

> Grafana, Loki and Ollama live **inside** the `192.168.122.0/24` NAT network; they are reachable
> from the host at `192.168.122.20`, not on the host's own addresses. Opening `3000/tcp` on the host
> would open nothing useful.

---

## 7. Python environment for the controller

The controller runs on the host (it needs `virsh`), not in a container.

```bash
cd ~/kvm-sentinel-soc
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r host/controller/requirements.txt
.venv/bin/python host/controller/approval_daemon.py --help
```

---

## 8. Deploy

```bash
cd ~/kvm-sentinel-soc
sudo ./host/provisioning/deploy-lab.sh
```

The script performs a preflight (binaries, `/dev/kvm`, libvirtd, RAM, disk), defines and starts the
isolated network, downloads and SHA256-verifies the Ubuntu 24.04 cloud image, creates the overlays,
renders the cloud-init seeds **from this repository**, boots both guests, waits for the services,
detaches the honeypot's bootstrap NIC and creates the `clean-baseline` snapshot.

---

## 9. Verify

```bash
virsh -c qemu:///system list --all
virsh -c qemu:///system domiflist vm-honeypot
virsh -c qemu:///system snapshot-list vm-honeypot

ssh soc@10.10.0.10    'cd /opt/honeypot && docker compose ps'
ssh soc@192.168.122.20 'cd /opt/soc && docker compose ps'

curl -s http://192.168.122.20:3000/api/health
curl -s http://192.168.122.20:11434/api/tags
curl -s http://192.168.122.1:5000/health     # only once the controller runs
```

Then:

```bash
sudo .venv/bin/python host/controller/approval_daemon.py
ssh soc@10.10.0.10 'cd /opt/honeypot && docker compose run --rm simulator'
```

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot recv data: Connection reset by peer` on `virt-install` | AppArmor profile blocking the disk path | keep images under `~/kvm-sentinel-soc/host/provisioning/images/` (a user path) or add the path to `/etc/apparmor.d/local/abstractions/libvirt-qemu` |
| `default` network has no DHCP leases | `dnsmasq-base` missing or `default` not started | `sudo apt install dnsmasq-base; sudo virsh net-start default` |
| deploy says `/dev/kvm` not writable | user not in `kvm` group | `sudo usermod -aG kvm $USER`, re-login |
| `only N MiB RAM available` | other workloads | stop them; the lab needs ~7 GiB |
| SSH to `192.168.122.20` hangs | `default` NAT down or the NIC has no lease | `virsh domifaddr vm-soc --source lease`; `virsh console vm-soc` |
| `docker: command not found` inside a guest | cloud-init still running | `ssh soc@... 'sudo cloud-init status --wait; sudo journalctl -u cloud-init -n 50'` |
| Controller cannot bind `192.168.122.1` | `virbr0` missing at that moment | start the controller after the network; it automatically falls back to `0.0.0.0` |
| Live-fire works locally but not from students | ufw blocking `2222`, or the wrong LAN IP | `sudo ./host/provisioning/enable-live-fire.sh status` |

---

## Next step

→ [04-CLASSROOM-LIVE-FIRE.md](04-CLASSROOM-LIVE-FIRE.md)
