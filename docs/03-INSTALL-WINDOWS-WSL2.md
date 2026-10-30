# 03 — Installing KVM-Sentinel-SOC on Windows 11 with WSL2

Target: a Windows 11 laptop that must run the whole lab — two KVM guests, the honeypot stack, the SOC
stack and the host controller — **inside WSL2 with nested virtualization**. This path exists for
students who do not dual-boot; read the limitations before committing to it.

Tested shape: Windows 11 23H2, WSL 2.x, Ubuntu 24.04 distro, 16 GiB RAM, Intel VT-x enabled.

---

## 1. Windows prerequisites

| Requirement | How to check |
|---|---|
| Windows 11 22H2 or newer | `winver` |
| Hardware virtualization enabled | Task Manager → Performance → CPU → *Virtualization: Enabled* |
| WSL2 with nested virtualization | WSL 2.0+ (`wsl --version`) |
| ≥ 40 GiB free on the system drive | VHDX grows to ~35 GiB with both guests |
| ≥ 12 GiB RAM | the lab needs ~7 GiB inside WSL |

On Windows 11 **Home**, Virtual Machine Platform and WSL are supported; Hyper-V manager is not
needed.

---

## 2. Configure memory and nested virtualization

Create or edit `C:\Users\<you>\.wslconfig`:

```ini
[wsl2]
memory=12GB
processors=6
swap=4GB
nestedVirtualization=true
```

Then restart WSL completely (this kills all distros):

```powershell
wsl --shutdown
```

`nestedVirtualization=true` is what exposes `/dev/kvm` to the distro. Without it, QEMU falls back to
TCG emulation and the lab is unusably slow (~30× slower boot).

---

## 3. Install the distro and systemd

```powershell
wsl --update
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2
wsl -l -v          # VERSION must be 2
```

Inside Ubuntu, enable systemd so `libvirtd` can be managed as a service — `/etc/wsl.conf`:

```ini
[boot]
systemd=true

[interop]
appendWindowsPath=false
```

Then `wsl --shutdown` again and reopen Ubuntu. Verify:

```bash
ps -p 1 -o comm=        # systemd
ls -l /dev/kvm          # crw-rw---- root kvm
```

If `/dev/kvm` is missing:

1. `wsl --update` (nested virt needs a recent WSL kernel),
2. confirm `nestedVirtualization=true` is spelled exactly and the file is in `%UserProfile%`,
3. `wsl --shutdown`, reboot Windows if you changed firmware settings,
4. check that no other hypervisor (VirtualBox 6, VMware Workstation with Hyper-V off) grabbed VT-x.

---

## 4. Install the virtualization stack (same as Ubuntu)

```bash
sudo apt update
sudo apt install -y \
  qemu-system-x86 qemu-utils \
  libvirt-daemon-system libvirt-clients \
  virtinst cloud-image-utils genisoimage \
  bridge-utils dnsmasq-base \
  iptables iproute2 curl jq socat \
  python3 python3-venv python3-pip \
  openssh-client rsync

sudo usermod -aG libvirtd,kvm "$USER"
sudo systemctl enable --now libvirtd
sudo virsh net-start default 2>/dev/null || true
sudo virsh net-autostart default
sudo sysctl -w net.ipv4.ip_forward=1
```

`virsh net-list --all` must show `default` active with `192.168.122.1`.

> **WSL restarts reset runtime state.** iptables rules, `socat` relays and `netsh portproxy` entries
> do not survive `wsl --shutdown`. `virsh net-autostart` and `systemctl enable` do. Re-run
> `enable-live-fire.sh enable` after every WSL restart.

---

## 5. Deploy the lab

```bash
cd ~/kvm-sentinel-soc
sudo ./host/provisioning/deploy-lab.sh --wait-timeout 2400
```

Nested virtualization roughly doubles boot time; the extended timeout avoids a false failure on the
readiness loop. Expect 20–30 minutes on first run.

If the download is slow on the campus network, pre-seed the image:

```bash
mkdir -p host/provisioning/images
curl -L -o host/provisioning/images/noble-server-cloudimg-amd64.img \
  https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
sudo ./host/provisioning/deploy-lab.sh --skip-download
```

---

## 6. Reach the guests from Windows

Everything lives inside WSL2's network namespace, so Windows sees only the WSL address
(`wsl hostname -I`). Three relays are needed.

### 6.1 Grafana and Ollama — relay with socat inside WSL

```bash
# runs in WSL; localhost forwarding makes them visible to Windows as localhost:3000 / :11434
nohup socat TCP-LISTEN:3000,fork,reuseaddr TCP:192.168.122.20:3000 >/dev/null 2>&1 &
nohup socat TCP-LISTEN:11434,fork,reuseaddr TCP:192.168.122.20:11434 >/dev/null 2>&1 &
```

Then open <http://localhost:3000> in Edge/Chrome (`admin` / `sentinel`).

### 6.2 Classroom live fire — portproxy from Windows

Run **PowerShell as Administrator**:

```powershell
$wslIp = (wsl hostname -I).Trim().Split(" ")[0]
netsh interface portproxy delete v4tov4 listenport=2222 listenaddress=0.0.0.0 | Out-Null
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 `
    connectport=2222 connectaddress=$wslIp
New-NetFirewallRule -DisplayName "KVM-Sentinel honeypot 2222" -Direction Inbound `
    -Protocol TCP -LocalPort 2222 -Action Allow -Profile Private
netsh interface portproxy show v4tov4
```

Re-run the block after every `wsl --shutdown` (the WSL IP changes). To remove:

```powershell
netsh interface portproxy delete v4tov4 listenport=2222 listenaddress=0.0.0.0
Remove-NetFirewallRule -DisplayName "KVM-Sentinel honeypot 2222"
```

Students then attack `ssh root@<WINDOWS_LAN_IP> -p 2222`.

### 6.3 Controller

Run it inside WSL, bound to `192.168.122.1:5000` exactly as on a native host:

```bash
cd ~/kvm-sentinel-soc
python3 -m venv .venv && .venv/bin/pip install -r host/controller/requirements.txt
sudo .venv/bin/python host/controller/approval_daemon.py
```

The prompt appears in the WSL terminal. If you prefer a native Windows console, see §8.

---

## 7. Verify

```bash
virsh -c qemu:///system list --all
virsh -c qemu:///system domiflist vm-honeypot

ssh soc@10.10.0.10    'cd /opt/honeypot && docker compose ps'
ssh soc@192.168.122.20 'cd /opt/soc && docker compose ps'

curl -s http://192.168.122.20:11434/api/tags | jq -r '.models[].name'
```

Then run a simulation as usual:

```bash
ssh soc@10.10.0.10 'cd /opt/honeypot && docker compose run --rm simulator'
```

---

## 8. Optional: controller on Windows instead of WSL

The controller needs `virsh` on the machine where it runs, so it must stay in WSL. If you want the
approval prompt in a Windows terminal, keep the daemon in WSL and drive it over its HTTP API:

```bash
# WSL: start in API-only mode with a shared token
sudo SENTINEL_TOKEN='pick-a-long-random-string' \
  .venv/bin/python host/controller/approval_daemon.py --auto-approve
```

This is **not** the recommended demo path: `--auto-approve` removes the human decision, which is the
whole point. Use it only for an unattended soak test, and say so when presenting.

---

## 9. Limitations on WSL2

| Limitation | Impact | Mitigation |
|---|---|---|
| Nested virtualization overhead | guests boot ~2× slower, LLM tokens/s lower | `--wait-timeout 2400`, expect 60–90 s first AI response |
| WSL IP changes on restart | portproxy + socat die | re-run §6.1/§6.2 after `wsl --shutdown` |
| iptables state is ephemeral | live-fire rules vanish | `enable-live-fire.sh enable` after each restart |
| VHDX grows monotonically | disk can reach ~35 GiB | `wsl --manage Ubuntu-24.04 --set-sparse true` (WSL 2.2+) |
| No GPU passthrough | Ollama is CPU-only | use `qwen2.5:0.5b` (already the default) |
| Sleep/hibernate kills guests | VMs stop abruptly | run `cleanup-lab.sh` before closing the lid, or keep the laptop awake |
| Windows Defender may scan the VHDX | random I/O stalls during snapshots | exclude `%LOCALAPPDATA%\Packages\...\LocalState\ext4.vhdx` |
| Corporate VPNs | may hijack the `192.168.122.0/24` route | disconnect the VPN during the demo |

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/dev/kvm` missing | `nestedVirtualization` not applied | check `.wslconfig`, `wsl --shutdown`, `wsl --update` |
| `qemu-system-x86_64: failed to initialize kvm` | another hypervisor owns VT-x | close VirtualBox/VMware, disable Hyper-V conflicting features |
| deploy is extremely slow | QEMU running in TCG (no KVM) | fix `/dev/kvm` first; do not "wait it out" |
| `localhost:3000` refused from Windows | socat relay not running | restart the socat command in §6.1 |
| Students cannot reach `2222` | portproxy missing or firewall profile wrong | re-run §6.2; check the network profile is *Private* |
| `REMOTE HOST IDENTIFICATION HAS CHANGED` | VM rebuilt | `ssh-keygen -R '[<host>]:2222'` |
| WSL shuts down when idle | Windows power policy | `wsl --shutdown` deliberately between sessions instead |
| Grafana "No data" | Loki not yet receiving after a cold start | give promtail 30 s; check `docker compose logs promtail` inside vm-honeypot |

---

## Next step

→ [04-CLASSROOM-LIVE-FIRE.md](04-CLASSROOM-LIVE-FIRE.md)
