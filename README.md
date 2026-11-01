# KVM-Sentinel-SOC

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A hypervisor-integrated AI Security Operations Centre for academic virtualization labs.
Two VMs, one hypervisor, one human in the loop.

## Quick Overview

| Component | Role | Key Tech |
|---|---|---|
| vm-honeypot | Deliberately weak SSH trap | Docker Compose, OpenSSH, rsyslog, Promtail |
| vm-soc | Observability + AI analysis | Loki, Grafana, Ollama, 4 Python agents |
| host controller | Human-in-the-loop response | Flask, Rich, virsh |

## Prerequisites

- **Hardware**: Intel/AMD CPU with VT-x/AMD-V, ≥8 GiB RAM, ≥30 GiB disk
- **OS**: NixOS 24.05+ / Ubuntu 22.04+ / Debian 12+ / Windows 11 + WSL2
- **Software**: KVM/libvirt, Docker 24+, Python 3.11+, QEMU 8+

## Quickstart (5 minutes)

```bash
# 1. Clone
git clone https://github.com/<org>/kvm-sentinel-soc.git
cd kvm-sentinel-soc

# 2. Provision (NixOS)
sudo nixos-rebuild switch --flake ./host/nixos#default
sudo ./host/provisioning/deploy-lab.sh

# 3. Start controller
sudo python3 host/controller/approval_daemon.py

# 4. Trigger a demo attack
ssh soc@192.168.122.20 'sudo docker compose -f /opt/soc/docker-compose.yml up -d'
```

## Operations dashboard (tmux)

One session, every moving part, live logs on disk:

```bash
cp .env.example .env          # once; set DASH_VM*_PASSWORD or use SSH keys
./scripts/tmux-dashboard.sh   # create or reattach
```

| Window | Panes | What you watch |
|---|---|---|
| `core` | controller, controller-health | approval daemon console + `/health` |
| `edge` | honeypot-logs, promtail-logs, trap-probe | trap tier and its log shipper |
| `brain` | agents, loki, grafana, ollama | AI pipeline and observability (2x2) |
| `infra` | libvirt-state, live-fire, host-resources | domains, DNAT rules, disk/RAM |
| `integrations` | loki-ingress, incidents | promtail→Loki path, audit trail |
| `logs` | all-logs, errors | merged tails, error-only tail |
| `health` | status | full `dashboard-status.sh` table |
| `shell` | shell | manual debugging (transcript saved) |
| `dashboard` | overview, pane-map | compact status + pane list |

```bash
./scripts/tmux-dashboard.sh              # create or attach (idempotent)
./scripts/tmux-dashboard.sh --status     # health snapshot (exit 1 on FAIL)
./scripts/tmux-dashboard.sh --logs       # focus the logs window
./scripts/tmux-dashboard.sh --stop       # stop dashboard-started processes
./scripts/tmux-dashboard.sh --restart
./scripts/dashboard-status.sh --watch 5 --compact
./scripts/tmux-dashboard-stop.sh --stop-stacks --stop-vms
```

Logs land in `logs/tmux-dashboard/` (`<component>.log`, `bootstrap.log`,
`status.log`, `shell-session.log`). PIDs are recorded with their start time in
`logs/tmux-dashboard/run/<session>/pids/`, so `--stop` never kills a reused PID
and never touches processes the dashboard did not start.

The dashboard does not generate attacks: the `shell` window prints the exact
manual command (`docker compose run --rm simulator`).

Troubleshooting:

- `ssh unreachable` panes → start the lab (`sudo ./host/provisioning/deploy-lab.sh`) or set `DASH_VM*_PASSWORD` / install `sshpass`.
- controller pane dies with a bind error → `192.168.122.1` is down: `sudo virsh net-start default`.
- panes report `compose ps failed` → stack not up; read `logs/tmux-dashboard/bootstrap.log`.
- `live-fire` shows SKIP → needs root: `sudo ./host/provisioning/enable-live-fire.sh status`.
- stale session → `./scripts/tmux-dashboard.sh --stop` then relaunch.

## Documentation

| Guide | Description |
|---|---|
| [NixOS Install](docs/01-INSTALL-NIXOS.md) | Full NixOS setup |
| [Ubuntu/Debian](docs/02-INSTALL-UBUNTU-DEBIAN.md) | Manual setup for Debian-based distros |
| [Windows/WSL2](docs/03-INSTALL-WINDOWS-WSL2.md) | Nested KVM on Windows |
| [Classroom Live-Fire](docs/04-CLASSROOM-LIVE-FIRE.md) | Multi-student attack scenario |
| [Architecture](docs/ARCHITECTURE.md) | Deep dive into design decisions |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and fixes |

## Known Issues

- ~~**Promtail config**: `target_config` field removed in Promtail 3.x~~ (FIXED)
- ~~**Docker internal network**: `internal: true` blocks host port publishing~~ (FIXED)
- ~~**SSH key auth**: Home directory permissions may require `chmod 700`~~ (FIXED in cloud-init)
- ~~**Simulator networking**: Static IP conflict~~ (FIXED)
- **Promtail → Alloy**: Promtail is in maintenance mode. Grafana Alloy is the successor.
  Migration recommended when Alloy's resource footprint drops below 30 MB.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
