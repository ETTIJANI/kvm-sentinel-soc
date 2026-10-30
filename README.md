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

- **Hardware**: Intel/AMD CPU with VT-x/AMD-V, ≥16 GiB RAM, ≥80 GiB disk
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

- **Promtail config**: `target_config` field removed in Promtail 3.x (fix pending)
- **Docker internal network**: `internal: true` blocks host port publishing (fix pending)
- **SSH key auth**: Home directory permissions may require `chmod 700` (workaround in docs)
- **Promtail → Alloy**: Promtail is in maintenance mode. Grafana Alloy is the successor.
  Migration recommended when Alloy's resource footprint drops below 30 MB.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
