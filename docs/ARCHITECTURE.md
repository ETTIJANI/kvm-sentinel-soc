# Architecture — KVM-Sentinel-SOC

## Overview

Two virtual machines, one physical hypervisor, one human in the loop:

* **vm-honeypot** — a deliberately weak SSH server on an isolated virtual network.
  It gets attacked, logs everything, and can reach nothing.
* **vm-soc** — Loki + Grafana for observability, a local CPU-only LLM (Ollama, `qwen2.5:0.5b`)
  and a four-agent Python pipeline that parses, detects, analyses and reports each intrusion.
* **host controller** — a webhook daemon on the physical machine that shows the AI verdict to a
  human and asks `[y/N]` before it creates a forensic snapshot and cuts the honeypot's virtual NIC.

The interesting part is not that it detects a brute force. It is that the *response* is
hypervisor-level (snapshot + SDN quarantine), that the AI only advises, and that a human decides.

## Data Pipeline

```
attacker (student laptop)
  │  ssh root@<HOST_LAN_IP> -p 2222
  ▼
host iptables DNAT → 10.10.0.10:2222 (SNAT to 10.10.0.1)
  ▼
vm-honeypot: ssh-honeypot container (OpenSSH on 2222, rsyslog → auth.log)
  ▼
promtail (tails /var/log/honeypot/auth.log, pushes to Loki)
  ▼
vm-soc: Loki (3100) → Agent Parseur → Agent Détecteur → Agent Analyste → Agent Rapporteur
  ▼
Grafana dashboard (3000) + incident report (Markdown + JSON)
  ▼
host controller webhook (5000) → human [y/N] → virsh snapshot + domif-setlink down
```

## Components and Ports

| Component | Host | Port | Purpose |
|---|---|---|---|
| `ssh-honeypot` container | vm-honeypot | 2222 | Trap SSH server (guest 2222 → container 2222) |
| `sshd` (management) | vm-honeypot | 22 | Admin SSH access |
| `promtail` | vm-honeypot | 9080 | Log shipper (metrics endpoint) |
| `loki` | vm-soc | 3100 | Log aggregation |
| `grafana` | vm-soc | 3000 | Dashboard (admin/sentinel) |
| `ollama` | vm-soc | 11434 | Local LLM (qwen2.5:0.5b) |
| `approval_daemon` | physical host | 5000 | Human-in-the-loop webhook |
| `enable-live-fire.sh` | physical host | 2222 | Classroom DNAT (LAN → trap) |

## Network Topology

| Network | Subnet | Gateway | Forward | Purpose |
|---|---|---|---|---|
| `virbr0` (default) | 192.168.122.0/24 | .1 | NAT | Internet access for both VMs |
| `virbr1` (backend-isolated) | 10.10.0.0/24 | .1 | none | Isolated trap ↔ SOC link |

**Isolation**: vm-honeypot's `eth0` (10.10.0.10) has no default route and no gateway.
The trap container cannot reach the internet. Isolation is enforced at the KVM level.

## Resource Budget

| VM | RAM | vCPU | Disk | OS |
|---|---|---|---|---|
| vm-honeypot | 1 GiB | 1 | 20 GiB | Ubuntu 24.04 |
| vm-soc | 5 GiB | 4 | 30 GiB | Ubuntu 24.04 |
| **Total** | **6 GiB** | **5** | **50 GiB** | |

## Repository Layout

```
KVM-AISOC/
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE
├── .gitignore
├── host/
│   ├── controller/          # approval_daemon.py, restore-honeypot.sh
│   ├── networks/            # backend-isolated.xml
│   ├── nixos/               # flake.nix, virtualization.nix
│   └── provisioning/        # deploy-lab.sh, enable-live-fire.sh, cloud-init/
├── vm1-honeypot/
│   ├── docker-compose.yml
│   ├── ssh-honeypot/        # Dockerfile, entrypoint.sh
│   ├── simulator/           # Dockerfile, simulate_attack.py
│   └── promtail/            # promtail-config.yml
├── vm2-soc/
│   ├── docker-compose.yml
│   ├── agents/              # 4 Python agents + main.py + Dockerfile
│   ├── grafana/             # Provisioned dashboards + datasources
│   ├── loki/                # loki-config.yml
│   └── reports/             # Generated incident reports (.gitkeep)
└── docs/
    ├── 01-INSTALL-NIXOS.md
    ├── 02-INSTALL-UBUNTU-DEBIAN.md
    ├── 03-INSTALL-WINDOWS-WSL2.md
    ├── 04-CLASSROOM-LIVE-FIRE.md
    ├── ARCHITECTURE.md      # This file
    ├── TROUBLESHOOTING.md
    └── architecture.mmd     # Mermaid diagram
```

## Security Model

- **AI only advises**: The LLM verdict is displayed, never executed
- **Human decides**: `[y/N]` prompt before any hypervisor action
- **Whitelisted commands**: Only `snapshot-create-as` and `domif-setlink` are executed
- **Input validation**: All alert fields validated (IP format, severity clamp, Rich escaping)
- **No shell injection**: Commands are built as argv lists, never via shell
- **Isolation**: Trap VM has no default route, no internet access
- **Audit trail**: Every human decision logged to JSON-lines file

## Detection Rule

- Counts only `failed_password` events (avoids OpenSSH double-line double count)
- 30-second sliding window per source IP
- 120-second per-IP cooldown after firing
- Threshold: 5 or more failures from one IP within the window

## Technology Choices

| Component | Choice | Rationale |
|---|---|---|
| Hypervisor | KVM/libvirt | Native Linux, academic standard |
| Log shipper | Promtail 3.2 | Lightweight (~15 MB), simple YAML config |
| Log store | Loki 3.2 | LogQL, low resource, Grafana-native |
| LLM | Ollama + qwen2.5:0.5b | CPU-only, fits in 5 GiB VM |
| Dashboard | Grafana 11.2 | Provisioned dashboards, Loki datasource |
| Controller | Flask + Rich | Simple webhook, beautiful terminal UI |
| OS | Ubuntu 24.04 | LTS, cloud images available, wide support |
