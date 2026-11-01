# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive `.gitignore` tailored to NixOS/Docker/Python stack
- `CONTRIBUTING.md` with Conventional Commits convention
- `docs/ARCHITECTURE.md` extracted from README for readability
- `docs/TROUBLESHOOTING.md` extracted from README

### Changed
- `README.md` restructured for conciseness (452 → ~120 lines)
- Port mapping corrected: trap moved from guest 22 to 2222 (avoids collision with admin sshd)
- Detection threshold wording: "more than 5" → "5 or more" (matches code)
- Storage budget reduced: 50 GiB → 25 GiB (vm-honeypot 20→10 GiB, vm-soc 30→15 GiB)
- RAM budget reduced: 6 GiB → 5 GiB (vm-soc 5→4 GiB)

### Fixed
- `backend-isolated.xml`: removed invalid `<forward mode='none'/>` (libvirt ≥10/12)
- `deploy-lab.sh`: renderer now skips comment lines containing tokens
- `enable-live-fire.sh`: `flush_rules()` strips quotes from iptables output
- `agent_analyste.py`: timeout reduced 180s → 25s with startup `warm_up()`
- `approval_daemon.py`: removed 0.0.0.0 bind fallback (security fix)
- `docker-compose.yml`: removed `internal: true` from honeypot-net (blocked host port publishing)
- `promtail-config.yml`: removed invalid `target_config` field (Promtail 3.x)
- `docker-compose.yml`: removed static IP from simulator (address conflict)
- `cloud-init-vm1/user-data`: added SSH key permission fix (StrictModes)
- `cloud-init-vm2/user-data`: added SSH key permission fix (StrictModes)

## [0.1.0] - 2026-10-30

### Added
- Initial release: complete KVM-Sentinel-SOC project
- Host provisioning: NixOS, Ubuntu/Debian, Windows/WSL2 guides
- vm-honeypot: Docker Compose SSH trap + Promtail + simulator
- vm-soc: Loki, Grafana, Ollama, 4-agent Python pipeline
- Host controller: human-in-the-loop webhook daemon
- Classroom live-fire mode with iptables DNAT
- Full documentation (4 install guides + architecture diagram)
- Incident reports (Markdown + JSON) + JSON-lines audit trail

[Unreleased]: https://github.com/<org>/kvm-sentinel-soc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/<org>/kvm-sentinel-soc/releases/tag/v0.1.0
