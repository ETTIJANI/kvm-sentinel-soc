# Troubleshooting — KVM-Sentinel-SOC

## Common Issues

### Cloud-init fails on vm-honeypot

**Symptom**: `cloud-init status` shows `error` or VM never gets an IP.

**Causes**:
- Cloud image download corrupted → verify SHA256: `sha256sum host/provisioning/images/noble-server-cloudimg-amd64.img`
- Seed ISO not mounted → check `virsh domblklist vm-honeypot` shows the ISO
- Network config MAC mismatch → verify MACs match between `network-config` and `virt-install`

**Fix**: Re-run `deploy-lab.sh --force` to rebuild from scratch.

### SSH key authentication fails

**Symptom**: `Permission denied (publickey)` when connecting as `soc`.

**Causes**:
- Home directory permissions too open (`drwxr-x---` instead of `drwx------`)
- `authorized_keys` file permissions wrong (should be `600`)

**Fix**:
```bash
sudo chmod 700 /home/soc
sudo chmod 600 /home/soc/.ssh/authorized_keys
sudo chown -R soc:soc /home/soc/.ssh
```

### Trap unreachable from host

**Symptom**: `curl` or `ssh` to `10.10.0.10:2222` from host fails.

**Cause**: `honeypot-net` has `internal: true` in `docker-compose.yml`, which blocks all host port publishing.

**Fix**: Remove or comment out `internal: true` from the `honeypot-net` network definition. Isolation is enforced at the KVM level (no default route on eth0).

### Promtail crash-looping

**Symptom**: `docker compose ps` shows promtail `Restarting`.

**Cause**: `target_config` field in `promtail-config.yml` is not valid in Promtail 3.x.

**Fix**: Remove the `target_config:` block (lines 32-33) from `promtail-config.yml`.

### Simulator fails with "Address already in use"

**Symptom**: `docker compose run --rm simulator` fails with networking error.

**Cause**: Static IP `172.31.240.66` conflicts with existing container.

**Fix**: Remove `ipv4_address: 172.31.240.66` from the simulator service in `docker-compose.yml`.

### Ollama model not loading

**Symptom**: Agent Analyste falls back to heuristic assessment.

**Causes**:
- Model not pulled → `docker exec ollama ollama pull qwen2.5:0.5b`
- Timeout too short → increase `OLLAMA_TIMEOUT_SECONDS` in `docker-compose.yml`
- VM out of memory → check `free -h` on vm-soc

### Classroom live-fire rules not working

**Symptom**: Students can't connect to `ssh root@<HOST_IP> -p 2222`.

**Causes**:
- `enable-live-fire.sh enable` not run
- `ip_forward` not enabled → `sysctl net.ipv4.ip_forward=1`
- Firewall blocking → check `iptables -S | grep kvm-sentinel`

**Fix**: Re-run `sudo ./host/provisioning/enable-live-fire.sh enable`

### Forensic snapshot fails

**Symptom**: `virsh snapshot-create-as` returns error.

**Causes**:
- VM not running → `virsh list --all`
- Disk not QCOW2 format → `qemu-img info <disk>`
- Insufficient disk space → `df -h`

### Reset between demos

```bash
# Restore honeypot from baseline snapshot
sudo ./host/controller/restore-honeypot.sh

# Or full redeploy
sudo ./host/provisioning/cleanup-lab.sh
sudo ./host/provisioning/deploy-lab.sh
```

### Uninstall

```bash
# Remove VMs
sudo virsh destroy vm-honeypot vm-soc 2>/dev/null
sudo virsh undefine vm-honeypot --remove-all-storage
sudo virsh undefine vm-soc --remove-all-storage

# Remove networks
sudo virsh net-destroy backend-isolated
sudo virsh net-undefine backend-isolated

# Remove NixOS config (if applied)
sudo rm /etc/nixos/kvm-sentinel.nix
sudo nixos-rebuild switch
```
