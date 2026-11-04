# Troubleshooting — KVM-Sentinel-SOC

## Common Issues

### Cloud-init fails on vm-honeypot

**Symptom**: `cloud-init status` shows `error` or VM never gets an IP.

**Causes**:
- Cloud image download corrupted → verify SHA256: `sha256sum host/provisioning/images/noble-server-cloudimg-amd64.img`
- Seed ISO not mounted → check `virsh domblklist vm-honeypot` shows the ISO
- Network config MAC mismatch → verify MACs match between `network-config` and `virt-install`

**Fix**: Re-run `deploy-lab.sh --force` to rebuild from scratch.

If only the vm-honeypot Docker build was interrupted and the VM is otherwise reachable, do not
redeploy: inspect it first, detach the bootstrap NIC, and create the baseline snapshot manually.

```bash
ssh soc@10.10.0.10 'docker ps; sudo cloud-init status --long'
virsh -c qemu:///system domiflist vm-honeypot   # confirm the bootstrap NIC is present
virsh -c qemu:///system detach-interface vm-honeypot network --mac 52:54:00:bb:00:01 --config
virsh -c qemu:///system detach-interface vm-honeypot network --mac 52:54:00:bb:00:01
virsh -c qemu:///system snapshot-create-as vm-honeypot clean-baseline \
  --description "clean baseline" --atomic
```

`deploy-lab.sh --force` destroys the current overlays and any evidence snapshots.

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

### Approval daemon unreachable from vm-soc

**Symptom**: On vm-soc, `curl http://192.168.122.1:5000/health` times out or is refused, while the same command works on the host.

**Cause**: The NixOS firewall can filter the guest-to-host path to a host-bound controller even when `5000/tcp` is in `allowedTCPPorts`. A `socat` proxy on the host is subject to the same filter.

**Fix**: Run the controller as a Docker container published on `virbr0`, as shown in
[01-INSTALL-NIXOS.md §8.1](01-INSTALL-NIXOS.md#81-rootless-nixos-deployment-and-the-webhook-firewall).
Verify from vm-soc:

```bash
ssh soc@192.168.122.20 'curl -s http://192.168.122.1:5000/health'
```

Do not expose port 5000 on the physical LAN; keep it bound to `192.168.122.1`.

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

**Fallback**: The agent pipeline does not require Ollama. When the model cannot be reached,
`agent_analyste.py` emits a deterministic heuristic assessment and the incident still reaches the
webhook.

### Deploy waits for Ollama on a slow link

**Symptom**: `deploy-lab.sh` keeps logging `still waiting for vm-soc Ollama`.

**Cause**: The Ollama image and `qwen2.5:0.5b` model are a multi-GB pull; the readiness check waits
for `192.168.122.20:11434`.

**Fix**: Pre-pull the model, or complete the stack manually and stop the waiter only after both VMs
and the containers have been verified. Do not expose `11434` outside the lab. If the model never
loads, leave Ollama down; detection still runs with the heuristic assessment.

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
- Rootless NixOS: `qemu-libvirtd` cannot traverse `$HOME` or open the overlay → check `getfacl`
  and re-run `deploy-lab.sh` after adding `acl` to `systemPackages`

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
