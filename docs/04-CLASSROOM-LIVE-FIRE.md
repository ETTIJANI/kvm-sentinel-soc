# 04 — Classroom live fire

How to run the demonstration in front of (or with) a class: everyone attacks the honeypot from their
own machine, the SOC reacts, and one human decides what the hypervisor does.

Time budget: **15 minutes** of demo, **5 minutes** of setup and **2 minutes** of teardown.

---

## 1. What the students are attacking

```text
student laptop ──ssh root@<HOST_LAN_IP> -p 2222──▶ host iptables DNAT
                                                     │  DNAT → 10.10.0.10:2222
                                                     │  SNAT → 10.10.0.1 (return path)
                                                     ▼
                                              vm-honeypot sshd  :2222
                                                     │
                                              promtail → Loki → agents
```

* The honeypot is **not** reachable from the LAN any other way.
* The honeypot has **no internet route**; it cannot be used to attack anything.
* The credentials are fake: `root` / `toor`. Anyone who gets in lands in a container with no
  privileges, no secrets and no route out.
* The DNAT exists only while `enable-live-fire.sh enable` is active.

---

## 2. Pre-class checklist (5 minutes)

```bash
cd ~/kvm-sentinel-soc

# 1. guests up and healthy
virsh -c qemu:///system list --all
ssh soc@10.10.0.10    'cd /opt/honeypot && docker compose ps'
ssh soc@192.168.122.20 'cd /opt/soc && docker compose ps'

# 2. pristine baseline available (reset between sessions)
sudo ./host/controller/restore-honeypot.sh --list

# 3. controller running (own terminal, leave visible to the class)
sudo .venv/bin/python host/controller/approval_daemon.py

# 4. webhook reachable from the SOC VM
ssh soc@192.168.122.20 'wget -qO- http://192.168.122.1:5000/health || curl -s http://192.168.122.1:5000/health'

# 5. dashboard open
#    http://192.168.122.20:3000  →  Dashboards → "SSH Sentinel SOC"  →  time range "Last 6 hours"

# 6. model warm (optional, saves 30-60 s on the first alert)
ssh soc@192.168.122.20 'docker exec ollama ollama run qwen2.5:0.5b "ok" </dev/null >/dev/null 2>&1 || true'
```

On a rootless NixOS host, run the controller as your `libvirtd` user (`.venv/bin/python
host/controller/approval_daemon.py` without `sudo`). If vm-soc cannot reach
`192.168.122.1:5000`, use the Docker-published controller in
[01-INSTALL-NIXOS.md §8.1](01-INSTALL-NIXOS.md#81-rootless-nixos-deployment-and-the-webhook-firewall).
The `restore-honeypot.sh` and live-fire commands still require root.

Then publish the trap:

```bash
sudo ./host/provisioning/enable-live-fire.sh enable --host-port 2222
sudo ./host/provisioning/enable-live-fire.sh status
```

`status` prints the host LAN address, the DNAT target and the two rule counters. Write the address on
the board.

Flags: `--host-port N` (default `2222`), `--wan-if IF` (default: the interface carrying the default
route; set it explicitly on a host with several NICs).

---

## 3. Attack commands for students

Give them a choice, from least to most noisy. Keep attempts **below ~20 per student** so the demo
stays readable.

```bash
# A. manual, shows the fake banner and a real auth failure
ssh root@<HOST_LAN_IP> -p 2222

# B. loop of failures (POSIX shell, works from macOS/Linux/WSL)
for i in $(seq 1 10); do
  sshpass -p "wrong$i" ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password \
      -p 2222 root@<HOST_LAN_IP> true 2>/dev/null
done

# C. hydra, if installed (Kali students usually have it)
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f \
      ssh://<HOST_LAN_IP>:2222

# D. nmap service fingerprint
nmap -sV -p 2222 <HOST_LAN_IP>
```

Windows students without WSL can use PuTTY against `<HOST_LAN_IP>:2222` (user `root`, any password)
and repeat it — the demo only needs failures.

> The threshold is **5 or more failed passwords from one IP within 30 seconds**. One student looping
> 10 times triggers it alone; a class triggering at once produces one incident per attacker IP.

---

## 4. Demo script (15 minutes)

| Min | On screen | Say this |
|---|---|---|
| 0–2 | `virsh list`, `domiflist` | "Two VMs, pinned MACs, one isolated bridge `10.10.0.0/24` declared with no `<forward>` element (libvirt mode `none`) — this network has no way out." |
| 2–4 | Grafana, empty-ish dashboard | "Promtail ships OpenSSH `auth.log` lines; Loki stores them; nothing is parsed yet." |
| 4–6 | Students attack | "Watch the failed-login rate panel." |
| 6–7 | Agents log (`docker compose logs -f agents`) | "Parseur turns lines into events, Détecteur applies the 5-in-30s rule per IP." |
| 7–9 | Controller terminal pops an incident | "The Analyste asked a 0.5-billion-parameter model running on CPU for a verdict. Severity, MITRE technique, recommended actions." |
| 9–11 | Operator reads, types `y` | "The AI never executes anything. The daemon rebuilt two whitelisted `virsh` commands locally and asked me." |
| 11–13 | `restore-honeypot.sh --status`, `snapshot-list` | "Atomic snapshot `forensic-breach-<ts>`, NIC link down. The VM still runs — evidence preserved, attacker cut off." |
| 13–14 | `vm2-soc/reports/*.md` | "The Rapporteur wrote a Markdown + JSON incident report. Here is the audit trail of my decision." |
| 14–15 | `restore-honeypot.sh --revert` | "Back to `clean-baseline`, link up. Ready for the next group." |

If the model is cold and the first verdict takes ~60 s, use the time to explain the heuristic
fallback — the pipeline never blocks on the LLM.

---

## 5. Monitoring during class

```bash
# live agent activity
ssh soc@192.168.122.20 'cd /opt/soc && docker compose logs -f --tail=50 agents'

# raw evidence as it arrives
ssh soc@10.10.0.10 'tail -f /opt/honeypot/logs/auth.log'

# one-line Loki query (top attackers, last hour)
ssh soc@192.168.122.20 'curl -sG http://localhost:3100/loki/api/v1/query_range \
  --data-urlencode "query=sum by (src_ip) (count_over_time({job=\"ssh-honeypot\"} |= \"Failed password\" [1h]))" \
  --data-urlencode "start=$(date -u -d "1 hour ago" +%s)000000000" \
  --data-urlencode "end=$(date -u +%s)000000000" | head -c 400'

# decisions taken so far
sudo tail -n 20 host/controller/state/incidents.jsonl | jq -c .
```

---

## 6. What the class should see afterwards

| Artefact | Location | Meaning |
|---|---|---|
| Incident reports | vm-soc `/opt/soc/reports/incident-<ts>-<ip>.{md,json}` | one per detected attacker IP |
| Audit trail | host `host/controller/state/incidents.jsonl` | who approved, which snapshot, which MAC, outcome |
| Snapshots | `virsh snapshot-list vm-honeypot` | `clean-baseline` + one `forensic-breach-<ts>` per approval |
| Dashboard | Grafana `SSH Sentinel SOC` | failed-login timeline, top attackers, top usernames, Loki ingestion |

Copy the reports to the host for grading:

```bash
rsync -av soc@192.168.122.20:/opt/soc/reports/ ./vm2-soc/reports/
```

---

## 7. Safety and ethics — read aloud before starting

1. **Written consent.** The lab owner (teacher/lab admin) authorises the attack on the honeypot IP
   and port **for the duration of the session only**.
2. **Scope.** Only `<HOST_LAN_IP>:2222`. Never scan or attack any other address on the campus
   network, never attack the hypervisor's SSH, never attack other students.
3. **Isolation guarantee.** The target has no internet route and no access to the campus LAN; the
   only thing exposed is one port that lives in a container.
4. **Fake credentials.** `root`/`toor` is intentional and must never be reused anywhere.
5. **Teardown.** `enable-live-fire.sh disable` at the end, and confirm with `status`.
6. **Reporting.** Any unintended access is reported to the lab admin immediately.

Post the scope on the board with the IP, the port and the end time.

---

## 8. Teardown (2 minutes)

```bash
sudo ./host/provisioning/enable-live-fire.sh disable
sudo ./host/provisioning/enable-live-fire.sh status          # must report "disabled"

sudo ./host/controller/restore-honeypot.sh --revert          # clean-baseline + link up
rsync -av soc@192.168.122.20:/opt/soc/reports/ ./vm2-soc/reports/

# optional, full stop
sudo ./host/provisioning/cleanup-lab.sh --force --keep-reports
```

For the WSL2 path, also remove the Windows portproxy and firewall rule (§6.2 of
[03-INSTALL-WINDOWS-WSL2.md](03-INSTALL-WINDOWS-WSL2.md)).

---

## 9. Scaling notes

| Students | Notes |
|---|---|
| ≤ 10 | default settings are fine; one incident card at a time |
| 10–30 | expect a burst of incident cards; answer them quickly or the queue grows (it is unbounded by design, alerts are never dropped) |
| 30+ | stagger the attack windows (3 groups of 10, 2 minutes each); four vCPUs saturate on Ollama before Loki does |

The agents process alerts sequentially. Each AI call costs 1–3 s warm, 30–60 s cold. A 30-student
class in one burst will queue; that is a legitimate teaching point about **back-pressure in
AI-augmented pipelines**.

---

## 10. Troubleshooting during the demo

| Symptom | Fix |
|---|---|
| Students get `Connection refused` | `enable-live-fire.sh status`; check the LAN IP and the firewall profile |
| Students get `Connection timed out` | the honeypot link is *down* (previous quarantine) → `restore-honeypot.sh --revert` |
| Dashboard flat during the attack | time range wrong, or promtail lost its stream → check `docker compose logs promtail` in vm-honeypot |
| Alerts in Grafana but no incident card | controller down, or `SENTINEL_TOKEN` mismatch → `curl http://192.168.122.1:5000/health` |
| Incident card but `y` does nothing | `virsh` permission (controller must run as root) — check the daemon's stderr |
| Snapshot name collisions | timestamps are UTC to the second; wait a second and retry |
| Model returns nonsense | the Analyste clamps it; if it is unusable the heuristic verdict is used — mention this during the demo |

---

## 11. Suggested assessment rubric

| Criterion | Weight | Evidence |
|---|---|---|
| Lab deployed from a clean host, unattended | 25% | `deploy-lab.sh` log, `virsh list` |
| Network isolation demonstrated | 20% | no route from honeypot, `net-dumpxml backend-isolated` |
| Telemetry pipeline works | 20% | Grafana panels + Loki query |
| AI verdict quality and safety | 15% | incident report, escaping, heuristic fallback shown |
| Human-in-the-loop response | 10% | audit trail, snapshot + link state |
| Documentation and teardown | 10% | README/doc accuracy, rules removed, baseline restored |

---

## Next step

Back to the [README](../README.md), or to the manual for your host:
[01 NixOS](01-INSTALL-NIXOS.md) · [02 Ubuntu/Debian](02-INSTALL-UBUNTU-DEBIAN.md) ·
[03 Windows/WSL2](03-INSTALL-WINDOWS-WSL2.md)
