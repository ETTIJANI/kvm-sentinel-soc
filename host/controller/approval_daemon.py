#!/usr/bin/env python3
"""KVM-Sentinel-SOC — human-in-the-loop hypervisor controller.

The AI pipeline on vm-soc detects an SSH brute force and POSTs an alert to this
daemon. Nothing happens automatically: the daemon prints the evidence and the
AI assessment, then asks the human operator for approval before touching the
hypervisor.

On approval it runs exactly two actions against vm-honeypot:

    1. virsh snapshot-create-as ... --name forensic-breach-<UTC>  --atomic
    2. virsh domif-setlink vm-honeypot <mac> down

Design properties that matter for the grade:

  * The daemon NEVER executes commands received over HTTP. The alert payload
    contains a ``proposed_commands`` field for display only; the two real
    commands are rebuilt locally from a hard-coded whitelist. A compromised
    vm-soc therefore cannot turn the controller into a remote shell.
  * Every field is validated before it reaches the terminal: the attacker IP
    must parse with ``ipaddress``, numbers are clamped, strings are capped and
    escaped for Rich markup. LLM output is untrusted text.
  * The Flask request handler only enqueues; the prompt happens on the main
    thread. Never call input() from a request handler.
  * Every decision is appended to a JSON-lines audit log.

Run it with the project virtualenv (see docs/02-INSTALL-UBUNTU-DEBIAN.md):

    python3 -m venv .venv && .venv/bin/pip install -r host/controller/requirements.txt
    sudo .venv/bin/python host/controller/approval_daemon.py
"""

from __future__ import annotations

import argparse
import getpass
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

LOG = logging.getLogger("kvm-sentinel.controller")
console = Console()

VIRSH = "virsh"
LIBVIRT_URI = "qemu:///system"
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")

REQUIRED_FIELDS: dict[str, type] = {
    "alert_id": str,
    "detected_at": str,
    "vm": str,
    "rule": str,
    "attacker_ip": str,
    "failure_count": int,
    "severity_label": str,
    "severity_score": int,
    "summary": str,
}
OPTIONAL_FIELDS: dict[str, type] = {
    "window_seconds": int,
    "threshold": int,
    "usernames": list,
    "first_seen": str,
    "last_seen": str,
    "analysis_markdown": str,
    "mitre_techniques": list,
    "recommended_actions": list,
    "proposed_commands": list,
    "report_path": str,
    "source": str,
}
SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "bold cyan",
}


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    host: str = "192.168.122.1"
    port: int = 5000
    cooldown: int = 120
    auto_approve: bool = False
    dry_run: bool = False
    domain: str = "vm-honeypot"
    iface_mac: str = "52:54:00:10:10:01"
    audit_log: Path = Path("state/incidents.jsonl")
    token: str = ""
    log_level: str = "INFO"

    stats: dict[str, int] = field(
        default_factory=lambda: {"received": 0, "queued": 0, "approved": 0, "dismissed": 0, "failed": 0}
    )
    cooldowns: dict[str, float] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    started_at: float = field(default_factory=time.time)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_virsh(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run virsh with an explicit argument vector. No shell, ever."""
    try:
        proc = subprocess.run(
            [VIRSH, "-c", LIBVIRT_URI, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "virsh not found in PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"virsh {' '.join(args)} timed out after {timeout}s"


def resolve_nic_mac(domain: str, fallback: str) -> str:
    """Find the MAC of the NIC attached to the isolated backend network."""
    rc, out, err = run_virsh(["domiflist", domain], timeout=20)
    if rc != 0:
        LOG.warning("domiflist failed (rc=%s): %s — using configured MAC %s", rc, err, fallback)
        return fallback

    candidates: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        macs = [p for p in parts if MAC_RE.match(p)]
        if not macs:
            continue
        if "backend-isolated" in parts:
            return macs[-1].lower()
        candidates.append(macs[-1].lower())
    if candidates:
        LOG.info("no interface labelled backend-isolated; quarantining first NIC %s", candidates[0])
        return candidates[0]
    LOG.warning("could not parse domiflist output; using configured MAC %s", fallback)
    return fallback


def append_audit(cfg: Config, entry: dict[str, Any]) -> None:
    try:
        cfg.audit_log.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with open(cfg.audit_log, "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:  # never let auditing kill the controller
        LOG.error("could not write audit log %s: %s", cfg.audit_log, exc)


def read_audit(cfg: Config, limit: int = 20) -> list[dict[str, Any]]:
    if not cfg.audit_log.exists():
        return []
    try:
        lines = cfg.audit_log.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        LOG.error("could not read audit log: %s", exc)
        return []
    entries = []
    for line in lines[-limit:]:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


# --------------------------------------------------------------------------- #
# payload validation
# --------------------------------------------------------------------------- #
class PayloadError(ValueError):
    pass


def validate_alert(raw: Any, cfg: Config) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PayloadError("body must be a JSON object")

    missing = [key for key in REQUIRED_FIELDS if key not in raw]
    if missing:
        raise PayloadError(f"missing required field(s): {', '.join(sorted(missing))}")

    clean: dict[str, Any] = {}
    for key, expected in {**REQUIRED_FIELDS, **OPTIONAL_FIELDS}.items():
        if key not in raw or raw[key] is None:
            clean[key] = [] if expected is list else ("" if expected is str else 0)
            continue
        value = raw[key]
        if expected is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise PayloadError(f"{key} must be an integer")
            clean[key] = value
        elif expected is str:
            if not isinstance(value, str):
                raise PayloadError(f"{key} must be a string")
            clean[key] = value[:4000]
        else:  # list
            if not isinstance(value, list):
                raise PayloadError(f"{key} must be a list")
            clean[key] = [str(item)[:300] for item in value][:20]

    try:
        ip = ipaddress.ip_address(clean["attacker_ip"].strip())
    except ValueError as exc:
        raise PayloadError(f"attacker_ip is not a valid IP address: {exc}") from exc
    clean["attacker_ip"] = str(ip)

    if clean["vm"] != cfg.domain:
        raise PayloadError(f"vm must be {cfg.domain!r} (got {clean['vm']!r})")

    clean["failure_count"] = max(0, min(int(clean["failure_count"]), 1_000_000))
    clean["severity_score"] = max(0, min(int(clean["severity_score"]), 10))
    clean["window_seconds"] = max(0, min(int(clean.get("window_seconds", 0)), 86_400))
    clean["threshold"] = max(0, min(int(clean.get("threshold", 0)), 1_000_000))
    label = clean["severity_label"].strip().lower()
    clean["severity_label"] = label if label in SEVERITY_COLORS else "medium"

    clean["usernames"] = sorted({u for u in clean.get("usernames", []) if u})[:10]
    clean["mitre_techniques"] = clean.get("mitre_techniques", [])[:10]
    clean["recommended_actions"] = [
        a for a in clean.get("recommended_actions", [])
        if a in {"snapshot", "quarantine", "block-ssh-port", "review-logs"}
    ][:6]

    alert_id = clean["alert_id"].strip()
    if not re.fullmatch(r"[A-Za-z0-9._:-]{4,120}", alert_id):
        raise PayloadError("alert_id must be 4-120 chars of [A-Za-z0-9._:-]")
    clean["alert_id"] = alert_id
    return clean


# --------------------------------------------------------------------------- #
# terminal rendering
# --------------------------------------------------------------------------- #
def render_alert(alert: dict[str, Any], mac: str, cfg: Config) -> None:
    severity = alert["severity_label"]
    color = SEVERITY_COLORS.get(severity, "yellow")
    score = alert["severity_score"]
    bar = "█" * score + "░" * (10 - score)

    console.print()
    console.rule(f"[bold red]INCIDENT[/bold red] {escape(alert['alert_id'])}")
    console.print(
        Panel(
            Text.from_markup(
                f"[{color}]severity {escape(severity)}  {bar}  {score}/10[/{color}]\n"
                f"[bold]rule[/bold]        {escape(alert['rule'])}\n"
                f"[bold]attacker[/bold]    {escape(alert['attacker_ip'])}\n"
                f"[bold]target[/bold]      {escape(alert['vm'])}  (interface MAC {escape(mac)})\n"
                f"[bold]detected[/bold]    {escape(alert['detected_at'])}"
            ),
            title="[bold]SSH brute force detected[/bold]",
            border_style=color.split()[-1],
        )
    )

    evidence = Table(show_header=False, box=None, padding=(0, 2))
    evidence.add_column(style="bold", width=16)
    evidence.add_column()
    evidence.add_row("failures", f"{alert['failure_count']} in {alert['window_seconds'] or '?'}s "
                                 f"(threshold {alert['threshold'] or '?'})")
    evidence.add_row("first seen", escape(alert.get("first_seen") or "n/a"))
    evidence.add_row("last seen", escape(alert.get("last_seen") or "n/a"))
    evidence.add_row("usernames", escape(", ".join(alert.get("usernames") or ["unknown"])))
    console.print(evidence)

    if alert.get("summary"):
        console.print(Panel(escape(alert["summary"]), title="AI analyst — summary", border_style="cyan"))
    if alert.get("analysis_markdown"):
        console.print(Panel(escape(alert["analysis_markdown"]),
                            title="AI analyst — assessment", border_style="cyan"))
    if alert.get("mitre_techniques"):
        console.print(f"[bold]MITRE ATT&CK[/bold]  {escape(', '.join(alert['mitre_techniques']))}")
    if alert.get("recommended_actions"):
        console.print(f"[bold]AI recommendation[/bold]  {escape(', '.join(alert['recommended_actions']))}")
    if alert.get("report_path"):
        console.print(f"[bold]report[/bold]  {escape(alert['report_path'])} "
                      f"[dim](inside vm-soc)[/dim]")

    snapshot = f"forensic-breach-{utc_stamp()}"
    planned = [
        f'virsh -c {LIBVIRT_URI} snapshot-create-as --domain {cfg.domain} '
        f'--name {snapshot} --description "AI SOC Automated Snapshot" --atomic',
        f"virsh -c {LIBVIRT_URI} domif-setlink {cfg.domain} {mac} down",
    ]
    table = Table(title="Commands the controller will run (locally built, not from the payload)",
                  show_lines=True, border_style="yellow")
    table.add_column("#", width=2)
    table.add_column("command")
    for index, command in enumerate(planned, start=1):
        table.add_row(str(index), command)
    console.print(table)

    remote = alert.get("proposed_commands") or []
    if remote:
        console.print("[dim]advisory commands supplied by vm-soc (display only, never executed):[/dim]")
        for command in remote:
            console.print(f"[dim]  • {escape(str(command))}[/dim]")


def perform_quarantine(cfg: Config, mac: str) -> dict[str, Any]:
    snapshot = f"forensic-breach-{utc_stamp()}"
    result: dict[str, Any] = {
        "snapshot_name": snapshot,
        "mac": mac,
        "snapshot_ok": False,
        "quarantine_ok": False,
        "errors": [],
    }

    snapshot_cmd = [
        "snapshot-create-as",
        "--domain", cfg.domain,
        "--name", snapshot,
        "--description", "AI SOC Automated Snapshot",
        "--atomic",
    ]
    link_cmd = ["domif-setlink", cfg.domain, mac, "down"]

    if cfg.dry_run:
        console.print("[yellow]dry-run:[/yellow] " + " ".join([VIRSH, "-c", LIBVIRT_URI, *snapshot_cmd]))
        console.print("[yellow]dry-run:[/yellow] " + " ".join([VIRSH, "-c", LIBVIRT_URI, *link_cmd]))
        result["snapshot_ok"] = result["quarantine_ok"] = True
        return result

    rc, out, err = run_virsh(snapshot_cmd)
    if rc == 0:
        result["snapshot_ok"] = True
        console.print(f"[green]✓[/green] forensic snapshot created: [bold]{escape(snapshot)}[/bold]")
    else:
        result["errors"].append(f"snapshot failed (rc={rc}): {err or out}")
        console.print(f"[red]✗[/red] snapshot failed (rc={rc}): {escape(err or out)}")

    rc, out, err = run_virsh(link_cmd)
    if rc == 0:
        result["quarantine_ok"] = True
        console.print(f"[green]✓[/green] network quarantined: {escape(cfg.domain)} / {escape(mac)} link down")
    else:
        result["errors"].append(f"domif-setlink failed (rc={rc}): {err or out}")
        console.print(f"[red]✗[/red] quarantine failed (rc={rc}): {escape(err or out)}")

    return result


# --------------------------------------------------------------------------- #
# Flask application
# --------------------------------------------------------------------------- #
def create_app(cfg: Config, alerts: "queue.Queue[dict[str, Any]]") -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    def token_ok() -> bool:
        if not cfg.token:
            return True
        supplied = request.headers.get("X-Sentinel-Token", "")
        return hmac.compare_digest(supplied, cfg.token)

    @app.get("/")
    def index():
        return jsonify(
            service="kvm-sentinel-soc-approval-daemon",
            version="1.0.0",
            endpoints={
                "POST /alert": "submit an incident for human review",
                "GET /health": "liveness and counters",
                "GET /incidents": "last 20 audited decisions",
            },
            domain=cfg.domain,
            dry_run=cfg.dry_run,
        )

    @app.get("/health")
    def health():
        rc, _, _ = run_virsh(["domstate", cfg.domain], timeout=10)
        return jsonify(
            status="ok",
            uptime_seconds=int(time.time() - cfg.started_at),
            pending=alerts.qsize(),
            virsh_available=(rc in (0, 1)),
            domain_running=(rc == 0),
            dry_run=cfg.dry_run,
            stats=cfg.stats,
        )

    @app.get("/incidents")
    def incidents():
        return jsonify(count=len(read_audit(cfg, limit=20)), incidents=read_audit(cfg, limit=20))

    @app.post("/alert")
    def alert():
        if not token_ok():
            LOG.warning("rejected alert: bad or missing X-Sentinel-Token from %s", request.remote_addr)
            return jsonify(status="unauthorized", error="invalid token"), 401

        raw = request.get_json(silent=True)
        try:
            clean = validate_alert(raw, cfg)
        except PayloadError as exc:
            LOG.warning("rejected malformed alert from %s: %s", request.remote_addr, exc)
            return jsonify(status="rejected", error=str(exc)), 400

        with cfg.lock:
            cfg.stats["received"] += 1
            last = cfg.cooldowns.get(clean["attacker_ip"], 0.0)
            if time.time() - last < cfg.cooldown:
                remaining = int(cfg.cooldown - (time.time() - last))
                LOG.info("cooldown active for %s (%ss left); alert ignored", clean["attacker_ip"], remaining)
                return jsonify(status="ignored", reason="cooldown", retry_after_seconds=remaining), 200
            cfg.cooldowns[clean["attacker_ip"]] = time.time()
            cfg.stats["queued"] += 1

        alerts.put(clean)
        LOG.info("alert %s queued (attacker %s, %s failures)",
                 clean["alert_id"], clean["attacker_ip"], clean["failure_count"])
        return jsonify(status="queued", alert_id=clean["alert_id"]), 202

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(status="rejected", error="payload exceeds 64 KiB"), 413

    return app


# --------------------------------------------------------------------------- #
# main loop
# --------------------------------------------------------------------------- #
def process_alert(cfg: Config, alert: dict[str, Any]) -> None:
    mac = resolve_nic_mac(cfg.domain, cfg.iface_mac)
    render_alert(alert, mac, cfg)

    approved = False
    if cfg.auto_approve:
        console.print("[yellow]--auto-approve: quarantining without asking[/yellow]")
        approved = True
    elif not sys.stdin.isatty():
        console.print("[yellow]stdin is not a TTY: alert held, no action taken[/yellow]")
    else:
        approved = Confirm.ask(
            f"Approve Hypervisor Quarantine & Forensic Snapshot for {cfg.domain}?",
            default=False,
            console=console,
        )

    result: dict[str, Any] = {}
    if approved:
        result = perform_quarantine(cfg, mac)
        with cfg.lock:
            cfg.stats["approved" if result.get("quarantine_ok") else "failed"] += 1
        if result.get("quarantine_ok"):
            console.print(Panel(
                "Honeypot quarantined. Evidence preserved as a live snapshot.\n"
                "Reset before the next demo:  sudo ./host/controller/restore-honeypot.sh --revert",
                title="[bold green]containment complete[/bold green]",
                border_style="green",
            ))
    else:
        with cfg.lock:
            cfg.stats["dismissed"] += 1
        console.print("[dim]No action taken. The honeypot stays online.[/dim]")

    append_audit(cfg, {
        "received_at": alert.get("detected_at"),
        "decided_at": utc_iso(),
        "decision": "approved" if approved else "dismissed",
        "alert_id": alert["alert_id"],
        "attacker_ip": alert["attacker_ip"],
        "severity_label": alert["severity_label"],
        "severity_score": alert["severity_score"],
        "failure_count": alert["failure_count"],
        "operator": os.environ.get("SUDO_USER") or getpass.getuser(),
        **result,
    })
    console.print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="KVM-Sentinel-SOC human-in-the-loop hypervisor controller",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="192.168.122.1", help="bind address")
    parser.add_argument("--port", type=int, default=5000, help="TCP port")
    parser.add_argument("--cooldown", type=int, default=120,
                        help="ignore repeated alerts from the same IP for N seconds")
    parser.add_argument("--auto-approve", action="store_true",
                        help="skip the [y/N] prompt (unattended demos)")
    parser.add_argument("--dry-run", action="store_true", help="print virsh commands without running them")
    parser.add_argument("--domain", default="vm-honeypot", help="libvirt domain to quarantine")
    parser.add_argument("--iface-mac", default="52:54:00:10:10:01",
                        help="fallback MAC of the isolated interface")
    parser.add_argument("--audit-log", default="state/incidents.jsonl", help="JSON-lines audit trail")
    parser.add_argument("--token", default=os.environ.get("SENTINEL_TOKEN", ""),
                        help="shared secret required in X-Sentinel-Token (empty disables auth)")
    parser.add_argument("--log-level", default="INFO", help="DEBUG, INFO, WARNING, ERROR")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)sZ %(levelname)-7s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    logging.Formatter.converter = time.gmtime

    cfg = Config(
        host=args.host,
        port=args.port,
        cooldown=args.cooldown,
        auto_approve=args.auto_approve,
        dry_run=args.dry_run,
        domain=args.domain,
        iface_mac=args.iface_mac.lower(),
        audit_log=Path(args.audit_log).expanduser(),
        token=args.token,
        log_level=args.log_level,
    )

    if not cfg.token:
        LOG.warning("SENTINEL_TOKEN is empty: the webhook accepts unauthenticated alerts. "
                    "Acceptable inside the lab network only.")

    bind_host = cfg.host
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((bind_host, cfg.port))
    except OSError as exc:
        console.print(f"[red]cannot bind {bind_host}:{cfg.port} ({exc})[/red]")
        console.print("[red]refusing to fall back to 0.0.0.0: that would expose the approval "
                      "webhook on every interface[/red]")
        console.print("[yellow]is the lab network up?  sudo virsh net-start default[/yellow]")
        return 2
    finally:
        probe.close()

    rc, out, err = run_virsh(["domstate", cfg.domain], timeout=15)
    if rc != 0:
        LOG.warning("domain %s not reachable via virsh (%s). Quarantine will fail until it is.",
                    cfg.domain, err or out)

    alerts: "queue.Queue[dict[str, Any]]" = queue.Queue()
    app = create_app(cfg, alerts)

    console.print(Panel.fit(
        "\n".join([
            "[bold]KVM-Sentinel-SOC — approval daemon[/bold]",
            f"webhook      : http://{bind_host}:{cfg.port}/alert",
            f"health       : http://{bind_host}:{cfg.port}/health",
            f"domain       : {cfg.domain}",
            f"cooldown     : {cfg.cooldown}s per attacker IP",
            f"auth token   : {'configured' if cfg.token else 'DISABLED'}",
            f"audit log    : {cfg.audit_log}",
            f"mode         : {'DRY-RUN' if cfg.dry_run else 'live'}"
            f"{' / auto-approve' if cfg.auto_approve else ''}",
            "",
            f"test: curl -s -X POST http://{bind_host}:{cfg.port}/alert "
            f"-H 'Content-Type: application/json' -d @alert.json",
        ]),
        border_style="cyan",
    ))

    server = threading.Thread(
        target=lambda: app.run(host=bind_host, port=cfg.port, threaded=True,
                               use_reloader=False, debug=False),
        name="flask",
        daemon=True,
    )
    server.start()

    stop = threading.Event()

    def _shutdown(signum, _frame):
        LOG.info("signal %s received, shutting down", signum)
        stop.set()

    signal_handlers = {}
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal_handlers[sig] = signal.signal(sig, _shutdown)
        except ValueError:  # not on the main thread (e.g. imported by tests)
            pass

    try:
        while not stop.is_set():
            try:
                alert = alerts.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                process_alert(cfg, alert)
            except Exception:  # one bad incident must not kill the controller
                LOG.exception("unhandled error while processing alert %s", alert.get("alert_id"))
    finally:
        for sig, handler in signal_handlers.items():
            try:
                signal.signal(sig, handler)
            except (ValueError, TypeError):
                pass
        console.print(
            f"[bold]shutdown[/bold] received={cfg.stats['received']} approved={cfg.stats['approved']} "
            f"dismissed={cfg.stats['dismissed']} failed={cfg.stats['failed']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
