#!/usr/bin/env python3
"""main.py — orchestration of the KVM-Sentinel-SOC agent pipeline.

Loop (every POLL_INTERVAL_SECONDS):

    Loki  ->  Agent Parseur  ->  Agent Detecteur  ->  Agent Analyste  ->  Agent Rapporteur
                                  (sliding window)     (Ollama, JSON)      (report + webhook)

Design notes:

  * One thread, synchronous. The pipeline is a state machine over a log stream;
    concurrency would only add reordering bugs to a teaching demo.
  * The cursor is committed only after a batch has been fully processed, so a
    crash mid-incident replays it instead of losing it (the parser dedupes).
  * Every external dependency can fail without killing the loop: Loki outages
    back off exponentially, Ollama falls back to a heuristic, the webhook
    retries then gives up. The heartbeat file keeps the container HEALTHCHECK
    honest.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from agent_analyste import AgentAnalyste
from agent_detecteur import Alert, SlidingWindowDetector
from agent_parseur import Event, LokiParser, LokiUnavailable
from agent_rapporteur import AgentRapporteur

LOG = logging.getLogger("pipeline")
console = Console()


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #
def env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("%s=%r is not an integer; using %s", name, raw, default)
        return default


def iso_to_ns(iso: str) -> int:
    try:
        parsed = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return int(time.time() * 1_000_000_000)
    return int(parsed.timestamp() * 1_000_000_000)


def touch_heartbeat(state_dir: Path) -> None:
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        (state_dir / "heartbeat").write_text(
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), encoding="utf-8"
        )
    except OSError as exc:
        LOG.debug("heartbeat write failed: %s", exc)


def print_incident(alert: Alert, outcome: dict) -> None:
    webhook = outcome.get("webhook") or {}
    delivered = "yes" if webhook.get("delivered") else "NO"
    table = Table(title=f"incident {alert.alert_id}", border_style="red", show_lines=False)
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("attacker", alert.attacker_ip)
    table.add_row("failures", f"{alert.failure_count} / {alert.window_seconds}s (threshold {alert.threshold})")
    table.add_row("severity", f"{alert.severity_label} ({alert.severity_score}/10)")
    table.add_row("usernames", ", ".join(alert.usernames) or "unknown")
    table.add_row("mitre", ", ".join(alert.mitre_techniques) or "n/a")
    table.add_row("report", outcome.get("report_md", "n/a"))
    table.add_row("webhook", delivered)
    console.print(table)


# --------------------------------------------------------------------------- #
# pipeline
# --------------------------------------------------------------------------- #
class Pipeline:
    def __init__(self) -> None:
        self.loki_url = env_str("LOKI_URL", "http://loki:3100")
        self.loki_query = env_str("LOKI_QUERY", '{job="ssh-honeypot"}')
        self.poll_interval = max(1, env_int("POLL_INTERVAL_SECONDS", 2))
        self.lookback = max(0, env_int("INITIAL_LOOKBACK_MINUTES", 30))
        self.ollama_url = env_str("OLLAMA_URL", "http://ollama:11434")
        self.ollama_model = env_str("OLLAMA_MODEL", "qwen2.5:0.5b")
        self.ollama_timeout = max(10, env_int("OLLAMA_TIMEOUT_SECONDS", 180))
        self.threshold = max(1, env_int("BRUTEFORCE_THRESHOLD", 5))
        self.window = max(1, env_int("BRUTEFORCE_WINDOW_SECONDS", 30))
        self.cooldown = max(0, env_int("ALERT_COOLDOWN_SECONDS", 120))
        self.webhook_url = env_str("WEBHOOK_URL", "http://192.168.122.1:5000/alert")
        self.webhook_timeout = max(1, env_int("WEBHOOK_TIMEOUT_SECONDS", 10))
        self.reports_dir = Path(env_str("REPORTS_DIR", "/reports"))
        self.state_dir = Path(env_str("STATE_DIR", "/app/state"))
        self.token = env_str("SENTINEL_TOKEN", "")

        self.parser = LokiParser(
            loki_url=self.loki_url,
            query=self.loki_query,
            state_dir=self.state_dir,
            initial_lookback_minutes=self.lookback,
        )
        self.detector = SlidingWindowDetector(
            threshold=self.threshold,
            window_seconds=self.window,
            cooldown_seconds=self.cooldown,
        )
        self.analyst = AgentAnalyste(
            ollama_url=self.ollama_url,
            model=self.ollama_model,
            timeout_seconds=self.ollama_timeout,
        )
        self.rapporteur = AgentRapporteur(
            reports_dir=self.reports_dir,
            webhook_url=self.webhook_url,
            timeout_seconds=self.webhook_timeout,
            token=self.token,
        )
        self.samples: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=50))
        self.stop_event = threading.Event()

    # ------------------------------------------------------------------ checks
    def preflight(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            probe = self.reports_dir / ".write-test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
        except OSError as exc:
            LOG.error("reports directory %s is not writable: %s", self.reports_dir, exc)
            raise SystemExit(2)

        LOG.info("loki      : %s  query=%s", self.loki_url, self.loki_query)
        LOG.info("ollama    : %s  model=%s  timeout=%ss", self.ollama_url, self.ollama_model, self.ollama_timeout)
        LOG.info("detection : %s failures / %ss, cooldown %ss", self.threshold, self.window, self.cooldown)
        LOG.info("webhook   : %s", self.webhook_url)
        LOG.info("reports   : %s", self.reports_dir)
        LOG.info("state     : %s (lookback %s min)", self.state_dir, self.lookback)
        if not self.token:
            LOG.warning("SENTINEL_TOKEN is empty: the controller webhook is unauthenticated (lab network only)")

    # -------------------------------------------------------------------- work
    def handle_alert(self, alert: Alert) -> None:
        samples = list(self.samples.get(alert.attacker_ip, deque()))
        analysis = self.analyst.analyze(alert, samples)
        enriched = alert.model_copy(
            update={
                "severity_score": analysis.severity_score,
                "severity_label": analysis.severity_label,
                "summary": analysis.summary,
                "analysis_markdown": analysis.analysis_markdown,
                "mitre_techniques": analysis.mitre_techniques,
                "recommended_actions": analysis.recommended_actions,
            }
        )
        LOG.info(
            "alert %s ip=%s failures=%s severity=%s/%s",
            enriched.alert_id,
            enriched.attacker_ip,
            enriched.failure_count,
            enriched.severity_label,
            enriched.severity_score,
        )
        outcome = self.rapporteur.publish(enriched)
        print_incident(enriched, outcome)

    def run(self) -> int:
        self.preflight()
        if self.analyst.warm_up():
            LOG.info("analyst model %s loaded (alerts answer in ~1-3s)", self.ollama_model)
        else:
            LOG.warning("%s not loaded: the first alert will use the heuristic assessment",
                        self.ollama_model)
        backoff = 1.0
        LOG.info("pipeline started (poll %ss)", self.poll_interval)

        while not self.stop_event.is_set():
            try:
                events, max_ns = self.parser.fetch_events()
            except LokiUnavailable as exc:
                LOG.warning("Loki unavailable: %s — retrying in %.0fs", exc, backoff)
                self.stop_event.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                touch_heartbeat(self.state_dir)
                continue
            except Exception:  # defensive: a parser bug must not kill the loop
                LOG.exception("unexpected error while fetching logs")
                self.stop_event.wait(min(backoff, 10.0))
                backoff = min(backoff * 2, 30.0)
                continue

            backoff = 1.0
            if events:
                LOG.debug("processing %s event(s)", len(events))
            for event in events:
                self.samples[event.src_ip].append(event.raw)
                try:
                    alert = self.detector.observe(event, iso_to_ns(event.ts))
                except Exception:
                    LOG.exception("detector error on event %s", event.ts)
                    continue
                if alert is not None:
                    try:
                        self.handle_alert(alert)
                    except Exception:
                        LOG.exception("failed to publish alert %s", alert.alert_id)

            if max_ns:
                self.parser.commit(max_ns)
            touch_heartbeat(self.state_dir)

            stats = self.detector.stats()
            if events:
                LOG.debug("detector stats: %s", stats)
            self.stop_event.wait(self.poll_interval)

        LOG.info("pipeline stopped; final detector stats: %s", self.detector.stats())
        return 0


def main() -> int:
    logging.basicConfig(
        level=getattr(logging, env_str("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)sZ %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stdout,
    )
    logging.Formatter.converter = time.gmtime

    pipeline = Pipeline()

    def _shutdown(signum, _frame):
        LOG.info("signal %s received, shutting down", signum)
        pipeline.stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _shutdown)
        except ValueError:
            pass

    return pipeline.run()


if __name__ == "__main__":
    raise SystemExit(main())
