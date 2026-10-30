"""Agent Détecteur — sliding-window brute-force detection.

Rule: more than N failed SSH authentications from the same source IP inside a
W-second window (defaults: 5 failures / 30 s, per the lab specification).

Two deliberate choices:

1. Only `failed_password` events are counted. OpenSSH logs *two* lines for an
   unknown user ("Invalid user bob from ..." then "Failed password for invalid
   user bob from ..."), so counting both would halve the effective threshold
   and make the detector look unstable during the defence.
2. A per-IP cooldown (default 120 s) and the clearing of the IP's window after
   a fire produce one incident per burst instead of one per packet. The
   rapporteur would otherwise write dozens of reports for a single attack.

The severity produced here is a deterministic floor computed from observable
facts. The analyst agent may raise or lower it, but if the LLM is cold or
unavailable this floor is what reaches the operator.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from datetime import datetime, timezone
from typing import Deque, Literal

from pydantic import BaseModel, Field

from agent_parseur import Event

LOG = logging.getLogger("agent.detecteur")

SeverityLabel = Literal["low", "medium", "high", "critical"]

# Accounts that make an attempt "targeted" rather than opportunistic.
HIGH_VALUE_USERS = {"root", "admin", "ubuntu", "oracle", "postgres", "pi"}


class Alert(BaseModel):
    """A confirmed brute-force incident, before and after AI enrichment."""

    alert_id: str
    detected_at: str
    attacker_ip: str
    failure_count: int
    window_seconds: int
    threshold: int
    usernames: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    rule: str = "ssh_bruteforce"
    severity_score: int = 5
    severity_label: SeverityLabel = "medium"
    summary: str = ""
    analysis_markdown: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


def label_for(score: int) -> SeverityLabel:
    if score < 3:
        return "low"
    if score < 6:
        return "medium"
    if score < 8:
        return "high"
    return "critical"


def iso_from_ns(ns: int) -> str:
    return (
        datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def alert_id_from(ns: int, ip: str) -> str:
    stamp = datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"inc-{stamp}-{ip.replace('.', '_').replace(':', '-')}"


class SlidingWindowDetector:
    def __init__(
        self,
        threshold: int = 5,
        window_seconds: int = 30,
        cooldown_seconds: int = 120,
    ) -> None:
        self.threshold = max(1, threshold)
        self.window_ns = max(1, window_seconds) * 1_000_000_000
        self.cooldown_ns = max(0, cooldown_seconds) * 1_000_000_000
        self.failures: dict[str, Deque[tuple[int, Event]]] = {}
        self.successes: dict[str, Deque[tuple[int, str]]] = {}
        self.cooldown_until: dict[str, int] = {}
        self.total_failures = 0
        self.alerts_fired = 0

    # ------------------------------------------------------------------ ingest
    def _prune(self, ip: str, now_ns: int) -> None:
        window = self.failures.get(ip)
        if window is not None:
            while window and now_ns - window[0][0] > self.window_ns:
                window.popleft()
        successes = self.successes.get(ip)
        if successes is not None:
            while successes and now_ns - successes[0][0] > self.window_ns:
                successes.popleft()

    def observe(self, event: Event, ns: int) -> Alert | None:
        """Feed one event. Returns an Alert when a burst is confirmed."""
        ip = event.src_ip
        if not ip:
            return None

        if event.event_type == "accepted_password":
            self.successes.setdefault(ip, deque()).append((ns, event.username))
            return None

        if event.auth_status != "failure" or event.event_type != "failed_password":
            return None

        self.total_failures += 1
        window = self.failures.setdefault(ip, deque())
        window.append((ns, event))
        self._prune(ip, ns)

        if len(window) < self.threshold:
            return None

        until = self.cooldown_until.get(ip, 0)
        if ns < until:
            return None

        alert = self._build_alert(ip, ns, list(window))
        self.alerts_fired += 1
        self.cooldown_until[ip] = ns + self.cooldown_ns
        window.clear()
        return alert

    # ------------------------------------------------------------------- build
    def _build_alert(self, ip: str, ns: int, window: list[tuple[int, Event]]) -> Alert:
        events = [event for _, event in window]
        usernames = sorted({event.username for event in events if event.username})[:10]
        first_ns = window[0][0]
        last_ns = window[-1][0]
        failures = len(events)

        score = 5
        if failures >= self.threshold * 2:
            score += 1
        if failures >= self.threshold * 4:
            score += 1
        if failures >= self.threshold * 8:
            score += 1
        if any(user in HIGH_VALUE_USERS for user in usernames):
            score += 1
        successes = list(self.successes.get(ip) or [])
        compromised = [user for _, user in successes]
        if compromised:
            score += 2
        score = max(0, min(score, 10))

        summary = (
            f"{failures} failed SSH authentications from {ip} within "
            f"{self.window_ns // 1_000_000_000}s (threshold {self.threshold})."
        )
        if compromised:
            summary += f" A successful login was observed for: {', '.join(sorted(set(compromised)))}."

        return Alert(
            alert_id=alert_id_from(ns, ip),
            detected_at=iso_from_ns(ns),
            attacker_ip=ip,
            failure_count=failures,
            window_seconds=self.window_ns // 1_000_000_000,
            threshold=self.threshold,
            usernames=usernames,
            first_seen=iso_from_ns(first_ns),
            last_seen=iso_from_ns(last_ns),
            severity_score=score,
            severity_label=label_for(score),
            summary=summary,
            recommended_actions=["snapshot", "quarantine"],
            mitre_techniques=["T1110.001"],
        )

    # ------------------------------------------------------------------- stats
    def stats(self) -> dict[str, int]:
        return {
            "tracked_ips": len(self.failures),
            "total_failures": self.total_failures,
            "alerts_fired": self.alerts_fired,
            "cooldowns_active": sum(1 for until in self.cooldown_until.values() if until > time.time_ns()),
        }
