"""Agent Parseur — turn raw sshd lines into structured events.

Data source: Loki. Promtail on vm-honeypot ships /var/log/auth.log to
http://10.10.0.20:3100 with the labels {job="ssh-honeypot", host="vm-honeypot",
source="auth.log"}.

Why polling query_range instead of the /tail websocket:

  * one dependency (requests), no reconnect logic for a long-lived socket,
  * a persisted cursor makes the pipeline restartable: after a container
    restart it resumes exactly where it stopped instead of losing the incident
    that was being analysed,
  * it is trivial to demonstrate during the defence: the cursor file is a
    JSON document a human can read.

Timestamp semantics: rsyslog's traditional format has no year ("Oct 30
10:11:12"), so the authoritative time of an event is the Loki/nanosecond
timestamp assigned at ingestion, not the text of the line. That is also what
the sliding window must use, because Promtail batches can arrive late.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import requests
from pydantic import BaseModel, Field

LOG = logging.getLogger("agent.parseur")

EventType = Literal[
    "failed_password",
    "invalid_user",
    "accepted_password",
    "connection_closed",
    "other",
]
AuthStatus = Literal["failure", "success", "unknown"]

IP_OCTET = r"(?:\d{1,3}\.){3}\d{1,3}"

# Priority order matters: the "invalid user" variants must be tested before the
# generic ones, otherwise the username would be captured as "invalid".
REGEX_ACCEPTED = re.compile(
    r"Accepted\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>" + IP_OCTET + r")\s+port\s+(?P<port>\d+)"
)
REGEX_FAILED_INVALID = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>" + IP_OCTET + r")\s+port\s+(?P<port>\d+)"
)
REGEX_FAILED = re.compile(
    r"Failed\s+(?P<method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>" + IP_OCTET + r")\s+port\s+(?P<port>\d+)"
)
REGEX_INVALID_USER = re.compile(r"Invalid\s+user\s+(?P<user>\S+)\s+from\s+(?P<ip>" + IP_OCTET + r")")
REGEX_CONNECTION_CLOSED = re.compile(
    r"Connection\s+closed\s+by\s+authenticating\s+user\s+(?P<user>\S+)\s+(?P<ip>" + IP_OCTET + r")"
)
REGEX_IP = re.compile(r"^" + IP_OCTET + r"$")

# Lines that are noise for the SOC (service lifecycle, disconnects without a
# user) are dropped instead of being stored as event_type="other".
NOISE_MARKERS = (
    "Server listening",
    "Received disconnect",
    "Disconnected from",
    "Connection reset by",
    "Connection closed by ",
    "pam_unix",
    "error: maximum authentication attempts exceeded",
)


class Event(BaseModel):
    """One structured authentication event."""

    ts: str = Field(description="ISO-8601 UTC timestamp (ingestion time, ...Z)")
    src_ip: str
    username: str = "unknown"
    event_type: EventType = "other"
    auth_status: AuthStatus = "unknown"
    raw: str = ""
    host: str = "vm-honeypot"


class LokiUnavailable(RuntimeError):
    """Raised when Loki cannot be reached or answers with an error."""


def ns_to_iso(ns: int) -> str:
    """Nanoseconds since epoch -> '2026-10-30T10:11:12.123456Z'."""
    return (
        datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class LokiParser:
    """Cursor-based reader for the honeypot stream in Loki."""

    def __init__(
        self,
        loki_url: str,
        query: str,
        state_dir: str | Path,
        initial_lookback_minutes: int = 30,
        session: requests.Session | None = None,
    ) -> None:
        self.loki_url = loki_url.rstrip("/")
        self.query = query
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.cursor_path = self.state_dir / "cursor.json"
        self.initial_lookback_minutes = initial_lookback_minutes
        self.session = session or requests.Session()
        self._seen: deque[str] = deque(maxlen=20000)
        self.last_ns = self._load_cursor()

    # ------------------------------------------------------------------ state
    def _load_cursor(self) -> int:
        if self.cursor_path.exists():
            try:
                payload = json.loads(self.cursor_path.read_text(encoding="utf-8"))
                last_ns = int(payload["last_ns"])
                for digest in payload.get("seen", [])[-2000:]:
                    self._seen.append(str(digest))
                LOG.info("resuming from cursor %s (%s)", last_ns, ns_to_iso(last_ns))
                return last_ns
            except (OSError, ValueError, KeyError, TypeError) as exc:
                LOG.warning("cursor %s unreadable (%s); falling back to lookback", self.cursor_path, exc)

        # First start: look back far enough to catch the burst that triggered
        # the lab, instead of silently starting "now".
        start = int(time.time() * 1_000_000_000) - self.initial_lookback_minutes * 60 * 1_000_000_000
        LOG.info("no cursor: initial lookback of %s min (%s)", self.initial_lookback_minutes, ns_to_iso(start))
        return start

    def commit(self, ns: int) -> None:
        """Persist the cursor atomically. Only call once the batch is handled."""
        self.last_ns = max(self.last_ns, ns)
        payload = {"last_ns": str(self.last_ns), "seen": list(self._seen)[-2000:]}
        tmp = self.cursor_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, self.cursor_path)
        except OSError as exc:
            LOG.error("could not persist cursor: %s", exc)

    # ------------------------------------------------------------------- read
    def fetch(self, limit: int = 5000, timeout: float = 10.0) -> list[tuple[int, str]]:
        """Return new (nanoseconds, raw line) pairs, oldest first."""
        now_ns = int(time.time() * 1_000_000_000)
        params = {
            "query": self.query,
            "start": str(self.last_ns + 1),
            "end": str(now_ns),
            "limit": str(limit),
            "direction": "forward",
        }
        try:
            response = self.session.get(
                f"{self.loki_url}/loki/api/v1/query_range", params=params, timeout=timeout
            )
        except requests.RequestException as exc:
            raise LokiUnavailable(f"cannot reach Loki at {self.loki_url}: {exc}") from exc

        if response.status_code != 200:
            raise LokiUnavailable(f"Loki returned HTTP {response.status_code}: {response.text[:200]}")

        try:
            body = response.json()
        except ValueError as exc:
            raise LokiUnavailable(f"Loki returned non-JSON payload: {exc}") from exc

        entries: list[tuple[int, str]] = []
        for stream in (body.get("data") or {}).get("result") or []:
            for value in stream.get("values") or []:
                try:
                    ns = int(value[0])
                    line = str(value[1])
                except (IndexError, TypeError, ValueError):
                    continue
                digest = hashlib.sha1(f"{ns}:{line}".encode("utf-8", "replace")).hexdigest()
                if digest in self._seen:
                    continue
                self._seen.append(digest)
                entries.append((ns, line))

        entries.sort(key=lambda item: item[0])
        return entries

    # ------------------------------------------------------------------ parse
    @staticmethod
    def parse_line(ns: int, line: str, host: str = "vm-honeypot") -> Event | None:
        """Map one raw sshd line to an Event (or None for non-events)."""
        raw = line.strip()
        if not raw:
            return None
        if any(marker in raw for marker in NOISE_MARKERS):
            return None
        if "sshd" not in raw and "Accepted" not in raw and "Failed" not in raw:
            return None

        timestamp = ns_to_iso(ns)

        def build(username: str, ip: str, event_type: EventType, status: AuthStatus) -> Event | None:
            if not REGEX_IP.match(ip):
                return None
            return Event(
                ts=timestamp,
                src_ip=ip,
                username=(username or "unknown")[:64],
                event_type=event_type,
                auth_status=status,
                raw=raw[:2000],
                host=host,
            )

        match = REGEX_ACCEPTED.search(raw)
        if match:
            return build(match.group("user"), match.group("ip"), "accepted_password", "success")

        match = REGEX_FAILED_INVALID.search(raw)
        if match:
            return build(match.group("user"), match.group("ip"), "failed_password", "failure")

        match = REGEX_FAILED.search(raw)
        if match:
            return build(match.group("user"), match.group("ip"), "failed_password", "failure")

        match = REGEX_INVALID_USER.search(raw)
        if match:
            return build(match.group("user"), match.group("ip"), "invalid_user", "failure")

        match = REGEX_CONNECTION_CLOSED.search(raw)
        if match:
            return build(match.group("user"), match.group("ip"), "connection_closed", "unknown")

        return None

    def fetch_events(self, host: str = "vm-honeypot") -> tuple[list[Event], int]:
        """Fetch + parse one batch. Returns (events, max_ns) for cursor commit."""
        batch = self.fetch()
        events: list[Event] = []
        max_ns = 0
        for ns, line in batch:
            max_ns = max(max_ns, ns)
            event = self.parse_line(ns, line, host=host)
            if event is not None:
                events.append(event)
        # If every line was filtered out, still advance the cursor one
        # microsecond past the last line so the same batch is not re-read.
        if batch and max_ns == 0:
            max_ns = max(ns for ns, _ in batch)
        return events, max_ns
