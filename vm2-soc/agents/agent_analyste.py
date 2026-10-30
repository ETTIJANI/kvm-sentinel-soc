"""Agent Analyste — local LLM threat assessment through Ollama.

Sends the structured incident (plus a handful of raw log lines) to a small
CPU-only model and asks for a strict JSON verdict. The model is qwen2.5:0.5b by
default: it fits comfortably in the 5 GiB VM and answers in a few seconds on 4
vCPUs once warm. Alerts use a hard 25 s cap so a hung model can never stall a
live demo; the one-off cold start is paid by warm_up() at container start.

The LLM is treated as untrusted input:
  * the response is parsed defensively (prose/fences tolerated, first balanced
    JSON object extracted),
  * every field is clamped and validated with pydantic,
  * `recommended_actions` is intersected with a whitelist,
  * the text is only ever printed escaped and stored in a report - it is never
    used to build a path or a command.

If Ollama is unreachable or answers garbage, the analyst degrades to a
deterministic heuristic assessment. Losing the model must never lose the
incident.
"""

from __future__ import annotations

import json
import logging
import re

import requests
from pydantic import BaseModel, Field, ValidationError

from agent_detecteur import Alert, label_for

LOG = logging.getLogger("agent.analyste")

ALLOWED_ACTIONS = ("snapshot", "quarantine", "block-ssh-port", "review-logs")
DEFAULT_ACTIONS = ["snapshot", "quarantine"]

SYSTEM_PROMPT = (
    "You are the analyst agent of a Security Operations Centre protecting a KVM "
    "hypervisor lab. You receive structured evidence about SSH authentication "
    "attempts against an Ubuntu 24.04 guest named vm-honeypot, which lives on an "
    "isolated libvirt network (10.10.0.0/24) and exposes a deliberately weak SSH "
    "service. The hypervisor can take exactly two containment actions: create a "
    "forensic snapshot of the guest, and set its virtual NIC link down "
    "(quarantine). You answer ONLY with a JSON object, no prose, no markdown "
    "fence. Be concise, factual and specific to the evidence given."
)

OUTPUT_CONTRACT = """Return exactly this JSON shape:
{
  "severity_score": <integer 0-10>,
  "severity_label": "<low|medium|high|critical>",
  "summary": "<one sentence, max 300 characters>",
  "analysis_markdown": "<3 to 6 short bullet points separated by \\n, max 1200 characters>",
  "mitre_techniques": ["<ATT&CK technique id, e.g. T1110.001>"],
  "recommended_actions": [<subset of "snapshot", "quarantine", "block-ssh-port", "review-logs">]
}
Scoring guide: 0-2 background noise, 3-5 single-source brute force, 6-7 sustained
brute force against privileged accounts, 8-10 evidence of successful compromise
or lateral movement intent."""


class Analysis(BaseModel):
    severity_score: int = 5
    severity_label: str = "medium"
    summary: str = ""
    analysis_markdown: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


def extract_json_object(text: str) -> dict:
    """Extract the first balanced {...} object from an LLM answer."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in model output")
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : index + 1])
    raise ValueError("unbalanced JSON object in model output")


def sanitize_text(value: str, limit: int) -> str:
    """Keep printable text only; strip control characters used for terminal tricks."""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value))
    return cleaned.strip()[:limit]


class AgentAnalyste:
    def __init__(self, ollama_url: str, model: str, timeout_seconds: int = 25) -> None:
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout = timeout_seconds
        self.session = requests.Session()

    def warm_up(self, timeout_seconds: int = 120) -> bool:
        payload = {
            "model": self.model,
            "prompt": "ok",
            "stream": False,
            "options": {"num_predict": 1, "num_ctx": 128},
        }
        try:
            response = self.session.post(
                f"{self.ollama_url}/api/generate", json=payload, timeout=timeout_seconds
            )
        except requests.RequestException as exc:
            LOG.warning("model warm-up failed (%s)", exc)
            return False
        return response.status_code == 200

    # ------------------------------------------------------------------ prompt
    def build_prompt(self, alert: Alert, samples: list[str]) -> str:
        evidence = "\n".join(f"- {sanitize_text(line, 300)}" for line in samples[:12]) or "- (no raw lines)"
        return (
            "INCIDENT EVIDENCE\n"
            f"rule: {alert.rule}\n"
            f"attacker_ip: {alert.attacker_ip}\n"
            f"failures: {alert.failure_count} in {alert.window_seconds}s (threshold {alert.threshold})\n"
            f"usernames: {', '.join(alert.usernames) or 'unknown'}\n"
            f"first_seen: {alert.first_seen}\n"
            f"last_seen: {alert.last_seen}\n"
            f"deterministic_severity: {alert.severity_label} ({alert.severity_score}/10)\n\n"
            "SAMPLE RAW LOG LINES\n"
            f"{evidence}\n\n"
            "ENVIRONMENT\n"
            "- target: Ubuntu 24.04 guest 'vm-honeypot' on an isolated libvirt network\n"
            "- exposure: SSH honeypot with a fake weak root credential\n"
            "- containment available: forensic snapshot, virtual NIC quarantine\n\n"
            f"{OUTPUT_CONTRACT}"
        )

    # ------------------------------------------------------------------- query
    def analyze(self, alert: Alert, samples: list[str]) -> Analysis:
        prompt = self.build_prompt(alert, samples)
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "num_ctx": 2048,
                "num_predict": 700,
                "top_p": 0.9,
            },
        }

        try:
            response = self.session.post(
                f"{self.ollama_url}/api/generate", json=payload, timeout=self.timeout
            )
        except requests.RequestException as exc:
            LOG.warning("Ollama unreachable (%s); using heuristic assessment", exc)
            return self.heuristic(alert, "local LLM unreachable")

        if response.status_code != 200:
            LOG.warning("Ollama HTTP %s; using heuristic assessment", response.status_code)
            return self.heuristic(alert, f"Ollama HTTP {response.status_code}")

        try:
            body = response.json()
            raw_answer = body.get("response", "")
        except ValueError as exc:
            LOG.warning("Ollama returned non-JSON envelope (%s); using heuristic", exc)
            return self.heuristic(alert, "invalid Ollama envelope")

        try:
            data = extract_json_object(raw_answer)
            analysis = Analysis(**data)
        except (ValueError, ValidationError, TypeError) as exc:
            LOG.warning("could not validate model output (%s); using heuristic", exc)
            LOG.debug("raw model output: %s", raw_answer[:500])
            return self.heuristic(alert, "unparseable model output")

        return self._normalize(analysis, alert)

    # --------------------------------------------------------------- normalize
    def _normalize(self, analysis: Analysis, alert: Alert) -> Analysis:
        score = max(0, min(int(analysis.severity_score), 10))
        # The deterministic floor protects the operator from an over-confident
        # tiny model that would rate a real burst as "low".
        if alert.failure_count >= alert.threshold * 2 and score < 5:
            score = 5
        actions = [a for a in analysis.recommended_actions if a in ALLOWED_ACTIONS]
        if not actions:
            actions = list(DEFAULT_ACTIONS)
        techniques = [sanitize_text(t, 40) for t in analysis.mitre_techniques if str(t).strip()][:6]
        if not techniques:
            techniques = ["T1110.001"]

        summary = sanitize_text(analysis.summary, 300) or alert.summary
        markdown = sanitize_text(analysis.analysis_markdown, 1200)
        if not markdown:
            markdown = (
                f"- {alert.failure_count} failed SSH authentications from {alert.attacker_ip} "
                f"within {alert.window_seconds}s.\n"
                f"- Targeted accounts: {', '.join(alert.usernames) or 'unknown'}.\n"
                "- Containment recommended: snapshot then quarantine the guest NIC."
            )

        return Analysis(
            severity_score=score,
            severity_label=label_for(score),
            summary=summary,
            analysis_markdown=markdown,
            mitre_techniques=techniques,
            recommended_actions=actions,
        )

    # ---------------------------------------------------------------- fallback
    def heuristic(self, alert: Alert, reason: str) -> Analysis:
        compromised = "successful authentication" in alert.summary.lower()
        markdown = "\n".join(
            [
                f"- {alert.failure_count} failed SSH authentications from `{alert.attacker_ip}` "
                f"within {alert.window_seconds}s (threshold {alert.threshold}).",
                f"- Accounts targeted: {', '.join(alert.usernames) or 'unknown'}.",
                f"- Source is on the isolated backend network; no route to the internet.",
                f"- Deterministic assessment only ({reason}); the LLM verdict is unavailable.",
                "- Recommended: forensic snapshot, then quarantine the virtual NIC and review the guest logs.",
            ]
        )
        return Analysis(
            severity_score=alert.severity_score,
            severity_label=alert.severity_label,
            summary=(
                f"Heuristic assessment: {alert.failure_count} failed SSH logins from "
                f"{alert.attacker_ip} in {alert.window_seconds}s"
                + (" with evidence of a successful login." if compromised else ".")
            ),
            analysis_markdown=markdown,
            mitre_techniques=["T1110.001", "T1078"] if compromised else ["T1110.001"],
            recommended_actions=list(DEFAULT_ACTIONS),
        )
