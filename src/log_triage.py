#!/usr/bin/env python3
"""Small log and alert triage service for ops use.

POST /triage with a JSON body:
    {"logs": "<log lines or alert text>", "alert": {"name": "...", "severity": "..."}}

Returns a structured triage summary:
    {"severity": "...", "likely_cause": "...", "next_steps": [...],
     "confidence": "...", "ai_used": true/false}

How it works:
- If LLM_API_KEY is set, it asks a language model for a triage summary.
- If no key is set, or the model call fails, it falls back to rule-based
  matching on common failure signatures (OOM, timeouts, 5xx, disk full...).

This is a triage helper, not a replacement for judgment. Model output can
be wrong. Always verify against the real logs before acting.

Standard library only, no dependencies.

Environment:
    LLM_API_KEY    API key for the model (optional)
    LLM_BASE_URL   Chat completions endpoint (default: OpenAI)
    LLM_MODEL      Model name (default: gpt-4o-mini)
    PORT           Listen port (default: 8080)
"""

import json
import logging
import os
import re
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("log-triage")

RULES = [
    {
        "pattern": r"OOMKilled|out of memory|java\.lang\.OutOfMemoryError",
        "severity": "high",
        "likely_cause": "Process ran out of memory and was killed.",
        "next_steps": [
            "Check container memory limits and recent usage.",
            "Look for a memory leak: usage climbing steadily before the kill.",
            "Raise the memory limit or fix the leak, then restart.",
        ],
    },
    {
        "pattern": r"CrashLoopBackOff|Back-off restarting failed container",
        "severity": "high",
        "likely_cause": "Container keeps crashing on start.",
        "next_steps": [
            "Read the container logs from the last crash.",
            "Check the startup command, config, and mounted secrets.",
            "Confirm the image tag did not change on the last deploy.",
        ],
    },
    {
        "pattern": r"connection refused|ECONNREFUSED|dial tcp.*refused",
        "severity": "high",
        "likely_cause": "Target service is down or not listening on that port.",
        "next_steps": [
            "Check whether the target service is running.",
            "Verify the port and the service address or DNS name.",
            "Check firewall and network policy rules between the two services.",
        ],
    },
    {
        "pattern": r"timeout|timed out|deadline exceeded|context deadline",
        "severity": "medium",
        "likely_cause": "A call took longer than the allowed timeout.",
        "next_steps": [
            "Check the downstream service latency and saturation.",
            "Look for a slow query, a retry storm, or a saturated queue.",
            "Confirm the timeout setting matches what the dependency can do.",
        ],
    },
    {
        "pattern": r"\b5\d\d\b|internal server error",
        "severity": "medium",
        "likely_cause": "Server-side errors in the application.",
        "next_steps": [
            "Check the app error logs around the first 5xx.",
            "Correlate with the last deploy or config change.",
            "Check the health of downstream dependencies.",
        ],
    },
    {
        "pattern": r"no space left|disk full|No space left on device",
        "severity": "high",
        "likely_cause": "Disk is full on the host or volume.",
        "next_steps": [
            "Find what is eating disk: logs, temp files, old images.",
            "Free space or grow the volume, then restart affected services.",
            "Add a disk usage alert if one does not exist.",
        ],
    },
    {
        "pattern": r"permission denied|forbidden|unauthorized|401|403",
        "severity": "medium",
        "likely_cause": "Credentials or permissions are missing or expired.",
        "next_steps": [
            "Check the service account, token, or API key in use.",
            "Verify the role or policy still grants the needed permission.",
            "Check for an expired certificate or rotated secret.",
        ],
    },
    {
        "pattern": r"DNS|name resolution|Name or service not known|NXDOMAIN",
        "severity": "medium",
        "likely_cause": "DNS name does not resolve.",
        "next_steps": [
            "Check the DNS name spelling and the resolver config.",
            "Confirm the target service exists and is registered.",
            "Check for a recent DNS or service discovery change.",
        ],
    },
]


def rule_based_triage(text):
    """Match log text against known failure signatures."""
    for rule in RULES:
        if re.search(rule["pattern"], text, re.IGNORECASE):
            return {
                "severity": rule["severity"],
                "likely_cause": rule["likely_cause"],
                "next_steps": rule["next_steps"],
                "confidence": "medium",
                "ai_used": False,
                "matched_rule": rule["pattern"],
            }
    return {
        "severity": "low",
        "likely_cause": "No known failure signature matched.",
        "next_steps": [
            "Read the full log context around the alert time.",
            "Check recent deploys and config changes for the service.",
            "Look at the service dashboard for latency, errors, and saturation.",
        ],
        "confidence": "low",
        "ai_used": False,
        "matched_rule": None,
    }


def call_llm(text, alert):
    """Ask the model for a triage summary. Returns None on any failure."""
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("LLM_MODEL", "gpt-4o-mini")
    prompt = (
        "You are an on-call triage helper. Given log text and an optional alert, "
        "return ONLY a JSON object with keys: severity (low/medium/high), "
        "likely_cause (one sentence), next_steps (list of 2-4 short steps), "
        "confidence (low/medium/high). Do not guess facts that are not in the logs. "
        f"Logs:\n{text}\nAlert: {json.dumps(alert or {})}"
    )
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = json.loads(response.read().decode("utf-8"))
        content = body["choices"][0]["message"]["content"]
        result = json.loads(content)
        result["ai_used"] = True
        return result
    except Exception as exc:  # noqa: BLE001 - any model failure falls back to rules
        logger.warning("Model call failed, falling back to rules: %s", exc)
        return None


def triage(payload):
    """Return a triage summary for a payload with logs and an optional alert."""
    text = payload.get("logs", "") or ""
    alert = payload.get("alert")
    if text.strip():
        llm_result = call_llm(text, alert)
        if llm_result:
            llm_result.setdefault("note", "Model output. Verify against the real logs before acting.")
            return llm_result
    result = rule_based_triage(text)
    result["note"] = "Rule-based triage. No model was used."
    return result


class TriageHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep stdout clean
        pass

    def _send_json(self, status, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/triage":
            self._send_json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, OSError):
            self._send_json(400, {"error": "request body must be valid JSON"})
            return
        self._send_json(200, triage(payload))


def main():
    port = int(os.environ.get("PORT", "8080"))
    server = HTTPServer(("0.0.0.0", port), TriageHandler)
    logger.info("Listening on port %d", port)
    server.serve_forever()


if __name__ == "__main__":
    main()
