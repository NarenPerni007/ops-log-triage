# Ops Log Triage

A small service that turns a log snippet or alert payload into a structured triage summary: severity, likely cause, and suggested next steps.

## What it does

POST to `/triage`:

```bash
curl -s -X POST localhost:8080/triage -H 'Content-Type: application/json' -d '{
  "logs": "pod CrashLoopBackOff, back-off restarting failed container",
  "alert": {"name": "PodCrashLooping", "severity": "critical"}
}'
```

Response:

```json
{
  "severity": "high",
  "likely_cause": "Container keeps crashing on start.",
  "next_steps": ["Read the container logs from the last crash.", "..."],
  "confidence": "medium",
  "ai_used": false,
  "note": "Rule-based triage. No model was used."
}
```

## How it works

- **With `LLM_API_KEY` set**, it asks a language model for a triage summary and marks `ai_used: true`.
- **Without a key, or if the model call fails**, it falls back to rule-based matching on common failure signatures: OOM, CrashLoopBackOff, connection refused, timeouts, 5xx, disk full, permission errors, DNS.
- The fallback is the point. The service is useful with no model at all.

## Limits

This is a triage helper, not a replacement for judgment. Model output can be wrong, and rule matches are guesses based on patterns. Always verify against the real logs before acting. It does not page anyone, restart anything, or change any state.

## Run locally

```bash
python3 src/log_triage.py
```

Standard library only, no dependencies. Set `LLM_API_KEY` to enable model triage.

## Run with Docker

```bash
docker build -t log-triage .
docker run -p 8080:8080 -e LLM_API_KEY=$LLM_API_KEY log-triage
```

## Deploy with Helm

```bash
helm install log-triage helm/log-triage
```

To enable model triage in the cluster, create a Secret named `log-triage-secrets` with key `LLM_API_KEY` and set `secretName: log-triage-secrets` in values. The key is never committed and never baked into the image.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

CI runs the tests, builds the Docker image, and lints the Helm chart on every push and pull request.
