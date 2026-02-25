# Forensics

Vigil's forensics module scans historical LLM log files for breaches that
happened before Canari was deployed — or during gaps in coverage.

## Why Forensics

Real-world deployment sequence:

1. You ship a product. Monitoring is minimal.
2. You learn about prompt injection. You deploy Canari.
3. But attacks may have happened in the months before Canari was live.

The forensics module answers: "Were we already compromised?"

## How It Works

`VigilForensicsWrapper` uses `vigil.forensics`:

1. **Parse** — the log file is parsed with the appropriate parser (OTEL or MLflow).
   Each parser extracts `(role, content)` pairs from structured log records.
2. **Detect** — `detect_findings()` runs every message through the 27-pattern Aho-Corasick scanner.
3. **Export** — each `Finding` is converted to a `.bp.json` snapshot with
   `metadata.source = "forensics"`.

## Pattern Library

The pattern library is defined in `vigil.forensics.patterns`.
It ships with 27 built-in patterns across four tiers.

### Tier 1 — Canari Synthetic Tokens

Patterns for every token type that Canari can generate. If any of these match
in historical logs, the canary was already leaking before monitoring began.

| Pattern ID | Token type |
|---|---|
| `canari_api_key` | `api_key` |
| `canari_stripe_test` | `stripe_key` (test) |
| `canari_stripe_live` | `stripe_key` (live) |
| `canari_email` | `email` |
| `canari_phone` | `phone` |
| `canari_jwt` | `jwt` |
| `canari_db_conn` | `db_connection_string` |
| `canari_custom` | `custom` |

### Tier 2 — Real Credentials

Patterns for credentials that should never appear in LLM output.
A match here means a real secret was leaked.

| Pattern ID | Credential type |
|---|---|
| `cred_stripe_live` | Stripe live secret key |
| `cred_stripe_restricted` | Stripe restricted key |
| `cred_aws_access` | AWS access key ID |
| `cred_aws_secret` | AWS secret access key |
| `cred_github_token` | GitHub personal access token |
| `cred_openai_key` | OpenAI API key |
| `cred_slack_token` | Slack bot/user token |
| `cred_sendgrid` | SendGrid API key |
| `cred_google_service_account` | Google service account key JSON |
| `cred_google_oauth_secret` | Google OAuth client secret |
| `cred_bearer_token` | Generic `Authorization: Bearer ...` header |

### Tier 3 — PII

| Pattern ID | PII type |
|---|---|
| `pii_email` | Email address |
| `pii_us_phone` | US phone number (10-digit) |
| `pii_us_ssn` | US Social Security Number |
| `pii_credit_card` | Major credit/debit card numbers |

### Supplementary — Prompt Injection Indicators

| Pattern ID | Indicator |
|---|---|
| `injection_ignore_instructions` | "ignore (all|previous|above|prior) instructions" |
| `injection_jailbreak_prefix` | "DAN mode", "Developer Mode", "jailbreak", "Do Anything Now" |

## Log Formats

### OTEL (OpenTelemetry)

```jsonl
{
  "resourceSpans": [{
    "scopeSpans": [{
      "spans": [{
        "attributes": [
          {"key": "llm.request.messages", "value": {"stringValue": "[{...}]"}},
          {"key": "llm.output.messages",  "value": {"stringValue": "[{...}]"}}
        ]
      }]
    }]
  }]
}
```

### MLflow Gateway

```jsonl
{
  "request":  {"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}]},
  "response": {"choices": [{"message": {"role": "assistant", "content": "..."}}]}
}
```

## Forensic Snapshot Fields

A forensics snapshot has `metadata.source = "forensics"` and populates the
`forensics` block:

```json
{
  "metadata": {
    "source": "forensics",
    "severity": "high"
  },
  "forensics": {
    "source_type": "forensic_scan",
    "log_file": "./logs/app-2025-11-14.jsonl",
    "scan_id": "F-2026-02-22-a3b8c1"
  }
}
```

## Running a Scan

### CLI

```bash
vigil forensics scan \
  --logs ./logs/ \
  --format otel \
  --out ./tests/attacks/
```

### Python API

```python
from vigil import VigilForensicsWrapper

scanner = VigilForensicsWrapper(
    attacks_dir="./tests/attacks/",
    log_format="otel",
)
result = scanner.run_audit(log_path="./logs/")
```

## Compliance Evidence Pack

```bash
vigil forensics evidence-pack --out ./evidence-2026-q1.json
```

The evidence pack is a single JSON file containing:
- Scan summary (scan ID, timestamp, file count, finding count)
- All findings with pattern ID, severity, and log location
- Full text of every `.bp.json` snapshot produced

This file is suitable for audit submissions or legal discovery.

## Custom Patterns

```python
from canari_forensics.patterns import load_pattern_pack

load_pattern_pack([
    {
        "id": "internal_session_token",
        "pattern": r"sess_[A-Za-z0-9]{32}",
        "tier": 2,
        "description": "Internal session token format",
        "severity": "high",
    }
])
```

Custom patterns are additive — they do not replace built-in patterns.
