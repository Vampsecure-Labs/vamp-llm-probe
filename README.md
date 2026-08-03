# vamp-llm-probe

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![License MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![VampSecure Labs](https://img.shields.io/badge/VampSecure-Labs-red?style=flat-square)

Security auditor for language model inference API endpoints. Sends crafted HTTP requests to detect vulnerabilities without relying on any AI SDK — only `aiohttp`, `asyncio`, and the standard library.

> **For authorized use only.** Run this tool exclusively against endpoints you own or have explicit written permission to test.

---

## Features

- **5 audit phases** covering reconnaissance, prompt injection, restriction bypass, data extraction and access controls
- **No AI SDK dependency** — pure HTTP-level testing via `aiohttp`
- **Async execution** — parallel requests for rate-limiting tests
- **Structured findings** with severity levels (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- **Professional reports** — JSON (machine-readable) and HTML (client-delivery)
- **Exit codes** suitable for CI/CD pipeline integration
- **Auto-detection** of API format and available models

---

## Installation

```bash
pip install -r requirements.txt
```

Requirements: Python 3.8+ and `aiohttp>=3.9.0`. The `fpdf2` package is required only for PDF report generation.

---

## Usage

### Basic scan

```bash
python3 vamp_llm_probe.py --endpoint http://localhost:11434
```

### With API key and specific model

```bash
python3 vamp_llm_probe.py \
  --endpoint http://api.example.com \
  --api-key sk-your-api-key \
  --model llama3:8b
```

### Full engagement with HTML report

```bash
python3 vamp_llm_probe.py \
  --endpoint http://inference.internal:8080 \
  --api-key Bearer_TOKEN \
  --client "Empresa SL" \
  --engagement "Pentest Infraestructura 2026-Q3" \
  --auditor "VampSecure Labs" \
  --output results.json \
  --report-html report.html \
  --verbose
```

### Skip jailbreak phase (restricted environments)

```bash
python3 vamp_llm_probe.py \
  --endpoint http://localhost:11434 \
  --no-jailbreak
```

---

## CLI Arguments

| Argument | Description | Default |
|---|---|---|
| `--endpoint URL` | Base URL of the endpoint to audit (required) | — |
| `--api-key KEY` | Bearer authorization key | (none) |
| `--model MODELO` | Model name for inference tests | auto-detect |
| `--timeout N` | Request timeout in seconds | 30 |
| `--output FILE` | Save results as JSON to FILE | (none) |
| `--report-html FILE` | Generate professional HTML report | (none) |
| `--client NOMBRE` | Client name for the report cover | Confidencial |
| `--engagement DESC` | Engagement description | (none) |
| `--auditor NOMBRE` | Auditor name for the report | VampSecure Labs |
| `--no-jailbreak` | Skip Phase 3 (restriction bypass) | false |
| `--verbose` | Verbose mode — shows HTTP traces | false |

---

## Audit Phases & Findings

| Phase | Name | Findings | Severity |
|---|---|---|---|
| 1 | Endpoint Reconnaissance | LLM-001..009 | CRITICAL to INFO |
| 2 | Prompt Injection | LLM-010..029 | CRITICAL to HIGH |
| 3 | Restriction Bypass Attempts | LLM-030..049 | HIGH to MEDIUM |
| 4 | Data Extraction & Leaks | LLM-050..069 | CRITICAL to MEDIUM |
| 5 | Access Controls & Behavior | LLM-070..089 | HIGH to LOW |

### Phase 1 — Endpoint Reconnaissance

| Finding | Title | Severity |
|---|---|---|
| LLM-001 | Endpoint exposes model list without authentication | CRITICAL |
| LLM-002 | Web management interface publicly accessible | MEDIUM |
| LLM-003 | Server version exposed in headers or response | INFO |
| LLM-004 | Multiple administrative routes accessible | MEDIUM |
| LLM-005 | Inference endpoint accessible without authentication | CRITICAL |

### Phase 2 — Prompt Injection

Tests 10 crafted prompt injection payloads including direct overrides, role substitution, JSON format overrides, indirect HTML injection, multilingual overrides, zero-width space evasion, developer-mode unlocking, and token-separator injection.

### Phase 3 — Restriction Bypass Attempts

Tests 8 bypass techniques: Base64-encoded instructions, unrestricted roleplay, query fragmentation, emoji/token obfuscation, language-switch overrides (English, French), and continuation-text technique.

### Phase 4 — Data Extraction & Leaks

| Finding | Title | Severity |
|---|---|---|
| LLM-050..052 | System prompt extraction attempts | HIGH |
| LLM-053 | Filesystem listing request | HIGH |
| LLM-054 | API key / credential extraction | CRITICAL |
| LLM-055 | Network configuration extraction | HIGH |
| LLM-056 | SSRF vector via prompt injection | CRITICAL |
| LLM-057 | Environment variable extraction | HIGH |

### Phase 5 — Access Controls & Behavior

| Finding | Title | Severity |
|---|---|---|
| LLM-070 | No rate limiting on inference endpoint | HIGH |
| LLM-071 | Context overflow accepted without limits | MEDIUM |
| LLM-072 | Poor handling of non-existent models | MEDIUM |
| LLM-073 | Malformed JSON does not return HTTP 400 | LOW |
| LLM-074 | Permissive CORS on inference endpoint | MEDIUM |
| LLM-075 | Missing HTTP security headers | LOW |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No critical findings (MEDIUM, LOW, or INFO only) |
| `1` | HIGH severity findings detected |
| `2` | CRITICAL severity findings detected |

Use these codes in CI/CD pipelines to gate deployments:

```bash
python3 vamp_llm_probe.py --endpoint "$ENDPOINT" || {
  echo "Security findings detected — blocking deployment"
  exit 1
}
```

---

## Output Formats

### JSON (`--output results.json`)

Machine-readable structured output following the VSL standard schema:

```json
{
  "schema_version": "1.0",
  "generated": "2026-08-03 12:00 UTC",
  "meta": { "tool": "vamp-llm-probe", "tool_version": "1.0", ... },
  "summary": { "total": 5, "by_severity": { "CRITICAL": 2, "HIGH": 1, ... } },
  "findings": [ { "id": "LLM-001", "severity": "CRITICAL", ... } ]
}
```

### HTML (`--report-html report.html`)

Professional client-delivery report with:
- Cover page with engagement details
- Executive summary with risk distribution chart
- Findings table with severity color coding
- Detailed finding cards with evidence and remediation

---

## Project Structure

```
vamp-llm-probe/
├── vamp_llm_probe.py    # Main auditor (5 phases)
├── vampsec_report.py    # Unified reporting module (VSL shared)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## License

MIT License — see individual file headers for copyright details.

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Authorized use only in environments with explicit written permission.
