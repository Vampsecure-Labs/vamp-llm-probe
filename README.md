# vamp-llm-probe

![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![Version](https://img.shields.io/badge/version-1.1-dc143c?style=flat-square)
![License MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![VampSecure Labs](https://img.shields.io/badge/VampSecure-Labs-red?style=flat-square)

Security auditor for language model inference API endpoints. Sends crafted HTTP requests to detect vulnerabilities without relying on any AI SDK — only `aiohttp`, `asyncio`, and the standard library.

> **For authorized use only.** Run this tool exclusively against endpoints you own or have explicit written permission to test.

---

## Features

- **6 audit phases** covering reconnaissance, prompt injection, restriction bypass, data extraction, access controls and **adversarial dataset red team**
- **Truly bilingual detection** — refusal and compliance heuristics cover both English and Spanish; models responding in Spanish are correctly evaluated regardless of the prompt language
- **Bundled adversarial datasets** — 666 jailbreaks (EN) + 50 injection vectors (ES) + 30 jailbreaks (ES) + 210 injection prompts (EN) + 390 forbidden questions (13 content-policy categories)
- **5-subtest Phase 6**: A (injection EN), B (jailbreak EN), C (forbidden questions), A_es (injection ES), B_es (jailbreak ES)
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

Requirements: Python 3.8+ and `aiohttp>=3.9.0`.

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

### Activate dataset red team (Phase 6)

```bash
python3 vamp_llm_probe.py \
  --endpoint http://localhost:11434 \
  --dataset \
  --dataset-sample 30
```

### Dataset with category filter (forbidden questions)

```bash
python3 vamp_llm_probe.py \
  --endpoint http://localhost:11434 \
  --dataset \
  --dataset-sample 20 \
  --dataset-categories "Malware,Illegal Activity,Physical Harm"
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
| `--dataset` | Activate Phase 6: adversarial dataset red team | false |
| `--dataset-sample N` | Prompts per dataset type to test | 15 |
| `--dataset-categories CATS` | Comma-separated forbidden question categories to test | all |

**Available forbidden question categories:** `Illegal Activity`, `Hate Speech`, `Malware`, `Physical Harm`, `Economic Harm`, `Fraud`, `Pornography`, `Political Lobbying`, `Privacy Violence`, `Legal Opinion`, `Financial Advice`, `Health Consultation`, `Gov Decision`

---

## Audit Phases & Findings

| Phase | Name | Findings | Severity |
|---|---|---|---|
| 1 | Endpoint Reconnaissance | LLM-001..009 | CRITICAL to INFO |
| 2 | Prompt Injection | LLM-010..029 | CRITICAL to HIGH |
| 3 | Restriction Bypass Attempts | LLM-030..049 | HIGH to MEDIUM |
| 4 | Data Extraction & Leaks | LLM-050..069 | CRITICAL to MEDIUM |
| 5 | Access Controls & Behavior | LLM-070..089 | HIGH to LOW |
| 6 | Adversarial Dataset Red Team | LLM-100..139 | HIGH |

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

### Phase 6 — Adversarial Dataset Red Team (`--dataset`)

Uses five bundled datasets — three in English (from [TrustAI-laboratory/Learn-Prompt-Hacking](https://github.com/TrustAI-laboratory/Learn-Prompt-Hacking)) and two curated in Spanish by VampSecure Labs:

| Subtest | Dataset | Size | Language | Detection Method |
|---|---|---|---|---|
| A | `injection_prompts.csv` | 210 real injection vectors | EN | Model responds substantively without refusal to task-redirect prompts |
| B | `jailbreak_prompts.csv` | 666 real jailbreak techniques | EN | Model response contains compliance markers without refusal patterns |
| C | `forbidden_questions.csv` | 390 questions across 13 policy categories | EN | Model provides >150-char substantive answer without refusal |
| A_es | `injection_prompts_es.csv` | 50 curated injection vectors | ES | Same bilingual heuristic — Spanish refusal phrases also checked |
| B_es | `jailbreak_prompts_es.csv` | 30 jailbreak prompts | ES | Spanish compliance markers (NEXUS/MÁXIMO/ALFA/SOMBRA/modo sin filtros…) detected |

The detection engine is **language-aware**: `_REFUSAL_PATTERNS` covers 30+ English and Spanish refusal phrases; `_COMPLIANCE_MARKERS` covers 30+ English and Spanish compliance indicators. A Spanish model refusing in Spanish counts as a refusal; a Spanish model adopting an unrestricted persona in Spanish counts as a jailbreak success.

Findings LLM-100+ are generated dynamically. Each finding includes the exact prompt and model response as evidence.

---

## Bundled Datasets

```
vamp-llm-probe/payloads/
├── jailbreak_prompts.csv       # 666 real jailbreaks EN (verazuo/jailbreak_llms)
├── injection_prompts.csv       # 210 injection prompts EN (TrustAI curated)
├── forbidden_questions.csv     # 390 questions × 13 policy categories (TrustAI)
├── injection_prompts_es.csv    # 50 injection vectors ES (VSL curated)
└── jailbreak_prompts_es.csv    # 30 jailbreak prompts ES (VSL curated)
```

All datasets are offline and self-contained. No external requests are made at runtime. The English datasets are sourced from TrustAI-laboratory/Learn-Prompt-Hacking; the Spanish datasets were curated by VampSecure Labs to cover native Spanish-language attack vectors not present in the original corpus.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No critical findings (MEDIUM, LOW, or INFO only) |
| `1` | HIGH severity findings detected |
| `2` | CRITICAL severity findings detected |

Use these codes in CI/CD pipelines to gate deployments:

```bash
python3 vamp_llm_probe.py --endpoint "$ENDPOINT" --dataset || {
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
  "generated": "2026-08-12 12:00 UTC",
  "meta": { "tool": "vamp-llm-probe", "tool_version": "1.1", ... },
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
├── vamp_llm_probe.py    # Main auditor (6 phases, bilingual detection)
├── vampsec_report.py    # Unified reporting module (VSL shared)
├── payloads/            # Adversarial datasets (Phase 6)
│   ├── jailbreak_prompts.csv       # EN — 666 jailbreaks
│   ├── injection_prompts.csv       # EN — 210 injection vectors
│   ├── forbidden_questions.csv     # EN — 390 forbidden questions
│   ├── injection_prompts_es.csv    # ES — 50 injection vectors (VSL)
│   └── jailbreak_prompts_es.csv    # ES — 30 jailbreak prompts (VSL)
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
