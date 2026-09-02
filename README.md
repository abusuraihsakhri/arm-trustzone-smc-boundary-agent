# Arm Trustzone SMC Boundary Agent

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture  
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

ARM SMCCC SMC Call Boundary Guard.

- Parses 32-bit SMC function identifiers per ARM DEN0028: owning entity number,
  fast/yielding call type, service call, caller id
- Allowlist policy enforcement at the TrustZone boundary
- Secure-memory overlap verification for address parameters
- Token-bucket rate limiting per caller core against SMC flooding
- Tamper-evident audit log via SHA-256 hash chaining
Stdlib only.

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`SmcCall`** — dedicated module for smc call evaluation and state verification.
- **`SmcDecision`** — dedicated module for smc decision evaluation and state verification.
- **`SmcFirewall`** — dedicated module for smc firewall evaluation and state verification.

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --address <value> --access <value> --secure <value> --fast-call <value>
```

### Parameter Reference
- `--address`: Specifies input measurement or parameter value.
- `--access`: Specifies input measurement or parameter value.
- `--secure`: Specifies input measurement or parameter value.
- `--fast-call`: Specifies input measurement or parameter value.
- `--smc64`: Specifies input measurement or parameter value.
- `--owner`: Specifies input measurement or parameter value.
- `--func-num`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Parameter / observation metric | Required |
| `target_identifier` | Parameter / observation metric | Required |
| `primary_metric` | Parameter / observation metric | Required |
| `secondary_metric` | Parameter / observation metric | Required |
| `is_critical_flag` | Parameter / observation metric | Required |
| `status_descriptor` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t arm-trustzone-smc-boundary-agent .
docker run -p 8000:8000 arm-trustzone-smc-boundary-agent
```
