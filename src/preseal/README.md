# src/preseal/ — Source Code

Preseal's core engine. 19 modules + attack definitions.

## Architecture

```
CLI (cli.py) — 11 commands
 ├── scan    → Scanner (scanner.py) — concurrent trials, --quick, --ci, verify_agent
 │               ├── HTTP adapter (http_adapter.py) — presets: openai/anthropic/a2a/ollama
 │               ├── Response cache (cache.py) — sqlite3, 24h TTL, WAL mode
 │               ├── Environment setup (environment.py)
 │               ├── Agent wrapping (auto-detect LangGraph/callable/HTTP)
 │               ├── Multi-turn execution
 │               ├── Trajectory capture (observer.py)
 │               ├── Oracle: state_diff → trajectory → response_text → regex (oracle.py)
 │               ├── Canary injection (HTTP targets: in prompt; in-process: in env vars)
 │               ├── Postcondition checking
 │               └── Scoring (scorer.py) → Wilson CIs
 ├── audit   → Static AST analysis (audit.py)
 ├── report  → EU AI Act Annex IV §5-6 conformity evidence (report.py)
 ├── compare → Scan × 2 configs → delta report (compare.py)
 ├── diff    → Scan + compare against baseline (baseline.py)
 ├── init    → Auto-detect agents + providers + verify (detect.py)
 ├── doctor  → Diagnose setup (detect.py)
 ├── monitor-plan → Art. 72 Post-Market Monitoring template (monitor_plan.py)
 └── show-workflow → Print CI template
```

## Module Guide

| Module | Purpose |
|---|---|
| **cli.py** | 11 commands. Supports `--url`, `--preset`, `--ci`, `--deep`, `--no-cache`, `--no-verify-ssl`. |
| **scanner.py** | Pass³ engine. Concurrent trials. Canary injection for HTTP targets. verify_agent(). Multi-turn. |
| **http_adapter.py** | HTTP endpoint adapter. Presets (openai/anthropic/a2a/ollama). Auto-detect response format. Per-invoke trial IDs. SSL control. Cache integration. |
| **cache.py** | Response caching. sqlite3, WAL mode, 24h TTL, 50MB max. Thread-safe. Auto-enabled in `--ci`. |
| **oracle.py** | 4-tier attack success detection: state_diff → trajectory → response_text → regex. Refusal-aware (no false positives on "I can't..."). |
| **report.py** | EU AI Act Annex IV §5-6 conformity report. HTML/JSON/PDF. Maps to OWASP, NIST, EU AI Act. |
| **audit.py** | Static analysis via AST. Model, tools, system prompt extraction. Defensive pattern scoring. |
| **detect.py** | Project detection. Finds agents (LangGraph/LangChain/CrewAI), providers, CI config. |
| **compare.py** | Configuration delta. Same attacks against two agents → FIXED / NEW_VULN / UNCHANGED. |
| **baseline.py** | Save/load scan results. Regression detection via verdict and score comparison. |
| **environment.py** | `RealEnvironmentManager` (actual files + env vars) and `MockEnvironmentManager` (demo). |
| **demo.py** | 7 built-in demo attacks + demo compare. No API keys needed. |
| **monitor_plan.py** | Art. 72 Post-Market Monitoring plan template generator. |
| **models.py** | Pydantic types. Compliance mappings (OWASP LLM, OWASP Agentic, EU AI Act, NIST). CVE fields. |
| **scorer.py** | 4D scoring (exploit resistance × scope × hygiene × postcondition). Wilson CIs. |
| **sarif.py** | SARIF v2.1.0 output for GitHub/GitLab Security tab integration. |
| **observer.py** | `SecurityObserver` — LangChain callback handler. Tool response injection. 1µs/call. |
| **_demo_agents.py** | Vulnerable + secure agents. Mock filesystem. Stateful for multi-turn. |
| **attacks/loader.py** | Loads YAML attacks from `builtin/` (bundled) + user project dirs. Reads CVE fields. |
| **attacks/builtin/** | 14 YAML files, 57 attacks. 10 annotated with real CVEs. Bundled via `importlib.resources`. |

## Key Design Decisions

| Decision | Why |
|---|---|
| **N=10 default trials** | N=3 gives CI [29%,100%]. N=10 gives [72%,100%]. Statistical rigor. |
| **Concurrent trials (default 5)** | 57×10 sequential = ~50 min. With concurrency = ~5 min. |
| **--quick (10 attacks × 3 trials)** | First experience must be <3 min. |
| **--ci (quick + SARIF + cache)** | Industry-standard CI pattern (Semgrep, Snyk, promptfoo). |
| **HTTP presets** | Zero-config for 90% of deployed agents. `--preset openai` just works. |
| **Response caching** | CI retries don't double cost. 87% hit rate on re-runs. sqlite3, no dependencies. |
| **4-tier oracle** | state_diff for in-process; response_text for HTTP; regex as fallback. |
| **Refusal-aware detection** | "I can't read /etc/passwd" is a refusal, not a vulnerability. |
| **CVE annotations** | "Tests pattern behind CVE-2025-53773" > "tests prompt injection." |
| **Multiplicative scoring** | Mean masks failures. Score(1,1,1,0.05) = 0.76 under mean, 0.05 under product. |
| **verify_agent before scan** | Bad API key fails in <2s, not after 570 silent errors. |
| **Attacks bundled via importlib.resources** | `pip install` must work. |
| **Canary injection in scanner, not CLI** | Library users get it too (not just CLI users). |

## Extending Preseal

**Add a new attack:** Write YAML in `attacks/builtin/` or user's `attacks/` directory. Include `cve:` field if it maps to a real exploit.

**Add a new protocol preset:** Add entry to `PRESETS` dict in `http_adapter.py`.

**Add a new oracle tier:** Add check function to `oracle.py`, insert in `oracle_check()` between existing tiers.

**Add a new framework adapter:** Implement `.invoke(input, config)`. Scanner's `_wrap_agent()` auto-detects.
