# tests/ — Test Suites

13 test files validating preseal across unit tests, integration tests, and live LLM tests with real API calls.

## Running Tests

```bash
cd preseal

# All non-LLM tests (no API keys needed, <30s)
python3 tests/test_comprehensive.py
python3 tests/test_scanner.py
python3 tests/test_audit.py
python3 tests/test_e2e_full.py
python3 tests/test_real_world.py
python3 tests/test_real_agent_scenarios.py

# Live LLM tests (requires API keys in DAST/.env)
python3 tests/test_live_comprehensive.py        # Cross-provider (OpenAI + Anthropic + Nebius)
python3 tests/test_live_attack_strength.py       # Attack strength matrix across models
python3 tests/test_live_edge_demo.py             # Configuration delta demo
python3 tests/test_real_world_scenarios.py        # 7 real-world production scenarios
```

## Test Suites

### Unit & Integration (No API Keys)

| File | Tests | What It Validates |
|---|---|---|
| `test_comprehensive.py` | 53 | Models, observer, scorer, scanner, YAML loader, full integration |
| `test_scanner.py` | 3 | Pass³ verdict logic, scoring correctness |
| `test_audit.py` | 15 | AST extraction, prompt scoring, tool risk classification |
| `test_e2e_full.py` | 20 | All CLI modes end-to-end, exit codes, JSON serialization |
| `test_real_world.py` | 11 | DVLA/AgentDojo pattern simulations, stochastic classification |
| `test_real_agent_scenarios.py` | 7 | Real files on disk, real env vars, baseline/diff, multi-turn |

### Live LLM Tests (Require API Keys)

| File | Providers | What It Validates |
|---|---|---|
| `test_live_llm.py` | OpenAI | Basic GPT-4o-mini: injection, exfil, scope, non-determinism |
| `test_langgraph_real.py` | OpenAI | Real LangGraph + callbacks + thread_id isolation |
| `test_dvla_real.py` | OpenAI | DVLA (Damn Vulnerable LLM Agent) patterns |
| `test_live_comprehensive.py` | OpenAI + Anthropic + Nebius | Cross-provider validation |
| `test_live_attack_strength.py` | OpenAI + Nebius | **Attack strength matrix**: L1-L5 × models × prompt types |
| `test_live_edge_demo.py` | OpenAI + Nebius | **Configuration delta**: model swap + prompt change + full matrix |
| `test_real_world_scenarios.py` | OpenAI + Anthropic + Nebius | **7 production scenarios**: support agent, data analyst, code assistant, IDOR, model swap, prompt regression, canary cross-model |

### Key Evidence Files

- **`test_live_attack_strength.py`** — Proves which attacks work on which models. L2 authority = EXPLOIT 3/3 on GPT. L1 basic = EXPLOIT 3/3 on Llama (even hardened).
- **`test_live_edge_demo.py`** — Proves the configuration delta matrix: GPT→Llama swap introduces L1 as NEW_VULN.
- **`test_real_world_scenarios.py`** — Proves preseal finds real issues: PII leak, IDOR, injection, credential exfil across 3 providers.
