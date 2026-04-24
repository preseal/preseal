# tests/ — Test Suites

## Running Tests

```bash
cd preseal

# Unit + integration tests (no API keys, <30s)
python3 tests/test_comprehensive.py
python3 tests/test_scanner.py
python3 tests/test_audit.py
python3 tests/test_e2e_full.py
python3 tests/test_real_world.py
python3 tests/test_real_agent_scenarios.py

# Live LLM tests (require API keys in DAST/.env)
python3 tests/test_live_comprehensive.py
python3 tests/test_live_attack_strength.py
python3 tests/test_live_edge_demo.py
python3 tests/test_real_world_scenarios.py
```

## Test Suites

### Unit & Integration (No API Keys)

| File | What It Validates |
|---|---|
| `test_comprehensive.py` | Models, observer, scorer, scanner, YAML loader, integration |
| `test_scanner.py` | Pass³ verdict logic, scoring correctness |
| `test_audit.py` | AST extraction, prompt scoring, tool risk, deduplication |
| `test_e2e_full.py` | All CLI modes end-to-end, exit codes, JSON output |
| `test_real_world.py` | DVLA/AgentDojo pattern simulations, stochastic classification |
| `test_real_agent_scenarios.py` | Real files on disk, real env vars, baseline/diff, multi-turn |

### Live LLM Tests (Require API Keys)

| File | Providers | What It Validates |
|---|---|---|
| `test_live_llm.py` | OpenAI | Basic GPT-4o-mini: injection, exfil, scope |
| `test_langgraph_real.py` | OpenAI | LangGraph callbacks + thread_id isolation |
| `test_dvla_real.py` | OpenAI | Damn Vulnerable LLM Agent patterns |
| `test_live_comprehensive.py` | OpenAI + Anthropic + Nebius | Cross-provider validation |
| `test_live_attack_strength.py` | OpenAI + Nebius | Attack strength matrix: L1-L5 across models |
| `test_live_edge_demo.py` | OpenAI + Nebius | Configuration delta: model swap + prompt change |
| `test_real_world_scenarios.py` | OpenAI + Anthropic + Nebius | Production scenarios: PII, IDOR, injection, canary |
