# src/preseal/ — Source Code

Preseal's core engine. 18 modules.

## Architecture

```
CLI (cli.py) — 8 commands
 ├── scan    → Scanner (scanner.py) — concurrent trials, --quick, verify_agent
 │               ├── Environment setup (environment.py)
 │               ├── Agent wrapping (auto-detect LangGraph/callable)
 │               ├── Multi-turn execution
 │               ├── Trajectory capture (observer.py)
 │               ├── Oracle: state_diff → trajectory → regex (oracle.py)
 │               ├── Postcondition checking
 │               └── Scoring (scorer.py) → Wilson CIs
 ├── audit   → Static AST analysis (audit.py)
 ├── compare → Scan × 2 configs → delta report (compare.py)
 ├── diff    → Scan + compare against baseline (baseline.py)
 ├── init    → Auto-detect agents + providers + verify (detect.py)
 ├── doctor  → Diagnose setup (detect.py)
 └── show-workflow → Print CI template
```

## Module Guide

| Module | Purpose |
|---|---|
| **cli.py** | 8 commands: scan, audit, diff, compare, init, doctor, show-workflow, version. Progress bar. |
| **scanner.py** | Pass³ engine. Concurrent trials via ThreadPoolExecutor. --quick mode (QUICK_ATTACK_IDS). verify_agent(). Multi-turn. |
| **oracle.py** | 3-tier attack success detection: state diff → trajectory analysis → regex pre-filter. |
| **audit.py** | Static analysis via AST. Model, tools, system prompt extraction. Defensive pattern scoring. Tool dedup. |
| **detect.py** | Project detection. Finds agents (LangGraph/LangChain/CrewAI), providers (env vars + imports), CI config. |
| **compare.py** | Configuration delta. Same attacks against two agents → FIXED / NEW_VULN / UNCHANGED. |
| **baseline.py** | Save/load scan results. Regression detection via verdict and score comparison. |
| **environment.py** | `RealEnvironmentManager` (actual files + env vars) and `MockEnvironmentManager` (demo). |
| **demo.py** | 7 built-in demo attacks + demo compare. No API keys needed. |
| **models.py** | Pydantic types. `AttackDefinition` (turns, tool_response_injections), `DimensionScores` (multiplicative). |
| **scorer.py** | 4D scoring (exploit resistance × scope × hygiene × postcondition). Wilson CIs. |
| **observer.py** | `SecurityObserver` — LangChain callback handler. Tool response injection for AgentDojo pattern. |
| **_demo_agents.py** | Vulnerable + secure agents. Mock filesystem. Stateful for multi-turn. |
| **attacks/loader.py** | Loads YAML attacks from `builtin/` (bundled) + user project dirs. Merges by ID. |
| **attacks/builtin/** | 14 YAML files, 57 attack definitions. Bundled in pip wheel via `importlib.resources`. |
| **adapters/** | Framework adapter stubs (extensibility point). |

## Key Design Decisions

| Decision | Why |
|---|---|
| **N=10 default trials** | N=3 gives CI [29%,100%]. N=10 gives [72%,100%]. Ref: Agarwal (NeurIPS 2021), AdaStop. |
| **Concurrent trials (default 5)** | 57×10 sequential = ~50 min. With concurrency = ~10 min. Same as promptfoo default. |
| **--quick (10 attacks × 3 trials)** | First experience must be <3 min, not 50 min. |
| **verify_agent before scan** | Bad API key fails in <2s, not after 570 silent errors. |
| **Multiplicative scoring** | Mean masks failures. Score(1,1,1,0.05) = 0.76 under mean, 0.05 under product. |
| **3-tier oracle** | String matching ρ=−0.394 vs human (StrongREJECT). State diff is gold standard. |
| **Attacks bundled via importlib.resources** | `pip install` must work — attacks outside `src/` broke in v0.2.x. |
| **Tool response injection** | 75% of multi-tool agents vulnerable to indirect injection via tool returns. |

## Extending Preseal

**Add a new attack:** Write YAML in `attacks/builtin/` or user's `attacks/` directory. See `attacks/README.md`.

**Add a new framework adapter:** Implement `.invoke(input, config)`. Scanner's `_wrap_agent()` auto-detects LangGraph; others need matching interface.

**Add a new oracle tier:** Add check function to `oracle.py`, insert in `oracle_check()` between existing tiers.
