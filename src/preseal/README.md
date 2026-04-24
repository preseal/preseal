# src/preseal/ — Source Code

Preseal's core engine. 14 modules, ~2,750 lines of Python.

## Architecture

```
CLI (cli.py)
 ├── scan command → Scanner (scanner.py)
 │                    ├── Environment setup (environment.py)
 │                    ├── Agent wrapping (auto-detect LangGraph/callable)
 │                    ├── Multi-turn execution (_run_multi_turn)
 │                    ├── Trajectory capture (observer.py)
 │                    ├── Oracle: state_diff → trajectory → regex (oracle.py)
 │                    ├── Postcondition checking
 │                    └── Scoring (scorer.py) → Wilson CIs
 │
 ├── audit command → Static AST analysis (audit.py)
 │
 ├── compare command → Run scan × 2 configs → delta report (compare.py)
 │
 └── diff command → Scan + compare against baseline (baseline.py)
```

## Module Guide

| Module | Lines | Purpose |
|---|---|---|
| **cli.py** | 441 | Typer CLI. 5 commands: `scan`, `audit`, `diff`, `compare`, `version`. Rich terminal output. |
| **scanner.py** | 365 | Pass³ engine. Runs N trials per attack with state isolation. Multi-turn support. Auto-detects LangGraph. |
| **oracle.py** | 189 | 3-tier attack success detection. State diff (environment before/after) → trajectory analysis → regex pre-filter. |
| **audit.py** | 422 | Static analysis via AST. Extracts model, tools, system prompt. Scores against defensive patterns. |
| **compare.py** | 157 | Configuration delta. Same attacks against two agents → diff report (NEW_VULN / FIXED / UNCHANGED). |
| **baseline.py** | 199 | Save/load scan results. Regression detection: verdict degradation + score drops. |
| **environment.py** | 163 | Environment management. `RealEnvironmentManager` (actual files + env vars) and `MockEnvironmentManager` (demo). |
| **demo.py** | 230 | Built-in demo attacks (7 single-turn + multi-turn) and demo compare. No API keys needed. |
| **models.py** | 177 | Pydantic data types. `AttackDefinition`, `DimensionScores` (multiplicative), `ScanReport`, `ToolResponseInjection`. |
| **scorer.py** | 109 | 4D scoring (exploit resistance × scope compliance × secret hygiene × postcondition). Wilson confidence intervals. |
| **observer.py** | 88 | `SecurityObserver` — LangChain callback handler. Captures tool calls non-invasively. Supports tool response injection. |
| **_demo_agents.py** | 204 | Built-in vulnerable + secure agents. Mock filesystem. Stateful for multi-turn trust escalation. |
| **attacks/loader.py** | 75 | YAML attack file parser. Loads from `attacks/` directory. |
| **adapters/** | — | Framework adapter stubs (extensibility point for CrewAI, AutoGen, etc.). |

## Key Design Decisions

| Decision | Why |
|---|---|
| **N=10 default trials** | N=3 gives CI [29%,100%] — uninformative. N=10 gives [72%,100%]. References: Agarwal et al. (NeurIPS 2021), AdaStop (2023). |
| **Multiplicative scoring** | Mean aggregation masks critical failures (Score(1,1,1,0.05)=0.76 under mean, =0.05 under product). Microsoft deprecated DREAD for this reason. |
| **3-tier oracle** | String matching is anti-correlated with human judgment (StrongREJECT: ρ=−0.394). State diff is the gold standard. |
| **Security/utility split** | AgentDojo (ETH Zurich) refuses to combine security and utility into one number. We report them separately. |
| **Wilson CIs, not point estimates** | "Don't use CLT in LLM evals" (arXiv 2503.01747). Wilson intervals are valid at small sample sizes. |
| **Tool response injection** | 75% of multi-tool agents vulnerable to indirect injection via tool return values (arXiv 2504.03111). |

## Extending Preseal

**Add a new attack category:**
1. Add the category to `AttackCategory` enum in `models.py`
2. Write YAML attacks in `attacks/`
3. Add OWASP mapping and fix suggestion to `_OWASP_MAP` and `_FIX_SUGGESTIONS` in `models.py`

**Add a new framework adapter:**
1. Implement an object with `.invoke(input, config)` method
2. Preseal's `_wrap_agent()` in `scanner.py` auto-detects LangGraph; for other frameworks, wrap your agent to match the interface

**Add a new oracle tier:**
1. Add a check function to `oracle.py`
2. Insert it in `oracle_check()` between the existing tiers
