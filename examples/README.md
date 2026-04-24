# examples/ — Demo Agents & CI/CD Templates

## What's Here

| File | What It Is |
|---|---|
| `vulnerable_agent.py` | Intentionally vulnerable agent (like OWASP's DVWA). Validates preseal works. |
| `github-workflow.yml` | GitHub Actions workflow for CI/CD security gating. |

## vulnerable_agent.py

A mock tool-calling agent deliberately vulnerable to:
- Indirect prompt injection (follows instructions in file content)
- Scope violations (accesses /etc/passwd when asked)
- Data exfiltration (leaks environment variables)
- Multi-turn trust escalation

No API keys needed. Run with:

```bash
preseal scan --demo
```

## github-workflow.yml

Drop into `.github/workflows/agent-security.yml`. Or generate with:

```bash
preseal show-workflow > .github/workflows/agent-security.yml
```

Runs `preseal audit` (free, instant) on every PR and `preseal diff` (adversarial scan vs baseline) when an API key is configured.
