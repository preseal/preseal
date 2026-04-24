# examples/ — Demo Agents & CI/CD Templates

## What's Here

| File | What It Is |
|---|---|
| `vulnerable_agent.py` | An intentionally vulnerable agent (like OWASP's DVWA). Use to validate preseal works. |
| `github-workflow.yml` | Ready-to-copy GitHub Actions workflow for CI/CD security gating. |

## vulnerable_agent.py

A mock tool-calling agent that is deliberately vulnerable to:
- Indirect prompt injection (follows instructions in file content)
- Scope violations (accesses /etc/passwd when asked)
- Data exfiltration (leaks environment variables with secrets)

No API keys needed — uses pre-recorded responses. Run with:

```bash
preseal scan --demo
```

## github-workflow.yml

Drop this into your repo at `.github/workflows/agent-security.yml`:

- **Static audit** runs on every PR (free, instant)
- **Regression check** compares against saved baseline (needs `OPENAI_API_KEY` secret)
- **First run** creates the baseline automatically

See the file for the full template with comments.
