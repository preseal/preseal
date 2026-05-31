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

## CI/CD Integration

**Option 1: GitHub Action** (recommended)

See `.github/actions/preseal-scan/action.yml` for the ready-to-use composite action,
or `.github/workflows/example-preseal.yml` for a complete workflow example with
PR gate + nightly deep scan.

**Option 2: Generate a workflow template:**

```bash
preseal show-workflow > .github/workflows/agent-security.yml
```

**Option 3: Minimal inline:**

```yaml
- run: pip install preseal
- run: preseal scan --url ${{ vars.AGENT_URL }} --preset openai --ci
         -H "Authorization: Bearer ${{ secrets.AGENT_KEY }}"
```

`--ci` enables quick scan + SARIF output + response caching. Exit code 1 blocks merge on structural vulnerabilities.
