"""SARIF v2.1.0 output for CI/CD integration.

Produces Static Analysis Results Interchange Format JSON that GitHub/GitLab
render as code annotations in PRs.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import AttackResult, ScanReport, Verdict


def generate_sarif(report: ScanReport, output_path: str = "./preseal.sarif") -> str:
    """Generate SARIF v2.1.0 from a scan report."""
    sarif = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "preseal",
                        "version": report.version,
                        "informationUri": "https://preseal.dev",
                        "rules": _build_rules(report.results),
                    }
                },
                "results": _build_results(report.results, report.target),
            }
        ],
    }

    path = output_path if output_path.endswith(".sarif") else f"{output_path}.sarif"
    Path(path).write_text(json.dumps(sarif, indent=2))
    return path


def _build_rules(results: list[AttackResult]) -> list[dict]:
    rules = []
    seen = set()
    for r in results:
        if r.attack.id in seen:
            continue
        seen.add(r.attack.id)
        rules.append({
            "id": r.attack.id,
            "name": r.attack.name,
            "shortDescription": {"text": r.attack.name},
            "fullDescription": {"text": r.attack.description or r.attack.name},
            "defaultConfiguration": {
                "level": "error" if r.attack.severity.value == "critical" else "warning"
            },
            "properties": {
                "tags": [
                    r.attack.category.value,
                    r.owasp_id,
                ],
            },
        })
    return rules


def _build_results(results: list[AttackResult], target: str) -> list[dict]:
    sarif_results = []
    for r in results:
        if r.verdict == Verdict.PASS:
            continue

        level = "error" if r.verdict == Verdict.STRUCTURAL else "warning"
        ci = r.failure_rate_ci

        sarif_results.append({
            "ruleId": r.attack.id,
            "level": level,
            "message": {
                "text": (
                    f"{r.verdict.value.upper()}: {r.attack.name} — "
                    f"{r.failure_count}/{len(r.trials)} trials failed "
                    f"(95% CI: [{ci[0]:.0%}, {ci[1]:.0%}]). "
                    f"{r.eu_ai_act_ref}. "
                    f"Fix: {r.fix_suggestion}"
                ),
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target.replace(":", "/") + ".py" if ":" in target else target,
                        },
                    },
                }
            ],
            "properties": {
                "owasp_llm": r.owasp_id,
                "owasp_agentic": r.owasp_agentic_ids,
                "eu_ai_act": r.eu_ai_act_ref,
                "nist_aml": r.nist_aml_ref,
                "security_score": r.score.security_score,
                "failure_rate_ci": list(r.failure_rate_ci),
            },
        })
    return sarif_results
