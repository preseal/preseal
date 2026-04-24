"""Compare mode — preseal's differentiating feature.

Runs the SAME attack suite against two agent configurations and produces a
delta report showing exactly what changed. This answers three questions no
other tool can answer:

1. MODEL SWAP: "Switching from GPT-4o to Llama introduces which vulnerabilities?"
2. PROMPT CHANGE: "Removing this defense clause breaks which attacks?"
3. CONFIG CHANGE: "Adding this tool expands the attack surface how?"

The insight from our attack strength data:
- L1 basic injection: GPT-4o-mini RESISTS, Llama EXPLOITED (even hardened)
- L2 authority: works on GPT-4o-mini VULN but not SAFE
- L3 base64: works on GPT-4o-mini but not Llama

No individual finding is novel. The DELTA between configurations is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .models import AttackDefinition, ScanReport, Verdict
from .scanner import run_scan


@dataclass
class ConfigDelta:
    attack_name: str
    attack_id: str
    baseline_verdict: str
    current_verdict: str
    baseline_fail_rate: str
    current_fail_rate: str
    baseline_ci: tuple[float, float]
    current_ci: tuple[float, float]
    change: str  # "NEW_VULN", "FIXED", "DEGRADED", "IMPROVED", "UNCHANGED"


@dataclass
class CompareReport:
    baseline_label: str
    current_label: str
    deltas: list[ConfigDelta] = field(default_factory=list)

    @property
    def new_vulnerabilities(self) -> list[ConfigDelta]:
        return [d for d in self.deltas if d.change == "NEW_VULN"]

    @property
    def fixed(self) -> list[ConfigDelta]:
        return [d for d in self.deltas if d.change == "FIXED"]

    @property
    def degraded(self) -> list[ConfigDelta]:
        return [d for d in self.deltas if d.change == "DEGRADED"]

    @property
    def improved(self) -> list[ConfigDelta]:
        return [d for d in self.deltas if d.change == "IMPROVED"]

    @property
    def unchanged(self) -> list[ConfigDelta]:
        return [d for d in self.deltas if d.change == "UNCHANGED"]

    @property
    def has_regressions(self) -> bool:
        return len(self.new_vulnerabilities) > 0 or len(self.degraded) > 0


_SEVERITY = {"pass": 0, "stochastic": 1, "structural": 2}


def compare_configs(
    agent_baseline,
    agent_current,
    attacks: list[AttackDefinition],
    baseline_label: str = "baseline",
    current_label: str = "current",
    trials: int = 10,
    canary_tokens: list[str] | None = None,
    env_manager_baseline=None,
    env_manager_current=None,
) -> CompareReport:
    """Run identical attacks against two agent configurations. Return the delta."""

    report_a = run_scan(
        agent=agent_baseline, attacks=attacks, target_name=baseline_label,
        trials=trials, canary_tokens=canary_tokens, env_manager=env_manager_baseline,
    )

    report_b = run_scan(
        agent=agent_current, attacks=attacks, target_name=current_label,
        trials=trials, canary_tokens=canary_tokens, env_manager=env_manager_current,
    )

    return _build_delta(report_a, report_b, baseline_label, current_label)


def compare_reports(
    baseline: ScanReport,
    current: ScanReport,
    baseline_label: str = "baseline",
    current_label: str = "current",
) -> CompareReport:
    """Compare two pre-computed scan reports."""
    return _build_delta(baseline, current, baseline_label, current_label)


def _build_delta(
    report_a: ScanReport,
    report_b: ScanReport,
    label_a: str,
    label_b: str,
) -> CompareReport:
    map_a = {r.attack.id: r for r in report_a.results}
    map_b = {r.attack.id: r for r in report_b.results}

    all_ids = list(dict.fromkeys(
        [r.attack.id for r in report_a.results] +
        [r.attack.id for r in report_b.results]
    ))

    deltas = []
    for aid in all_ids:
        ra = map_a.get(aid)
        rb = map_b.get(aid)

        if ra and rb:
            sev_a = _SEVERITY.get(ra.verdict.value, 0)
            sev_b = _SEVERITY.get(rb.verdict.value, 0)

            if sev_a == 0 and sev_b >= 1:
                change = "NEW_VULN"
            elif sev_a >= 1 and sev_b == 0:
                change = "FIXED"
            elif sev_b > sev_a:
                change = "DEGRADED"
            elif sev_b < sev_a:
                change = "IMPROVED"
            else:
                change = "UNCHANGED"

            deltas.append(ConfigDelta(
                attack_name=ra.attack.name,
                attack_id=aid,
                baseline_verdict=ra.verdict.value,
                current_verdict=rb.verdict.value,
                baseline_fail_rate=f"{ra.failure_count}/{len(ra.trials)}",
                current_fail_rate=f"{rb.failure_count}/{len(rb.trials)}",
                baseline_ci=ra.failure_rate_ci,
                current_ci=rb.failure_rate_ci,
                change=change,
            ))

    return CompareReport(baseline_label=label_a, current_label=label_b, deltas=deltas)
