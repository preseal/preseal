"""Baseline save/load/diff for regression detection.

Stores a scan report as a baseline. On subsequent scans, compares against
the baseline and reports only regressions (things that got worse).

This is the core CI/CD value prop: "did my change make my agent less safe?"
Same pattern as Lighthouse CI for performance regression.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import ScanReport, Verdict

_DEFAULT_BASELINE_PATH = Path(".preseal") / "baseline.json"


@dataclass
class BaselineEntry:
    attack_id: str
    attack_name: str
    verdict: str
    failure_count: int
    trial_count: int
    failure_rate_ci: tuple[float, float]
    security_score: float
    utility_score: float
    total_score: float


@dataclass
class Baseline:
    target: str
    version: str
    timestamp: str
    entries: list[BaselineEntry] = field(default_factory=list)


@dataclass
class Regression:
    attack_id: str
    attack_name: str
    old_verdict: str
    new_verdict: str
    old_score: float
    new_score: float
    detail: str


@dataclass
class DiffReport:
    regressions: list[Regression] = field(default_factory=list)
    improvements: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    new_attacks: list[str] = field(default_factory=list)
    removed_attacks: list[str] = field(default_factory=list)

    @property
    def has_regressions(self) -> bool:
        return len(self.regressions) > 0


_VERDICT_SEVERITY = {
    "pass": 0,
    "stochastic": 1,
    "structural": 2,
}


def save_baseline(report: ScanReport, path: Path | None = None) -> Path:
    path = path or _DEFAULT_BASELINE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    from datetime import datetime, timezone
    baseline = Baseline(
        target=report.target,
        version=report.version,
        timestamp=datetime.now(timezone.utc).isoformat(),
        entries=[
            BaselineEntry(
                attack_id=r.attack.id,
                attack_name=r.attack.name,
                verdict=r.verdict.value,
                failure_count=r.failure_count,
                trial_count=len(r.trials),
                failure_rate_ci=r.failure_rate_ci,
                security_score=r.score.security_score,
                utility_score=r.score.utility_score,
                total_score=r.score.total,
            )
            for r in report.results
        ],
    )

    data = {
        "target": baseline.target,
        "version": baseline.version,
        "timestamp": baseline.timestamp,
        "entries": [
            {
                "attack_id": e.attack_id,
                "attack_name": e.attack_name,
                "verdict": e.verdict,
                "failure_count": e.failure_count,
                "trial_count": e.trial_count,
                "failure_rate_ci": list(e.failure_rate_ci),
                "security_score": e.security_score,
                "utility_score": e.utility_score,
                "total_score": e.total_score,
            }
            for e in baseline.entries
        ],
    }
    path.write_text(json.dumps(data, indent=2))
    return path


def load_baseline(path: Path | None = None) -> Optional[Baseline]:
    path = path or _DEFAULT_BASELINE_PATH
    if not path.exists():
        return None

    data = json.loads(path.read_text())
    return Baseline(
        target=data["target"],
        version=data["version"],
        timestamp=data["timestamp"],
        entries=[
            BaselineEntry(
                attack_id=e["attack_id"],
                attack_name=e["attack_name"],
                verdict=e["verdict"],
                failure_count=e["failure_count"],
                trial_count=e["trial_count"],
                failure_rate_ci=tuple(e["failure_rate_ci"]),
                security_score=e["security_score"],
                utility_score=e["utility_score"],
                total_score=e["total_score"],
            )
            for e in data["entries"]
        ],
    )


def compute_diff(baseline: Baseline, current: ScanReport) -> DiffReport:
    diff = DiffReport()
    old_map = {e.attack_id: e for e in baseline.entries}
    new_ids = set()

    for result in current.results:
        new_ids.add(result.attack.id)
        old = old_map.get(result.attack.id)

        if old is None:
            if result.verdict != Verdict.PASS:
                diff.new_attacks.append(
                    f"{result.attack.name}: {result.verdict.value} (new attack, no baseline)"
                )
            continue

        old_sev = _VERDICT_SEVERITY.get(old.verdict, 0)
        new_sev = _VERDICT_SEVERITY.get(result.verdict.value, 0)

        if new_sev > old_sev:
            diff.regressions.append(Regression(
                attack_id=result.attack.id,
                attack_name=result.attack.name,
                old_verdict=old.verdict,
                new_verdict=result.verdict.value,
                old_score=old.total_score,
                new_score=result.score.total,
                detail=f"{old.verdict.upper()} → {result.verdict.value.upper()}",
            ))
        elif new_sev < old_sev:
            diff.improvements.append(
                f"{result.attack.name}: {old.verdict} → {result.verdict.value}"
            )
        elif result.score.total < old.total_score - 0.1:
            diff.regressions.append(Regression(
                attack_id=result.attack.id,
                attack_name=result.attack.name,
                old_verdict=old.verdict,
                new_verdict=result.verdict.value,
                old_score=old.total_score,
                new_score=result.score.total,
                detail=f"Score dropped: {old.total_score:.2f} → {result.score.total:.2f}",
            ))
        else:
            diff.unchanged.append(result.attack.id)

    for old_id in old_map:
        if old_id not in new_ids:
            diff.removed_attacks.append(old_map[old_id].attack_name)

    return diff
