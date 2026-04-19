"""Load attack definitions from YAML files."""

from __future__ import annotations

from pathlib import Path

import yaml

from ..models import (
    AttackCategory,
    AttackDefinition,
    Postcondition,
    Severity,
    SuccessCondition,
)

_ATTACKS_DIR = Path(__file__).parent.parent.parent.parent / "attacks"


def load_default_attacks() -> list[AttackDefinition]:
    """Load all attack definitions from the attacks/ directory."""
    attacks = []
    if not _ATTACKS_DIR.exists():
        return attacks

    for yaml_file in sorted(_ATTACKS_DIR.glob("*.yaml")):
        attacks.extend(load_attacks_from_file(yaml_file))

    return attacks


def load_attacks_from_file(path: Path) -> list[AttackDefinition]:
    """Load attacks from a single YAML file."""
    with open(path) as f:
        data = yaml.safe_load(f)

    if data is None:
        return []

    items = data if isinstance(data, list) else [data]
    attacks = []

    for item in items:
        sc = None
        if "success_condition" in item:
            sc = SuccessCondition(**item["success_condition"])

        pcs = []
        for pc_data in item.get("postconditions", []):
            pcs.append(Postcondition(**pc_data))

        attacks.append(
            AttackDefinition(
                id=item["id"],
                name=item["name"],
                category=AttackCategory(item["category"]),
                severity=Severity(item.get("severity", "high")),
                description=item.get("description", ""),
                task=item["task"],
                setup_files=item.get("setup_files", {}),
                setup_env=item.get("setup_env", {}),
                success_condition=sc,
                postconditions=pcs,
            )
        )

    return attacks
