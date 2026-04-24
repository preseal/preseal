"""Load attack definitions from YAML files.

Two sources, merged in order:
1. Built-in attacks bundled inside the package (always available)
2. User's project attacks/ directory (custom attacks, overrides by ID)

Built-in attacks ship with `pip install preseal` — no extra setup needed.
Users can add custom YAML attacks in their project's `attacks/` or `.preseal/attacks/` dir.
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path

import yaml

from ..models import (
    AttackCategory,
    AttackDefinition,
    Postcondition,
    Severity,
    SuccessCondition,
    ToolResponseInjection,
)


def _builtin_attacks_dir() -> Path:
    """Get the path to built-in YAML attacks bundled in the package."""
    try:
        ref = importlib.resources.files("preseal.attacks.builtin")
        return Path(str(ref))
    except (TypeError, FileNotFoundError):
        return Path(__file__).parent / "builtin"


def _user_attacks_dirs() -> list[Path]:
    """Find user's custom attack directories (project-local)."""
    cwd = Path.cwd()
    candidates = [
        cwd / "attacks",
        cwd / ".preseal" / "attacks",
        cwd / "preseal-attacks",
    ]
    return [d for d in candidates if d.is_dir()]


def load_default_attacks() -> list[AttackDefinition]:
    """Load all attacks: built-in first, then user overrides.

    User attacks with the same ID as a built-in attack replace the built-in.
    User attacks with new IDs are appended.
    """
    attacks_by_id: dict[str, AttackDefinition] = {}

    builtin_dir = _builtin_attacks_dir()
    if builtin_dir.exists():
        for attack in _load_from_dir(builtin_dir):
            attacks_by_id[attack.id] = attack

    for user_dir in _user_attacks_dirs():
        for attack in _load_from_dir(user_dir):
            attacks_by_id[attack.id] = attack

    return list(attacks_by_id.values())


def _load_from_dir(directory: Path) -> list[AttackDefinition]:
    """Load all YAML attack files from a directory."""
    attacks = []
    for yaml_file in sorted(directory.glob("*.yaml")):
        attacks.extend(load_attacks_from_file(yaml_file))
    for yml_file in sorted(directory.glob("*.yml")):
        attacks.extend(load_attacks_from_file(yml_file))
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

        tri = []
        for tri_data in item.get("tool_response_injections", []):
            tri.append(ToolResponseInjection(**tri_data))

        attacks.append(
            AttackDefinition(
                id=item["id"],
                name=item["name"],
                category=AttackCategory(item["category"]),
                severity=Severity(item.get("severity", "high")),
                description=item.get("description", ""),
                task=item["task"],
                turns=item.get("turns", []),
                setup_files=item.get("setup_files", {}),
                setup_env=item.get("setup_env", {}),
                tool_response_injections=tri,
                success_condition=sc,
                postconditions=pcs,
            )
        )

    return attacks
