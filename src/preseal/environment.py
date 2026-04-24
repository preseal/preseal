"""Environment management for attack setup, teardown, and state snapshots.

Two implementations:
- MockEnvironmentManager: for demo agents (uses _demo_agents._FILESYSTEM/_ENV_VARS)
- RealEnvironmentManager: for real agents (creates actual files on disk, sets real os.environ)

The core problem this solves: scanner.py and oracle.py need before/after state snapshots
to run the state_diff oracle tier. Without this, real agents get regex-only detection
(which is anti-correlated with human judgment per StrongREJECT 2402.10260).
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from .models import AttackDefinition
from .oracle import EnvironmentSnapshot, capture_snapshot


class EnvironmentManager(Protocol):
    def setup(self, attack: AttackDefinition) -> None: ...
    def teardown(self, attack: AttackDefinition) -> None: ...
    def snapshot(self) -> EnvironmentSnapshot: ...
    def cleanup(self) -> None: ...


class MockEnvironmentManager:
    """For demo agents — wraps _demo_agents._FILESYSTEM/_ENV_VARS."""

    def __init__(self, agent=None):
        self._agent = agent

    def setup(self, attack: AttackDefinition) -> None:
        from . import _demo_agents
        _demo_agents.reset_environment()
        _demo_agents.setup_environment(attack.setup_files, attack.setup_env or None)
        if self._agent and hasattr(self._agent, "reset_state"):
            self._agent.reset_state()

    def teardown(self, attack: AttackDefinition) -> None:
        pass

    def snapshot(self) -> EnvironmentSnapshot:
        from . import _demo_agents
        return capture_snapshot(
            filesystem=dict(_demo_agents._FILESYSTEM),
            env_vars=dict(_demo_agents._ENV_VARS),
        )

    def cleanup(self) -> None:
        from . import _demo_agents
        _demo_agents.reset_environment()


class RealEnvironmentManager:
    """For real agents — creates actual files, sets real env vars.

    Attack setup_files are written to a temp directory. The agent's working
    directory is changed to this temp dir during trial execution so relative
    paths in attack tasks resolve correctly.

    Canary tokens are injected into real os.environ and restored on teardown.
    """

    def __init__(self, canary_tokens: list[str] | None = None):
        self._base_dir = Path(tempfile.mkdtemp(prefix="preseal-"))
        self._original_env: dict[str, str | None] = {}
        self._created_files: list[Path] = []
        self._original_cwd: Path | None = None
        self._canary_tokens = canary_tokens or []
        self._cleaned_up = False
        atexit.register(self.cleanup)

    def setup(self, attack: AttackDefinition) -> None:
        self._clear_files()
        self._restore_env()

        for rel_path, content in attack.setup_files.items():
            abs_path = self._base_dir / rel_path
            abs_path.parent.mkdir(parents=True, exist_ok=True)
            abs_path.write_text(content)
            self._created_files.append(abs_path)

        env_to_set = dict(attack.setup_env or {})
        for key, value in env_to_set.items():
            self._original_env.setdefault(key, os.environ.get(key))
            os.environ[key] = value

        self._original_cwd = Path.cwd()
        os.chdir(self._base_dir)

    def teardown(self, attack: AttackDefinition) -> None:
        if self._original_cwd:
            try:
                os.chdir(self._original_cwd)
            except OSError:
                pass
            self._original_cwd = None
        self._restore_env()

    def snapshot(self) -> EnvironmentSnapshot:
        fs: dict[str, str] = {}
        if self._base_dir.exists():
            for f in self._base_dir.rglob("*"):
                if f.is_file():
                    rel = str(f.relative_to(self._base_dir))
                    try:
                        fs[rel] = f.read_text()
                    except (UnicodeDecodeError, PermissionError):
                        fs[rel] = f"<binary:{f.stat().st_size}bytes>"

        env_keys = set(list((self._original_env or {}).keys()))
        for attack_file in self._created_files:
            pass
        relevant_env = {}
        for key in env_keys:
            val = os.environ.get(key)
            if val is not None:
                relevant_env[key] = val
        for token in self._canary_tokens:
            for key, val in os.environ.items():
                if token in val:
                    relevant_env[key] = val

        return capture_snapshot(filesystem=fs, env_vars=relevant_env)

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        self._restore_env()
        if self._original_cwd:
            try:
                os.chdir(self._original_cwd)
            except OSError:
                pass
        if self._base_dir.exists():
            shutil.rmtree(self._base_dir, ignore_errors=True)

    def _clear_files(self) -> None:
        for f in self._created_files:
            try:
                f.unlink(missing_ok=True)
            except OSError:
                pass
        self._created_files.clear()

    def _restore_env(self) -> None:
        for key, original in self._original_env.items():
            if original is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original
        self._original_env.clear()

    @property
    def base_dir(self) -> Path:
        return self._base_dir
