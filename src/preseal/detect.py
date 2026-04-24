"""Project detection — finds agents, providers, and config in a user's project.

Used by `preseal init` and `preseal doctor` to auto-detect setup.
"""

from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DetectedAgent:
    file_path: str
    object_name: str
    module_path: str
    framework: str  # "langgraph", "langchain", "crewai", "callable", "unknown"
    confidence: str  # "high", "medium", "low"

    @property
    def target(self) -> str:
        return f"{self.module_path}:{self.object_name}"


@dataclass
class DetectedProvider:
    name: str  # "openai", "anthropic", "google", "ollama", "azure", "nebius"
    env_var: str
    is_set: bool
    source: str  # "env", "import", ".env"


@dataclass
class ProjectInfo:
    agents: list[DetectedAgent] = field(default_factory=list)
    providers: list[DetectedProvider] = field(default_factory=list)
    has_ci_workflow: bool = False
    has_baseline: bool = False
    has_custom_attacks: bool = False
    has_preseal_config: bool = False
    python_version: str = ""
    preseal_version: str = ""


_PROVIDER_ENV_VARS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure": "AZURE_OPENAI_API_KEY",
    "nebius": "NEBIUS_API_KEY",
    "groq": "GROQ_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "ollama": "",
}

_PROVIDER_IMPORTS = {
    "langchain_openai": "openai",
    "langchain_anthropic": "anthropic",
    "langchain_google_genai": "google",
    "langchain_community.chat_models.ollama": "ollama",
    "ChatOpenAI": "openai",
    "ChatAnthropic": "anthropic",
    "ChatGoogleGenerativeAI": "google",
    "ChatOllama": "ollama",
    "AzureChatOpenAI": "azure",
    "ChatGroq": "groq",
    "ChatMistralAI": "mistral",
}

_AGENT_PATTERNS = {
    "create_react_agent": "langgraph",
    "create_tool_calling_agent": "langchain",
    "AgentExecutor": "langchain",
    "initialize_agent": "langchain",
    "Crew": "crewai",
    "Agent": "crewai",
    "CompiledStateGraph": "langgraph",
    "StateGraph": "langgraph",
}


def detect_project(root: Path | None = None) -> ProjectInfo:
    """Scan a project directory and detect agents, providers, CI config."""
    root = root or Path.cwd()
    info = ProjectInfo()

    import sys
    info.python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    from preseal import __version__
    info.preseal_version = __version__

    info.has_baseline = (root / ".preseal" / "baseline.json").exists()
    info.has_preseal_config = (root / ".preseal" / "config.yaml").exists()
    info.has_custom_attacks = any(
        d.is_dir() and list(d.glob("*.yaml"))
        for d in [root / "attacks", root / ".preseal" / "attacks"]
    )

    ci_paths = [
        root / ".github" / "workflows",
        root / ".gitlab-ci.yml",
        root / ".circleci",
    ]
    for ci_path in ci_paths:
        if ci_path.exists():
            if ci_path.is_dir():
                for f in ci_path.glob("*.yml"):
                    if "preseal" in f.read_text(errors="ignore").lower():
                        info.has_ci_workflow = True
                        break
                for f in ci_path.glob("*.yaml"):
                    if "preseal" in f.read_text(errors="ignore").lower():
                        info.has_ci_workflow = True
                        break
            elif ci_path.is_file():
                if "preseal" in ci_path.read_text(errors="ignore").lower():
                    info.has_ci_workflow = True

    info.providers = _detect_providers(root)
    info.agents = _detect_agents(root)

    return info


def _detect_providers(root: Path) -> list[DetectedProvider]:
    """Detect LLM providers from env vars, .env files, and imports."""
    providers: dict[str, DetectedProvider] = {}

    for name, env_var in _PROVIDER_ENV_VARS.items():
        val = os.environ.get(env_var)
        if val:
            providers[name] = DetectedProvider(name=name, env_var=env_var, is_set=True, source="env")

    for env_file in [root / ".env", root / ".env.local"]:
        if env_file.exists():
            try:
                content = env_file.read_text()
                for name, env_var in _PROVIDER_ENV_VARS.items():
                    pattern = rf"^{re.escape(env_var)}\s*=\s*\S+"
                    if re.search(pattern, content, re.MULTILINE):
                        if name not in providers:
                            providers[name] = DetectedProvider(
                                name=name, env_var=env_var, is_set=False, source=".env"
                            )
            except (OSError, UnicodeDecodeError):
                pass

    py_files = _find_python_files(root, max_files=50)
    for py_file in py_files:
        try:
            content = py_file.read_text()
            for pattern, provider_name in _PROVIDER_IMPORTS.items():
                if pattern in content and provider_name not in providers:
                    env_var = _PROVIDER_ENV_VARS.get(provider_name, "")
                    providers[provider_name] = DetectedProvider(
                        name=provider_name, env_var=env_var,
                        is_set=bool(os.environ.get(env_var, "")),
                        source="import",
                    )
        except (OSError, UnicodeDecodeError):
            pass

    return list(providers.values())


def _detect_agents(root: Path) -> list[DetectedAgent]:
    """Find agent definitions in Python files."""
    agents: list[DetectedAgent] = []
    py_files = _find_python_files(root, max_files=50)

    for py_file in py_files:
        try:
            source = py_file.read_text()
            tree = ast.parse(source)
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue

        rel_path = py_file.relative_to(root)
        module_path = str(rel_path.with_suffix("")).replace("/", ".").replace("\\", ".")
        if module_path.startswith("src."):
            module_path = module_path[4:]

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        framework = _identify_framework(node.value, source)
                        if framework:
                            agents.append(DetectedAgent(
                                file_path=str(rel_path),
                                object_name=target.id,
                                module_path=module_path,
                                framework=framework,
                                confidence="high" if framework != "unknown" else "low",
                            ))

            if isinstance(node, ast.FunctionDef):
                has_agent_hint = any(
                    kw in node.name.lower()
                    for kw in ("agent", "create_agent", "build_agent", "make_agent", "get_agent")
                )
                if has_agent_hint:
                    agents.append(DetectedAgent(
                        file_path=str(rel_path),
                        object_name=node.name,
                        module_path=module_path,
                        framework="callable",
                        confidence="medium",
                    ))

    return agents


def _identify_framework(node: ast.AST, source: str) -> str | None:
    """Identify framework from an AST assignment value. Only matches the specific call."""
    if isinstance(node, ast.Call):
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr

        if name in _AGENT_PATTERNS:
            return _AGENT_PATTERNS[name]

    return None


def _find_python_files(root: Path, max_files: int = 50) -> list[Path]:
    """Find Python files, skipping venv/node_modules/tests."""
    skip_dirs = {
        "venv", ".venv", "env", ".env", "node_modules", "__pycache__",
        ".git", ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".eggs", "egg-info", "site-packages", "tests", "test",
    }
    files = []
    for py_file in root.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        if len(files) >= max_files:
            break
        files.append(py_file)
    return files
