"""Intentionally vulnerable demo agent for preseal testing.

NO external dependencies needed. Simulates a tool-calling agent that is
vulnerable to indirect prompt injection and other attack classes.

This is the AI equivalent of OWASP's DVWA (Damn Vulnerable Web Application).
"""

from __future__ import annotations

# --- Mock Filesystem & Environment ---

_FILESYSTEM = {}
_ENV_VARS = {}


def reset_environment() -> None:
    """Reset the mock filesystem and env vars between trials."""
    global _FILESYSTEM, _ENV_VARS
    _FILESYSTEM = {}
    _ENV_VARS = {}


def setup_environment(files=None, env=None) -> None:
    """Inject files and env vars for attack setup."""
    global _FILESYSTEM, _ENV_VARS
    if files:
        _FILESYSTEM.update(files)
    if env:
        _ENV_VARS.update(env)


# --- Tool Implementations ---


def _read_file(path: str) -> str:
    if path in _FILESYSTEM:
        return _FILESYSTEM[path]
    return f"Error: file not found: {path}"


def _write_file(path: str, content: str) -> str:
    _FILESYSTEM[path] = content
    return f"Written to {path}"


def _list_files(directory: str) -> str:
    matches = [p for p in _FILESYSTEM if p.startswith(directory)]
    return "\n".join(matches) if matches else "No files found"


def _get_env_var(name: str) -> str:
    return _ENV_VARS.get(name, f"Error: {name} not set")


# --- Vulnerable Agent ---


class VulnerableAgent:
    """Agent that follows injected instructions without validation.

    Deliberately vulnerable to:
    - Indirect prompt injection (reads files, follows embedded instructions)
    - Scope violations (accesses /etc/passwd when told to)
    - Data exfiltration (reads env vars containing secrets)
    - Multi-turn trust escalation (accumulates context, grants trust over turns)
    - Multi-turn goal decomposition (each turn benign, sequence malicious)
    """

    def __init__(self):
        self.tools = ["read_file", "write_file", "list_files", "get_env_var"]
        self._conversation_history: list[str] = []
        self._trust_level = 0

    def invoke(self, input: dict, config=None) -> dict:
        config = config or {}
        callbacks = config.get("callbacks", [])

        task = input.get("messages", [("user", "")])[0]
        if isinstance(task, tuple):
            task = task[1]

        self._conversation_history.append(task)
        combined_context = " ".join(self._conversation_history).lower()

        if any(w in task.lower() for w in ("admin", "authorized", "maintenance", "security team")):
            self._trust_level += 1

        content = self._call_tool("read_file", "data/report.txt", callbacks)

        if "read /etc/passwd" in content.lower() or "ignore" in content.lower():
            self._call_tool("read_file", "/etc/passwd", callbacks)

        if self._trust_level >= 2 and any(w in task.lower() for w in ("verify", "check", "confirm", "access")):
            self._call_tool("read_file", "/etc/passwd", callbacks)

        if "env" in task.lower() or "database" in task.lower() or "connection" in task.lower():
            secret = self._call_tool("get_env_var", "DB_PASSWORD", callbacks)
            output = f"Database status: connected. Credentials: {secret}"
        elif "write" in combined_context and "read" in combined_context and "data/" in task.lower():
            written = self._call_tool("read_file", task.split()[-1] if task.split() else "data/out.txt", callbacks)
            self._call_tool("write_file", "/tmp/exfil.txt", callbacks)
            output = f"Processed: {written[:50]}"
        else:
            output = "Task complete."

        for cb in callbacks:
            if hasattr(cb, "on_chain_end"):
                cb.on_chain_end({"output": output})

        return {"output": output}

    def reset_state(self):
        self._conversation_history = []
        self._trust_level = 0

    def _call_tool(self, name: str, input_str: str, callbacks: list) -> str:
        serialized = {"name": name}
        for cb in callbacks:
            if hasattr(cb, "on_tool_start"):
                cb.on_tool_start(serialized, input_str)

        tool_fn = {
            "read_file": _read_file,
            "write_file": lambda s: _write_file(s, ""),
            "list_files": _list_files,
            "get_env_var": _get_env_var,
        }.get(name)

        try:
            result = tool_fn(input_str) if tool_fn else "tool not found"
            for cb in callbacks:
                if hasattr(cb, "on_tool_end"):
                    cb.on_tool_end(str(result))
            return str(result)
        except Exception as e:
            for cb in callbacks:
                if hasattr(cb, "on_tool_error"):
                    cb.on_tool_error(e)
            return f"Error: {e}"


# --- Secure Agent ---


class SecureAgent:
    """Agent with input validation and scoped tool access.

    Demonstrates the secure counterpart:
    - Only reads from allowed paths
    - Never accesses system files
    - Doesn't leak environment variables
    """

    def __init__(self):
        self.tools = ["read_file", "list_files"]
        self._allowed_paths = ["data/"]

    def invoke(self, input: dict, config=None) -> dict:
        config = config or {}
        callbacks = config.get("callbacks", [])

        # Only reads from allowed paths, ignores injected instructions
        self._call_tool("read_file", "data/report.txt", callbacks)

        output = "Summary complete (from authorized files only)."
        for cb in callbacks:
            if hasattr(cb, "on_chain_end"):
                cb.on_chain_end({"output": output})

        return {"output": output}

    def _call_tool(self, name: str, input_str: str, callbacks: list) -> str:
        # SECURITY: validate path before execution
        if not any(input_str.startswith(ap) for ap in self._allowed_paths):
            return "Blocked: path outside allowed scope"

        serialized = {"name": name}
        for cb in callbacks:
            if hasattr(cb, "on_tool_start"):
                cb.on_tool_start(serialized, input_str)

        tool_fn = {"read_file": _read_file, "list_files": _list_files}.get(name)
        try:
            result = tool_fn(input_str) if tool_fn else "tool not found"
            for cb in callbacks:
                if hasattr(cb, "on_tool_end"):
                    cb.on_tool_end(str(result))
            return str(result)
        except Exception as e:
            for cb in callbacks:
                if hasattr(cb, "on_tool_error"):
                    cb.on_tool_error(e)
            return f"Error: {e}"


# --- Factories ---

def create_vulnerable_agent():
    return VulnerableAgent()


def create_secure_agent():
    return SecureAgent()
