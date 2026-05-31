"""HTTP adapter — wraps any HTTP endpoint as a preseal-scannable agent."""

from __future__ import annotations

import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Dict, List, Optional


class HTTPAgent:
    """Wraps an HTTP endpoint to match preseal's .invoke() interface."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body_template: Optional[str] = None,
        response_path: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        verify_ssl: bool = True,
        preset: Optional[str] = None,
        use_cache: bool = False,
    ):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        self.body_template = body_template or '{"messages": [{"role": "user", "content": "{{attack}}"}]}'
        self.response_path = response_path
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verify_ssl = verify_ssl
        self._preset = preset
        self._call_count = 0
        self._cache = None
        if use_cache or os.environ.get("PRESEAL_CACHE_ENABLED", "").lower() in ("1", "true", "yes"):
            from .cache import ResponseCache
            self._cache = ResponseCache()

    def invoke(self, input: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Send attack to HTTP endpoint, return response in preseal format."""
        config = config or {}
        self._call_count += 1

        # Extract attack text from preseal's input format
        messages = input.get("messages", [])
        if not messages:
            attack_text = ""
        else:
            msg = messages[-1]
            if isinstance(msg, tuple):
                attack_text = msg[1]
            elif isinstance(msg, dict):
                attack_text = msg.get("content", "")
            elif hasattr(msg, "content"):
                attack_text = msg.content
            else:
                attack_text = str(msg)

        # Build request body — substitute per-invocation placeholders
        trial_id = uuid.uuid4().hex[:8]
        body = self.body_template.replace("{{attack}}", _escape_json_string(attack_text))
        body = body.replace("{{trial_id}}", trial_id)

        # Check cache before making HTTP call
        cache_key = None
        if self._cache:
            from .cache import make_cache_key
            cache_key = make_cache_key(self.url, body)
            cached = self._cache.get(cache_key)
            if cached is not None:
                response_text = cached
                output = self._extract_response(response_text)
                for cb in config.get("callbacks", []):
                    if hasattr(cb, "on_chain_end"):
                        cb.on_chain_end({"output": output})
                return {"output": output}

        # Make request with retries
        response_text = self._do_request(body)

        # Cache successful responses
        if self._cache and cache_key:
            try:
                data = json.loads(response_text)
                is_error = isinstance(data, dict) and "error" in data
            except (json.JSONDecodeError, ValueError):
                is_error = False
            if not is_error:
                self._cache.put(cache_key, response_text)

        # Extract response content
        output = self._extract_response(response_text)

        # Notify callbacks if present
        for cb in config.get("callbacks", []):
            if hasattr(cb, "on_chain_end"):
                cb.on_chain_end({"output": output})

        return {"output": output}

    def _do_request(self, body: str) -> str:
        """Execute HTTP request with retries. Returns response body as string."""
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    self.url,
                    data=body.encode("utf-8") if body and self.method != "GET" else None,
                    headers={**{"Content-Type": "application/json"}, **self.headers},
                    method=self.method,
                )

                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                    return resp.read().decode("utf-8")

            except urllib.error.HTTPError as e:
                # Capture error responses — we want to see what the agent says under attack
                try:
                    error_body = e.read().decode("utf-8")
                    return error_body
                except Exception:
                    last_error = e
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                last_error = e
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay * (attempt + 1))

        # All retries exhausted — return error as response (don't raise)
        return json.dumps({"error": str(last_error)})

    def _extract_response(self, raw: str) -> str:
        """Extract text content from response using response_path or auto-detection."""
        if not raw:
            return ""

        # Try to parse as JSON
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            # Not JSON — return raw text
            return raw.strip()

        # If user specified a path, use it
        if self.response_path:
            return _extract_path(data, self.response_path)

        # A2A protocol has a unique response structure
        if self._preset == "a2a":
            return _extract_a2a_response(data)

        # Auto-detect common response formats
        return _auto_extract(data)


def _escape_json_string(s: str) -> str:
    """Escape a string for safe insertion into a JSON template."""
    # Use json.dumps to get proper escaping, then strip the quotes
    return json.dumps(s)[1:-1]


def _extract_path(data: Any, path: str) -> str:
    """Extract value from nested dict/list using dot-notation path.

    Supports: "choices.0.message.content", "response", "data.text"
    """
    parts = path.split(".")
    current = data

    for part in parts:
        if current is None:
            return ""
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return ""
        else:
            return str(current)

    if current is None:
        return ""
    if isinstance(current, str):
        return current
    return json.dumps(current)


def _auto_extract(data: Any) -> str:
    """Auto-detect response text from common API formats."""
    if isinstance(data, str):
        return data

    if not isinstance(data, dict):
        return json.dumps(data)

    # OpenAI-style: choices[0].message.content
    if "choices" in data:
        choices = data["choices"]
        if choices and isinstance(choices, list):
            choice = choices[0]
            if isinstance(choice, dict):
                msg = choice.get("message", {})
                if isinstance(msg, dict) and "content" in msg:
                    return msg["content"] or ""

    # Anthropic-style: content[0].text
    if "content" in data and isinstance(data["content"], list):
        parts = data["content"]
        if parts and isinstance(parts[0], dict) and "text" in parts[0]:
            return parts[0]["text"]

    # Simple response field
    for key in ("response", "output", "text", "answer", "result", "message"):
        if key in data:
            val = data[key]
            if isinstance(val, str):
                return val
            if isinstance(val, dict) and "content" in val:
                return val["content"]

    # Messages array (chat format): last message content
    if "messages" in data and isinstance(data["messages"], list):
        msgs = data["messages"]
        if msgs:
            last = msgs[-1]
            if isinstance(last, dict):
                return last.get("content", "")
            if hasattr(last, "content"):
                return last.content

    # Fallback: dump entire response
    return json.dumps(data)


PRESETS = {
    "openai": {
        "body_template": '{"model": "{{model}}", "messages": [{"role": "system", "content": "{{system}}"}, {"role": "user", "content": "{{attack}}"}]}',
        "response_path": "choices.0.message.content",
    },
    "anthropic": {
        "body_template": '{"model": "{{model}}", "max_tokens": 1024, "messages": [{"role": "user", "content": "{{attack}}"}]}',
        "response_path": "content.0.text",
    },
    "a2a": {
        "body_template": '{"jsonrpc": "2.0", "id": "preseal-{{trial_id}}", "method": "message/send", "params": {"message": {"messageId": "msg-{{trial_id}}", "role": "user", "parts": [{"text": "{{attack}}"}]}}}',
        "response_path": None,  # uses custom extraction
    },
    "ollama": {
        "body_template": '{"model": "{{model}}", "messages": [{"role": "user", "content": "{{attack}}"}], "stream": false}',
        "response_path": "message.content",
    },
}


def _extract_a2a_response(data: Any) -> str:
    """Extract response text from A2A Task result."""
    if not isinstance(data, dict):
        return str(data)
    # A2A response: {"result": {"id": "...", "status": {...}, "artifacts": [{"parts": [{"text": "..."}]}]}}
    result = data.get("result", data)
    artifacts = result.get("artifacts", [])
    if artifacts:
        parts = artifacts[0].get("parts", [])
        texts = [p.get("text", "") for p in parts if "text" in p]
        if texts:
            return "\n".join(texts)
    # Fallback: check status message
    status = result.get("status", {})
    if "message" in status:
        msg = status["message"]
        if isinstance(msg, dict) and "parts" in msg:
            return "\n".join(p.get("text", "") for p in msg["parts"] if "text" in p)
    return json.dumps(data)


def discover_a2a_agent(base_url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Fetch A2A Agent Card from /.well-known/agent.json."""
    url = base_url.rstrip("/") + "/.well-known/agent.json"
    try:
        req = urllib.request.Request(url, method="GET")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def create_http_agent(
    url: str,
    method: str = "POST",
    headers: Optional[List[str]] = None,
    body_template: Optional[str] = None,
    response_path: Optional[str] = None,
    timeout: int = 30,
    preset: Optional[str] = None,
    model: Optional[str] = None,
    system_prompt: Optional[str] = None,
    verify_ssl: bool = True,
    use_cache: bool = False,
) -> HTTPAgent:
    """Factory for CLI usage. Parses header strings into dict.

    Presets: 'openai', 'anthropic', 'a2a', 'ollama'. Auto-configures
    body template and response path for common API formats.
    """
    header_dict = {}
    if headers:
        for h in headers:
            if ":" in h:
                key, value = h.split(":", 1)
                header_dict[key.strip()] = value.strip()

    # Apply preset defaults
    if preset and preset in PRESETS:
        p = PRESETS[preset]
        if body_template is None:
            body_template = p["body_template"]
        if response_path is None:
            response_path = p["response_path"]

    # Substitute model/system placeholders in template (trial_id is per-invoke, not here)
    if body_template:
        body_template = body_template.replace("{{model}}", model or "gpt-4o-mini")
        body_template = body_template.replace("{{system}}", _escape_json_string(system_prompt or "You are a helpful assistant."))

    # A2A: set required header
    if preset == "a2a":
        header_dict.setdefault("A2A-Version", "1.0")

    return HTTPAgent(
        url=url,
        method=method,
        headers=header_dict,
        body_template=body_template,
        response_path=response_path,
        timeout=timeout,
        verify_ssl=verify_ssl,
        preset=preset,
        use_cache=use_cache,
    )
