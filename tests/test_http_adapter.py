"""Tests for preseal HTTP adapter — HTTPAgent, helpers, and create_http_agent factory."""

import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from preseal.http_adapter import (
    HTTPAgent,
    _escape_json_string,
    _extract_path,
    _auto_extract,
    create_http_agent,
)

passed = 0
failed = 0


def test(name):
    """Decorator-free test runner."""
    global passed, failed

    def decorator(fn):
        global passed, failed
        try:
            fn()
            passed += 1
            print(f"  PASS: {name}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL: {name} — {e}")
        except Exception as e:
            failed += 1
            print(f"  ERROR: {name} — {type(e).__name__}: {e}")

    return decorator


class FakeHTTPAgent(HTTPAgent):
    """Subclass that overrides _do_request to return canned responses."""

    def __init__(self, canned_response: str, **kwargs):
        kwargs.setdefault("url", "http://localhost:8000/chat")
        super().__init__(**kwargs)
        self._canned_response = canned_response
        self._last_body = None

    def _do_request(self, body: str) -> str:
        self._last_body = body
        return self._canned_response


# =============================================================================
# TESTS
# =============================================================================

print("\n=== HTTP Adapter Tests ===")


@test("HTTPAgent initializes with correct defaults")
def _():
    agent = HTTPAgent(url="http://example.com/api")
    assert agent.url == "http://example.com/api"
    assert agent.method == "POST"
    assert agent.headers == {}
    assert "{{attack}}" in agent.body_template
    assert agent.response_path is None
    assert agent.timeout == 30
    assert agent.max_retries == 2
    assert agent.retry_delay == 1.0
    assert agent.verify_ssl is True


@test("HTTPAgent.invoke() extracts attack text from tuple input")
def _():
    agent = FakeHTTPAgent(canned_response='{"output": "hello"}')
    result = agent.invoke({"messages": [("user", "test prompt")]})
    assert result["output"] == "hello"
    assert "test prompt" in agent._last_body


@test("HTTPAgent.invoke() extracts attack text from dict input")
def _():
    agent = FakeHTTPAgent(canned_response='{"output": "ok"}')
    result = agent.invoke({"messages": [{"role": "user", "content": "dict prompt"}]})
    assert "dict prompt" in agent._last_body


@test("HTTPAgent.invoke() extracts attack text from object with .content")
def _():
    class FakeMsg:
        content = "object prompt"

    agent = FakeHTTPAgent(canned_response='{"output": "ok"}')
    agent.invoke({"messages": [FakeMsg()]})
    assert "object prompt" in agent._last_body


@test("_escape_json_string handles quotes, newlines, backslashes")
def _():
    assert _escape_json_string('say "hi"') == 'say \\"hi\\"'
    assert _escape_json_string("line1\nline2") == "line1\\nline2"
    assert _escape_json_string("back\\slash") == "back\\\\slash"


@test("_extract_path extracts from nested dicts")
def _():
    data = {"choices": [{"message": {"content": "extracted"}}]}
    assert _extract_path(data, "choices.0.message.content") == "extracted"


@test("_extract_path extracts from lists by index")
def _():
    data = {"items": ["zero", "one", "two"]}
    assert _extract_path(data, "items.1") == "one"


@test("_extract_path returns empty string for missing keys")
def _():
    data = {"a": {"b": 1}}
    assert _extract_path(data, "a.c.d") == ""


@test("_auto_extract handles OpenAI format")
def _():
    data = {"choices": [{"message": {"content": "openai response"}}]}
    assert _auto_extract(data) == "openai response"


@test("_auto_extract handles Anthropic format")
def _():
    data = {"content": [{"text": "anthropic response", "type": "text"}]}
    assert _auto_extract(data) == "anthropic response"


@test("_auto_extract handles simple response fields")
def _():
    assert _auto_extract({"response": "simple"}) == "simple"
    assert _auto_extract({"output": "out"}) == "out"
    assert _auto_extract({"text": "txt"}) == "txt"


@test("_auto_extract handles messages array")
def _():
    data = {"messages": [{"role": "assistant", "content": "last msg"}]}
    assert _auto_extract(data) == "last msg"


@test("create_http_agent with preset openai sets correct template")
def _():
    agent = create_http_agent("http://api.openai.com/v1/chat/completions", preset="openai")
    assert "choices.0.message.content" == agent.response_path
    assert '"model"' in agent.body_template
    assert "gpt-4o-mini" in agent.body_template


@test("create_http_agent with preset a2a sets A2A-Version header")
def _():
    agent = create_http_agent("http://localhost:9000", preset="a2a")
    assert agent.headers.get("A2A-Version") == "1.0"


@test("Trial ID is unique per invoke ({{trial_id}} substitution)")
def _():
    agent = FakeHTTPAgent(
        canned_response='{"output": "ok"}',
        url="http://localhost:8000",
        body_template='{"id": "{{trial_id}}", "msg": "{{attack}}"}',
    )
    agent.invoke({"messages": [("user", "test1")]})
    body1 = agent._last_body
    agent.invoke({"messages": [("user", "test2")]})
    body2 = agent._last_body
    # Extract trial_ids from bodies
    id1 = json.loads(body1)["id"]
    id2 = json.loads(body2)["id"]
    assert id1 != id2, f"Trial IDs should be unique, got {id1} twice"
    assert len(id1) == 8


@test("SSL verification defaults to True")
def _():
    agent = create_http_agent("https://example.com/api")
    assert agent.verify_ssl is True


@test("Error responses are captured (not raised)")
def _():
    # Simulate an error response body from _do_request
    agent = FakeHTTPAgent(canned_response='{"error": "rate limit exceeded"}')
    result = agent.invoke({"messages": [("user", "hello")]})
    # Should not raise — error is captured in the output
    assert "rate limit exceeded" in result["output"]


# =============================================================================
# SUMMARY
# =============================================================================

print(f"\n{'='*60}")
print(f"HTTP Adapter Tests: {passed} passed, {failed} failed, {passed + failed} total")
print(f"{'='*60}")

if failed > 0:
    sys.exit(1)
