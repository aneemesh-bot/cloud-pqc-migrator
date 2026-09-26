from __future__ import annotations

import io
import json
import urllib.error
from unittest.mock import MagicMock

import anthropic
import httpx
import pytest
from click.testing import CliRunner

from cloud_pqc_migrator.main import cli
from cloud_pqc_migrator.remediation import (
    DEFAULT_ANTHROPIC_MODEL,
    AnthropicBackend,
    LLMBackendError,
    OllamaBackend,
    generate_remediation,
    get_backend,
)

_VALID_JSON = json.dumps({
    "cli_command": "aws elbv2 modify-listener --listener-arn arn:x --ssl-policy ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "rollback_command": "aws elbv2 modify-listener --listener-arn arn:x --ssl-policy ELBSecurityPolicy-2016-08",
    "iac_template": None,
    "forecasted_state": "TLS 1.3 enforced",
    "reasoning": "ok",
})


def _http_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode()
    resp.__enter__.return_value = resp
    return resp


# ── get_backend ───────────────────────────────────────────────────────────────

def test_get_backend_anthropic_defaults_to_recommended_model():
    backend = get_backend("anthropic", None)
    assert isinstance(backend, AnthropicBackend)
    assert backend.model == DEFAULT_ANTHROPIC_MODEL


def test_get_backend_anthropic_custom_model():
    assert get_backend("anthropic", "claude-sonnet-5").model == "claude-sonnet-5"


def test_get_backend_ollama_requires_model():
    with pytest.raises(LLMBackendError, match="--model is required"):
        get_backend("ollama", None)


def test_get_backend_unknown_provider():
    with pytest.raises(LLMBackendError):
        get_backend("openai", "gpt")


# ── AnthropicBackend ──────────────────────────────────────────────────────────

def test_anthropic_complete_uses_selected_model():
    backend = AnthropicBackend("claude-sonnet-5")
    client = MagicMock()
    client.messages.create.return_value.content = [MagicMock(text="hello")]
    backend._client = client

    assert backend.complete("sys", [{"role": "user", "content": "hi"}]) == "hello"
    kwargs = client.messages.create.call_args.kwargs
    assert kwargs["model"] == "claude-sonnet-5"
    assert kwargs["system"][0]["text"] == "sys"
    assert kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_anthropic_preflight_missing_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMBackendError, match="ANTHROPIC_API_KEY"):
        AnthropicBackend().preflight()


def test_anthropic_preflight_unknown_model():
    backend = AnthropicBackend("claude-typo")
    client = MagicMock()
    request = httpx.Request("GET", "https://api.anthropic.com/v1/models/claude-typo")
    client.models.retrieve.side_effect = anthropic.NotFoundError(
        "not found", response=httpx.Response(404, request=request), body=None
    )
    backend._client = client

    with pytest.raises(LLMBackendError, match="Unknown Anthropic model 'claude-typo'"):
        backend.preflight()


# ── OllamaBackend ─────────────────────────────────────────────────────────────

def test_ollama_complete_sends_chat_request(mocker):
    urlopen = mocker.patch(
        "urllib.request.urlopen",
        return_value=_http_response({"message": {"role": "assistant", "content": "{}"}}),
    )
    backend = OllamaBackend("llama3.1", host="http://ollama:11434")

    assert backend.complete("sys", [{"role": "user", "content": "hi"}]) == "{}"

    req = urlopen.call_args.args[0]
    assert req.full_url == "http://ollama:11434/api/chat"
    body = json.loads(req.data)
    assert body["model"] == "llama3.1"
    assert body["messages"][0] == {"role": "system", "content": "sys"}
    assert body["messages"][1] == {"role": "user", "content": "hi"}
    assert body["stream"] is False
    assert body["format"] == "json"


def test_ollama_host_from_env_without_scheme(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "10.0.0.5:11434/")
    assert OllamaBackend("llama3.1").host == "http://10.0.0.5:11434"


def test_ollama_host_default(monkeypatch):
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    assert OllamaBackend("llama3.1").host == "http://localhost:11434"


def test_ollama_preflight_unreachable(mocker):
    mocker.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("refused"))
    with pytest.raises(LLMBackendError, match="ollama serve"):
        OllamaBackend("llama3.1", host="localhost:1").preflight()


def test_ollama_preflight_model_not_pulled(mocker):
    mocker.patch(
        "urllib.request.urlopen",
        return_value=_http_response({"models": [{"name": "mistral:latest"}]}),
    )
    with pytest.raises(LLMBackendError, match="ollama pull llama3.1"):
        OllamaBackend("llama3.1").preflight()


@pytest.mark.parametrize("requested", ["llama3.1", "llama3.1:latest"])
def test_ollama_preflight_matches_implicit_latest_tag(mocker, requested):
    mocker.patch(
        "urllib.request.urlopen",
        return_value=_http_response({"models": [{"name": "llama3.1:latest"}]}),
    )
    OllamaBackend(requested).preflight()


def test_ollama_http_error_is_wrapped(mocker):
    err = urllib.error.HTTPError(
        "http://localhost:11434/api/chat", 404, "Not Found", {}, io.BytesIO(b'{"error":"model not found"}')
    )
    mocker.patch("urllib.request.urlopen", side_effect=err)
    with pytest.raises(LLMBackendError, match="model not found"):
        OllamaBackend("nope").complete("sys", [])


# ── Pipeline retry path ───────────────────────────────────────────────────────

def test_generate_remediation_retries_on_invalid_output(sample_gap):
    backend = MagicMock()
    backend.complete.side_effect = ["not json at all", _VALID_JSON]

    remediation = generate_remediation(sample_gap, backend=backend)

    assert backend.complete.call_count == 2
    retry_messages = backend.complete.call_args_list[1].args[1]
    assert [m["role"] for m in retry_messages] == ["user", "assistant", "user"]
    assert retry_messages[1]["content"] == "not json at all"
    assert remediation.forecasted_state == "TLS 1.3 enforced"


# ── `models` command ──────────────────────────────────────────────────────────

def test_models_command_marks_default(mocker):
    mocker.patch.object(
        AnthropicBackend, "list_models", return_value=[DEFAULT_ANTHROPIC_MODEL, "claude-sonnet-5"]
    )
    result = CliRunner().invoke(cli, ["models"])

    assert result.exit_code == 0, result.output
    assert DEFAULT_ANTHROPIC_MODEL in result.output
    assert "claude-sonnet-5" in result.output
    assert "✓" in result.output


def test_models_command_ollama_unreachable(mocker):
    mocker.patch.object(OllamaBackend, "list_models", side_effect=LLMBackendError("down"))
    result = CliRunner().invoke(cli, ["models", "--llm-provider", "ollama"])
    assert result.exit_code == 1
    assert "down" in result.output
