from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Protocol, cast

import anthropic

# Anthropic's current recommended model. Bump this when a newer model is recommended.
# Pinned rather than resolved at runtime so runs stay reproducible.
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5-5"

DEFAULT_OLLAMA_HOST = "http://localhost:11434"
_OLLAMA_TIMEOUT_SECONDS = 300
_MAX_TOKENS = 2048

PROVIDERS = ("anthropic", "ollama")


class LLMBackendError(RuntimeError):
    pass


class MissingAPIKeyError(LLMBackendError):
    pass


class LLMBackend(Protocol):
    name: str
    model: str

    def complete(self, system: str, messages: list[dict[str, str]]) -> str: ...

    def preflight(self) -> None: ...

    def list_models(self) -> list[str]: ...


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_ANTHROPIC_MODEL) -> None:
        self.model = model
        self._client: anthropic.Anthropic | None = None

    def _get_client(self) -> anthropic.Anthropic:
        if self._client is None:
            if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
                raise MissingAPIKeyError(
                    "ANTHROPIC_API_KEY is not set. "
                    "Export the variable before running the remediation step:\n"
                    "  export ANTHROPIC_API_KEY=sk-ant-..."
                )
            self._client = anthropic.Anthropic()
        return self._client

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        response = self._get_client().messages.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=cast(Any, messages),
        )
        return str(getattr(response.content[0], "text", ""))

    def preflight(self) -> None:
        client = self._get_client()
        try:
            client.models.retrieve(self.model)
        except anthropic.NotFoundError as exc:
            raise LLMBackendError(
                f"Unknown Anthropic model {self.model!r}. Run "
                "`cloud-pqc-migrator models --llm-provider anthropic` to see available models."
            ) from exc
        except anthropic.APIError as exc:
            raise LLMBackendError(f"Anthropic API check failed: {exc}") from exc

    def list_models(self) -> list[str]:
        try:
            return [m.id for m in self._get_client().models.list()]
        except anthropic.APIError as exc:
            raise LLMBackendError(f"Could not list Anthropic models: {exc}") from exc


def _normalise_host(host: str) -> str:
    host = host.strip().rstrip("/")
    if "://" not in host:
        host = f"http://{host}"
    return host


def _with_latest(name: str) -> str:
    return name if ":" in name else f"{name}:latest"


class OllamaBackend:
    name = "ollama"

    def __init__(self, model: str, host: str | None = None) -> None:
        self.model = model
        self.host = _normalise_host(host or os.environ.get("OLLAMA_HOST") or DEFAULT_OLLAMA_HOST)

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.host}{path}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=_OLLAMA_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode())  # type: ignore[no-any-return]
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace").strip()
            raise LLMBackendError(f"Ollama request to {url} failed ({exc.code}): {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMBackendError(
                f"Could not reach Ollama at {self.host} ({exc}). Is `ollama serve` running?"
            ) from exc

    def complete(self, system: str, messages: list[dict[str, str]]) -> str:
        body = self._request(
            "/api/chat",
            {
                "model": self.model,
                "messages": [{"role": "system", "content": system}, *messages],
                "stream": False,
                "format": "json",
                "options": {"num_predict": _MAX_TOKENS, "temperature": 0},
            },
        )
        try:
            return str(body["message"]["content"])
        except (KeyError, TypeError) as exc:
            raise LLMBackendError(f"Unexpected Ollama response: {body!r}") from exc

    def list_models(self) -> list[str]:
        body = self._request("/api/tags")
        return [m["name"] for m in body.get("models", [])]

    def preflight(self) -> None:
        available = {_with_latest(n) for n in self.list_models()}
        if _with_latest(self.model) not in available:
            raise LLMBackendError(
                f"Ollama model {self.model!r} is not available at {self.host}.\n"
                f"  ollama pull {self.model}"
            )


def get_backend(
    provider: str,
    model: str | None = None,
    ollama_host: str | None = None,
) -> LLMBackend:
    if provider == "anthropic":
        return AnthropicBackend(model or DEFAULT_ANTHROPIC_MODEL)
    if provider == "ollama":
        if not model:
            raise LLMBackendError("--model is required with --llm-provider ollama")
        return OllamaBackend(model, host=ollama_host)
    raise LLMBackendError(f"Unknown LLM provider {provider!r}. Choose one of: {', '.join(PROVIDERS)}")
