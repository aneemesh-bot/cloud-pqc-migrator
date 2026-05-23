from __future__ import annotations

import json
import re

_SHELL_METACHAR_RE = re.compile(r"[;&|`$]")
_ALLOWED_PREFIXES = ("aws ", "gcloud ")


class RemediationValidationError(ValueError):
    pass


def strip_markdown_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last fence lines
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text.strip()


def validate_cli_command(cmd: str, field_name: str) -> None:
    if not cmd:
        raise RemediationValidationError(f"{field_name} is empty")
    if not any(cmd.startswith(p) for p in _ALLOWED_PREFIXES):
        raise RemediationValidationError(
            f"{field_name} must start with 'aws ' or 'gcloud ', got: {cmd[:40]!r}"
        )
    if _SHELL_METACHAR_RE.search(cmd):
        raise RemediationValidationError(
            f"{field_name} contains shell metacharacters (security risk): {cmd[:80]!r}"
        )


def validate_remediation_output(raw_text: str) -> dict:
    cleaned = strip_markdown_fences(raw_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise RemediationValidationError(f"LLM response is not valid JSON: {exc}") from exc

    required_keys = {"cli_command", "rollback_command", "forecasted_state", "reasoning"}
    missing = required_keys - data.keys()
    if missing:
        raise RemediationValidationError(f"LLM response missing required keys: {missing}")

    validate_cli_command(data["cli_command"], "cli_command")
    validate_cli_command(data["rollback_command"], "rollback_command")

    return data
