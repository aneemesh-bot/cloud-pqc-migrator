from __future__ import annotations

import os
import uuid
from typing import Callable, Optional

import anthropic

from cloud_pqc_migrator.models import Gap, Remediation, RemediationStatus
from .prompt_templates import SYSTEM_PROMPT, build_user_prompt
from .validator import validate_remediation_output, RemediationValidationError

_client: Optional[anthropic.Anthropic] = None


class MissingAPIKeyError(RuntimeError):
    pass


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            raise MissingAPIKeyError(
                "ANTHROPIC_API_KEY is not set. "
                "Export the variable before running the remediation step:\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )
        _client = anthropic.Anthropic()
    return _client


def generate_remediation(gap: Gap) -> Remediation:
    client = _get_client()
    user_prompt = build_user_prompt(gap)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_prompt}],
    )

    raw_text = response.content[0].text

    try:
        data = validate_remediation_output(raw_text)
    except RemediationValidationError:
        # Retry once with an error-correction turn
        retry_response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": user_prompt},
                {"role": "assistant", "content": raw_text},
                {
                    "role": "user",
                    "content": (
                        "Your previous response was not valid JSON or failed validation. "
                        "Please respond ONLY with the JSON object as specified in the output contract. "
                        "No markdown fences, no explanatory text — pure JSON only."
                    ),
                },
            ],
        )
        raw_text = retry_response.content[0].text
        data = validate_remediation_output(raw_text)

    return Remediation(
        remediation_id=str(uuid.uuid4()),
        gap=gap,
        cli_command=data["cli_command"],
        rollback_command=data["rollback_command"],
        iac_template=data.get("iac_template"),
        forecasted_state=data["forecasted_state"],
        llm_reasoning=data.get("reasoning"),
        status=RemediationStatus.PENDING,
    )


def generate_all_remediations(
    gaps: list[Gap],
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> list[Remediation]:
    remediations: list[Remediation] = []
    for i, gap in enumerate(gaps):
        r = generate_remediation(gap)
        remediations.append(r)
        if progress_callback:
            progress_callback(i + 1, len(gaps))
    return remediations
