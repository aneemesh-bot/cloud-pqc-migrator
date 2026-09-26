from __future__ import annotations

import uuid
from typing import Callable

from cloud_pqc_migrator.models import Gap, Remediation, RemediationStatus
from .llm_backends import AnthropicBackend, LLMBackend
from .prompt_templates import SYSTEM_PROMPT, build_user_prompt
from .validator import validate_remediation_output, RemediationValidationError


def generate_remediation(gap: Gap, backend: LLMBackend | None = None) -> Remediation:
    backend = backend or AnthropicBackend()
    user_prompt = build_user_prompt(gap)

    raw_text = backend.complete(SYSTEM_PROMPT, [{"role": "user", "content": user_prompt}])

    try:
        data = validate_remediation_output(raw_text)
    except RemediationValidationError:
        # Retry once with an error-correction turn
        raw_text = backend.complete(
            SYSTEM_PROMPT,
            [
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
    progress_callback: Callable[[int, int], None] | None = None,
    backend: LLMBackend | None = None,
) -> list[Remediation]:
    backend = backend or AnthropicBackend()
    remediations: list[Remediation] = []
    for i, gap in enumerate(gaps):
        r = generate_remediation(gap, backend=backend)
        remediations.append(r)
        if progress_callback:
            progress_callback(i + 1, len(gaps))
    return remediations
