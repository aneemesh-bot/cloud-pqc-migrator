from __future__ import annotations

from enum import Enum
from pydantic import BaseModel

from .gap import Gap


class RemediationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class Remediation(BaseModel):
    remediation_id: str
    gap: Gap
    cli_command: str
    rollback_command: str
    iac_template: str | None = None
    forecasted_state: str
    status: RemediationStatus = RemediationStatus.PENDING
    llm_reasoning: str | None = None
    execution_output: str | None = None
    health_check_passed: bool | None = None
