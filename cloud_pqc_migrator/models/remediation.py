from __future__ import annotations

from enum import Enum
from typing import Optional

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
    iac_template: Optional[str] = None
    forecasted_state: str
    status: RemediationStatus = RemediationStatus.PENDING
    llm_reasoning: Optional[str] = None
    execution_output: Optional[str] = None
    health_check_passed: Optional[bool] = None
