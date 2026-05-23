from __future__ import annotations

from datetime import date
from enum import Enum, IntEnum
from typing import Optional

from pydantic import BaseModel

from .cbom import CryptoAsset


class Priority(IntEnum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3


class FIPSStandard(str, Enum):
    FIPS_203 = "FIPS_203"   # ML-KEM (CRYSTALS-Kyber)
    FIPS_204 = "FIPS_204"   # ML-DSA (CRYSTALS-Dilithium)
    FIPS_205 = "FIPS_205"   # SLH-DSA (SPHINCS+)


class Gap(BaseModel):
    gap_id: str
    asset: CryptoAsset
    priority: Priority
    rule_id: str
    description: str
    fips_references: list[FIPSStandard]
    current_state: str
    target_state: str
    t_start: Optional[date] = None
