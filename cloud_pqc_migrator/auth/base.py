from __future__ import annotations

import os
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from cloud_pqc_migrator.models import CloudProvider


@dataclass
class CredentialBundle:
    provider: CloudProvider
    env_vars: dict[str, str] = field(default_factory=dict)
    masked_display: str = ""
    expires_at: datetime | None = None

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(tz=timezone.utc) >= self.expires_at

    def will_expire_soon(self, minutes: int = 5) -> bool:
        if self.expires_at is None:
            return False
        from datetime import timedelta
        return datetime.now(tz=timezone.utc) >= (self.expires_at - timedelta(minutes=minutes))

    def build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(self.env_vars)
        return env


class CredentialProvider(ABC):
    @abstractmethod
    def prompt_and_load(self) -> CredentialBundle:
        ...

    @abstractmethod
    def validate(self, bundle: CredentialBundle) -> bool:
        ...

    def clear(self, bundle: CredentialBundle) -> None:
        for key in bundle.env_vars:
            bundle.env_vars[key] = ""


def run_subprocess(cmd: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after 30s: {' '.join(cmd)}"
    return result.returncode, result.stdout, result.stderr
