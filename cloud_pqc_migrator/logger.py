from __future__ import annotations

import logging
import sys
from pathlib import Path

_LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s — %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

log = logging.getLogger("cloud_pqc_migrator")


def configure_logging(level: str = "WARNING", log_file: Path | None = None) -> None:
    numeric = getattr(logging, level.upper(), logging.WARNING)
    log.setLevel(numeric)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(numeric)
    stderr_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    log.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        log.addHandler(file_handler)
