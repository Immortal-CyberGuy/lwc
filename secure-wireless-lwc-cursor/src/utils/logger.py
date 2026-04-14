"""Simple logging setup for demos and scripts."""

from __future__ import annotations

import logging
import sys
from typing import Optional


def get_logger(
    name: str,
    *,
    level: int = logging.INFO,
    fmt: Optional[str] = None,
) -> logging.Logger:
    """
    Return a logger that prints to stderr (idempotent if handlers already exist).
    """
    log = logging.getLogger(name)
    if log.handlers:
        log.setLevel(level)
        return log
    log.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(
            fmt or "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )
    log.addHandler(handler)
    log.propagate = False
    return log
