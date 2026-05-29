"""
utils/logger.py
================
Provides a consistent logger for every module in LogVault.
Usage:
    from utils.logger import get_logger
    log = get_logger("my_module")
    log.info("Hello")
    log.error("Something failed: %s", err)
"""

import logging
import sys
import os

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(f"logvault.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
        logger.propagate = False
    return logger
