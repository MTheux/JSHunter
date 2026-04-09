"""
JSHunter — Logger
Logging estruturado com cores e niveis
"""

import logging
import sys
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """Formatter com cores para terminal"""

    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[37m',      # White
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[91m',  # Bright Red
    }
    RESET = '\033[0m'
    RED = '\033[31m'
    GREY = '\033[90m'

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.fromtimestamp(record.created).strftime('%H:%M:%S')
        return (
            f"{self.GREY}{timestamp}{self.RESET} "
            f"{self.RED}[JSHunter]{self.RESET} "
            f"{color}{record.levelname:<8}{self.RESET} "
            f"{record.getMessage()}"
        )


def setup_logger(name="jshunter", level=logging.INFO) -> logging.Logger:
    """Configura e retorna o logger da aplicacao"""
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ColorFormatter())
    logger.addHandler(handler)

    return logger


# Logger global da aplicacao
logger = setup_logger()
