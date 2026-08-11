import logging
import json
from typing import Any
import sys
import config


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # include extra fields if present
        if hasattr(record, "extra"):
            try:
                payload.update(record.extra)
            except Exception:
                pass
        # include any record.__dict__ extras (request_id, user_id, etc.)
        for k, v in record.__dict__.items():
            if k in ("msg", "args", "levelname", "levelno", "name", "msg", "exc_info", "stack_info", "lineno", "pathname", "filename", "module", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName", "processName", "process"):
                continue
            try:
                json.dumps({k: v})
                payload[k] = v
            except Exception:
                payload[k] = str(v)

        return json.dumps(payload)


def get_logger(name: str = __name__) -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, config.LOG_LEVEL.upper(), logging.INFO))
    return logger
