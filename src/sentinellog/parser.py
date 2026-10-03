"""Parsing helpers for normalized authentication events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    success: bool
    raw: str


# Example format:
# 2026-10-03T08:00:01Z user=alice ip=192.0.2.10 result=failed
_EVENT_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+user=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+result=(?P<result>success|failed)$",
    re.IGNORECASE,
)


def parse_line(line: str) -> AuthEvent | None:
    """Parse a SentinelLog authentication line.

    Returns None for malformed or unsupported lines instead of crashing the
    monitoring pipeline.
    """
    raw = line.strip()
    if not raw:
        return None

    match = _EVENT_RE.match(raw)
    if not match:
        return None

    timestamp = datetime.fromisoformat(match.group("timestamp").replace("Z", "+00:00"))
    return AuthEvent(
        timestamp=timestamp,
        username=match.group("username"),
        source_ip=match.group("ip"),
        success=match.group("result").lower() == "success",
        raw=raw,
    )
