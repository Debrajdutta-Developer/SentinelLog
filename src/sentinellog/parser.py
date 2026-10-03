"""Authentication log parsers used by SentinelLog."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    username: str
    source_ip: str
    success: bool
    raw: str
    source_format: str = "normalized"


_EVENT_RE = re.compile(
    r"^(?P<timestamp>\S+)\s+user=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+result=(?P<result>success|failed)$",
    re.IGNORECASE,
)

_SSHD_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<action>Failed password|Accepted (?:password|publickey|keyboard-interactive/pam))\s+"
    r"for (?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<ip>[0-9A-Fa-f:.]+)",
    re.IGNORECASE,
)

_MONTHS = {name: index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
)}


def _parse_normalized(raw: str) -> AuthEvent | None:
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
        source_format="normalized",
    )


def _parse_sshd(raw: str) -> AuthEvent | None:
    match = _SSHD_RE.match(raw)
    if not match:
        return None
    now = datetime.now(timezone.utc)
    timestamp = datetime(
        now.year,
        _MONTHS[match.group("month")],
        int(match.group("day")),
        *map(int, match.group("time").split(":")),
        tzinfo=timezone.utc,
    )
    action = match.group("action").lower()
    return AuthEvent(
        timestamp=timestamp,
        username=match.group("username"),
        source_ip=match.group("ip"),
        success=action.startswith("accepted"),
        raw=raw,
        source_format="openssh",
    )


def parse_line(line: str) -> AuthEvent | None:
    """Parse normalized SentinelLog records or common OpenSSH auth lines."""
    raw = line.strip()
    if not raw:
        return None
    return _parse_normalized(raw) or _parse_sshd(raw)
