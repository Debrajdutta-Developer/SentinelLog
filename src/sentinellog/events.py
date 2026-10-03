"""Structured security-event schema used by SentinelLog alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    rule_id: str
    severity: str
    category: str
    source_ip: str
    username: str
    observed_at: datetime
    message: str
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "source_ip": self.source_ip,
            "username": self.username,
            "observed_at": self.observed_at.isoformat(),
            "message": self.message,
            "evidence": self.evidence,
        }
