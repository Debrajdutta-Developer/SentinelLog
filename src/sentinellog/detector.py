"""Detection rules for authentication telemetry."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Iterable

from .parser import AuthEvent


@dataclass(frozen=True)
class SecurityAlert:
    rule: str
    severity: str
    source_ip: str
    username: str
    failed_attempts: int
    first_seen: datetime
    last_seen: datetime
    message: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data


def detect_failed_logins(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window_seconds: int = 300,
) -> list[SecurityAlert]:
    """Detect repeated failed logins from the same source/user pair.

    Detection is defensive and operates only on supplied telemetry. A source
    triggers when it reaches ``threshold`` failures inside the time window.
    """
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")

    buckets: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    alerted: set[tuple[str, str, datetime]] = set()
    alerts: list[SecurityAlert] = []
    window = timedelta(seconds=window_seconds)

    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.source_ip, event.username)
        failures = buckets[key]

        if event.success:
            failures.clear()
            continue

        failures.append(event.timestamp)
        cutoff = event.timestamp - window
        while failures and failures[0] < cutoff:
            failures.popleft()

        if len(failures) >= threshold:
            first_seen = failures[0]
            alert_key = (event.source_ip, event.username, first_seen)
            if alert_key in alerted:
                continue
            alerted.add(alert_key)
            severity = "high" if len(failures) >= threshold * 2 else "medium"
            alerts.append(
                SecurityAlert(
                    rule="AUTH-001",
                    severity=severity,
                    source_ip=event.source_ip,
                    username=event.username,
                    failed_attempts=len(failures),
                    first_seen=first_seen,
                    last_seen=event.timestamp,
                    message=(
                        f"Repeated authentication failures for {event.username} "
                        f"from {event.source_ip}: {len(failures)} failures "
                        f"within {window_seconds}s."
                    ),
                )
            )

    return alerts
