"""Correlation-based defensive authentication detection rules."""

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
    evidence: dict | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        return data


def _validate(threshold: int, window_seconds: int) -> timedelta:
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")
    return timedelta(seconds=window_seconds)


def detect_failed_logins(events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 300) -> list[SecurityAlert]:
    """AUTH-001: repeated failures for the same source/user pair."""
    window = _validate(threshold, window_seconds)
    buckets: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    alerted: set[tuple[str, str, datetime]] = set()
    alerts: list[SecurityAlert] = []

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
            alert_key = (*key, first_seen)
            if alert_key in alerted:
                continue
            alerted.add(alert_key)
            severity = "high" if len(failures) >= threshold * 2 else "medium"
            alerts.append(SecurityAlert(
                rule="AUTH-001", severity=severity, source_ip=event.source_ip,
                username=event.username, failed_attempts=len(failures),
                first_seen=first_seen, last_seen=event.timestamp,
                message=f"Repeated authentication failures for {event.username} from {event.source_ip}: {len(failures)} failures within {window_seconds}s.",
                evidence={"source_format": event.source_format, "threshold": threshold, "window_seconds": window_seconds},
            ))
    return alerts


def detect_password_spraying(events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 300) -> list[SecurityAlert]:
    """AUTH-002: repeated failures from one source against multiple users."""
    window = _validate(threshold, window_seconds)
    buckets: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)
    alerted: set[tuple[str, datetime]] = set()
    alerts: list[SecurityAlert] = []

    for event in sorted(events, key=lambda item: item.timestamp):
        failures = buckets[event.source_ip]
        if event.success:
            continue
        failures.append((event.timestamp, event.username))
        cutoff = event.timestamp - window
        while failures and failures[0][0] < cutoff:
            failures.popleft()
        unique_users = {username for _, username in failures}
        if len(failures) >= threshold and len(unique_users) >= 2:
            first_seen = failures[0][0]
            key = (event.source_ip, first_seen)
            if key in alerted:
                continue
            alerted.add(key)
            alerts.append(SecurityAlert(
                rule="AUTH-002", severity="high", source_ip=event.source_ip,
                username="*", failed_attempts=len(failures), first_seen=first_seen,
                last_seen=event.timestamp,
                message=f"Multiple authentication failures from {event.source_ip} across {len(unique_users)} usernames within {window_seconds}s.",
                evidence={"target_users": sorted(unique_users), "window_seconds": window_seconds},
            ))
    return alerts


def detect_success_after_failures(events: Iterable[AuthEvent], threshold: int = 3, window_seconds: int = 300) -> list[SecurityAlert]:
    """AUTH-003: successful authentication following repeated failures."""
    window = _validate(threshold, window_seconds)
    buckets: dict[tuple[str, str], deque[datetime]] = defaultdict(deque)
    alerts: list[SecurityAlert] = []
    alerted: set[tuple[str, str, datetime]] = set()

    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.source_ip, event.username)
        failures = buckets[key]
        cutoff = event.timestamp - window
        while failures and failures[0] < cutoff:
            failures.popleft()
        if event.success:
            if len(failures) >= threshold:
                first_seen = failures[0]
                alert_key = (*key, event.timestamp)
                if alert_key not in alerted:
                    alerted.add(alert_key)
                    alerts.append(SecurityAlert(
                        rule="AUTH-003", severity="high", source_ip=event.source_ip,
                        username=event.username, failed_attempts=len(failures),
                        first_seen=first_seen, last_seen=event.timestamp,
                        message=f"Successful authentication followed {len(failures)} failures for {event.username} from {event.source_ip}.",
                        evidence={"threshold": threshold, "window_seconds": window_seconds},
                    ))
            failures.clear()
        else:
            failures.append(event.timestamp)
    return alerts


def run_all_rules(events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 300) -> list[SecurityAlert]:
    """Run all enabled built-in authentication detections."""
    materialized = list(events)
    alerts = detect_failed_logins(materialized, threshold, window_seconds)
    alerts.extend(detect_password_spraying(materialized, threshold, window_seconds))
    alerts.extend(detect_success_after_failures(materialized, max(3, threshold - 2), window_seconds))
    return sorted(alerts, key=lambda alert: alert.last_seen)
