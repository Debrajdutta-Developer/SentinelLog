from datetime import datetime, timezone, timedelta

from sentinellog.detector import detect_failed_logins
from sentinellog.parser import AuthEvent


def event(second: int, result: bool = False) -> AuthEvent:
    return AuthEvent(
        timestamp=datetime(2026, 10, 3, 8, 0, second, tzinfo=timezone.utc),
        username="alice",
        source_ip="192.0.2.10",
        success=result,
        raw="",
    )


def test_alert_at_five_failures():
    alerts = detect_failed_logins([event(i) for i in range(5)])
    assert len(alerts) == 1
    assert alerts[0].rule == "AUTH-001"
    assert alerts[0].failed_attempts == 5


def test_success_resets_failure_sequence():
    events = [event(i) for i in range(4)] + [event(10, True)] + [event(20 + i) for i in range(4)]
    assert detect_failed_logins(events) == []


def test_old_failures_fall_outside_window():
    events = [event(0), event(1), event(2), event(3), event(4)]
    alerts = detect_failed_logins(events, threshold=5, window_seconds=3)
    assert alerts == []
