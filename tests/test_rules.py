from datetime import datetime, timezone

from sentinellog.detector import detect_password_spraying, detect_success_after_failures, run_all_rules
from sentinellog.parser import AuthEvent


def event(second: int, user: str, ip: str = "192.0.2.10", success: bool = False) -> AuthEvent:
    return AuthEvent(datetime(2026, 10, 3, 8, 0, second, tzinfo=timezone.utc), user, ip, success, "")


def test_password_spraying_across_users():
    events = [event(i, f"user{i}") for i in range(5)]
    alerts = detect_password_spraying(events)
    assert len(alerts) == 1
    assert alerts[0].rule == "AUTH-002"
    assert alerts[0].username == "*"


def test_success_after_failures_creates_correlation_alert():
    events = [event(i, "alice") for i in range(3)] + [event(10, "alice", success=True)]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert alerts[0].rule == "AUTH-003"
    assert alerts[0].severity == "high"


def test_all_rules_returns_multiple_signal_types():
    events = [event(i, "alice") for i in range(5)] + [event(10, "alice", success=True)]
    alerts = run_all_rules(events)
    assert {alert.rule for alert in alerts} >= {"AUTH-001", "AUTH-003"}
