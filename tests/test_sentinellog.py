from datetime import datetime, timezone

from sentinellog.detector import detect_failed_logins
from sentinellog.parser import parse_line


def event_line(second: int, result: str = "failed") -> str:
    return f"2026-10-03T08:00:{second:02d}Z user=alice ip=192.0.2.10 result={result}"


def test_parser_accepts_valid_event():
    event = parse_line(event_line(1))
    assert event is not None
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.success is False
    assert event.timestamp.tzinfo == timezone.utc


def test_parser_rejects_invalid_event():
    assert parse_line("not a supported authentication record") is None


def test_threshold_creates_one_alert():
    events = [parse_line(event_line(i)) for i in range(1, 6)]
    alerts = detect_failed_logins([e for e in events if e], threshold=5, window_seconds=300)
    assert len(alerts) == 1
    assert alerts[0].rule == "AUTH-001"
    assert alerts[0].failed_attempts == 5
    assert alerts[0].severity == "medium"


def test_success_resets_failure_sequence():
    lines = [event_line(1), event_line(2), event_line(3), event_line(4), event_line(5, "success"), event_line(6)]
    events = [parse_line(line) for line in lines]
    alerts = detect_failed_logins([e for e in events if e], threshold=5, window_seconds=300)
    assert alerts == []


def test_old_events_fall_outside_window():
    events = [
        parse_line("2026-10-03T08:00:00Z user=alice ip=192.0.2.10 result=failed"),
        parse_line("2026-10-03T08:01:00Z user=alice ip=192.0.2.10 result=failed"),
        parse_line("2026-10-03T08:02:00Z user=alice ip=192.0.2.10 result=failed"),
        parse_line("2026-10-03T08:06:00Z user=alice ip=192.0.2.10 result=failed"),
        parse_line("2026-10-03T08:07:00Z user=alice ip=192.0.2.10 result=failed"),
    ]
    alerts = detect_failed_logins([e for e in events if e], threshold=5, window_seconds=300)
    assert alerts == []
