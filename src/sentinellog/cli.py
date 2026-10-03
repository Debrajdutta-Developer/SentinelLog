"""Command-line interface for SentinelLog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .detector import detect_failed_logins, detect_password_spraying, detect_success_after_failures, run_all_rules
from .parser import parse_line


def _read_lines(path: str):
    if path == "-":
        yield from sys.stdin
        return
    with Path(path).open("r", encoding="utf-8") as handle:
        yield from handle


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelLog defensive authentication monitor")
    parser.add_argument("logfile", help="authentication log file, or '-' for stdin")
    parser.add_argument("--threshold", type=int, default=5, help="failure threshold (default: 5)")
    parser.add_argument("--window", type=int, default=300, help="detection window in seconds (default: 300)")
    parser.add_argument("--rule", choices=("all", "AUTH-001", "AUTH-002", "AUTH-003"), default="all")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit JSON alerts")
    args = parser.parse_args()

    events = []
    malformed = 0
    for line in _read_lines(args.logfile):
        event = parse_line(line)
        if event is None and line.strip():
            malformed += 1
        elif event is not None:
            events.append(event)

    if args.rule == "AUTH-001":
        alerts = detect_failed_logins(events, args.threshold, args.window)
    elif args.rule == "AUTH-002":
        alerts = detect_password_spraying(events, args.threshold, args.window)
    elif args.rule == "AUTH-003":
        alerts = detect_success_after_failures(events, max(3, args.threshold - 2), args.window)
    else:
        alerts = run_all_rules(events, args.threshold, args.window)

    if args.as_json:
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2))
        return 0

    print(f"Parsed events: {len(events)}")
    print(f"Malformed/unsupported lines: {malformed}")
    print(f"Rule: {args.rule}")
    print(f"Alerts: {len(alerts)}")
    for alert in alerts:
        print(f"[{alert.severity.upper()}] {alert.rule}: {alert.message}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
