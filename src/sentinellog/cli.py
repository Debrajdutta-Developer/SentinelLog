"""Command-line interface for SentinelLog."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .detector import detect_failed_logins
from .parser import parse_line


def main() -> int:
    parser = argparse.ArgumentParser(description="SentinelLog authentication monitor")
    parser.add_argument("logfile", type=Path, help="authentication log file")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=300, help="detection window in seconds")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit JSON alerts")
    args = parser.parse_args()

    events = []
    malformed = 0
    with args.logfile.open("r", encoding="utf-8") as handle:
        for line in handle:
            event = parse_line(line)
            if event is None and line.strip():
                malformed += 1
            elif event is not None:
                events.append(event)

    alerts = detect_failed_logins(events, args.threshold, args.window)

    if args.as_json:
        print(json.dumps([alert.to_dict() for alert in alerts], indent=2))
    else:
        print(f"Parsed events: {len(events)}")
        print(f"Malformed/unsupported lines: {malformed}")
        print(f"Alerts: {len(alerts)}")
        for alert in alerts:
            print(f"[{alert.severity.upper()}] {alert.rule}: {alert.message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
