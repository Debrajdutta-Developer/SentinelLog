# Contributing to SentinelLog

Contributions are welcome when they improve defensive monitoring, detection quality, reliability, documentation, or test coverage.

## Before opening a change

1. Explain the security or engineering problem.
2. Keep examples synthetic and non-sensitive.
3. Add or update tests for behavior changes.
4. Update documentation when detection logic changes.
5. Do not add functionality intended for unauthorized access or credential attacks.

## Detection rules

New rules should document:
- rule identifier
- event prerequisites
- correlation key
- threshold/window
- severity rationale
- expected false-positive cases
- tests and sample telemetry

## Quality bar

Prefer small, reviewable changes. Avoid claiming that an alert proves compromise. Detection output should provide evidence that helps an authorized analyst investigate.