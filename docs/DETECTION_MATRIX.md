# Detection Matrix

| Rule | Signal | Correlation | Default policy | Severity |
|---|---|---|---|---|
| AUTH-001 | Repeated failures against one account | source IP + username | 5 failures / 300s | medium |
| AUTH-002 | Repeated failures across accounts | source IP | configurable threshold / window | high |
| AUTH-003 | Success after repeated failures | source IP + username | correlated failure sequence followed by success | high |

## Interpretation

These rules identify suspicious authentication patterns. They do not establish attacker intent or compromise by themselves.

## Tuning considerations

Thresholds should be adapted to the environment. Service accounts, administrative jump hosts, automated systems, and noisy authentication sources can create legitimate patterns that require exclusions or different thresholds.
