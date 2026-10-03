# SentinelLog Demo

This demo uses synthetic authentication telemetry only.

## Scenario

A source repeatedly fails authentication for the same account. The detector correlates the events and emits an AUTH-001 alert.

A second pattern demonstrates repeated failures against multiple usernames from one source, producing an AUTH-002 signal.

A third pattern demonstrates successful authentication after repeated failures, producing an AUTH-003 signal.

## Example workflow

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
sentinellog examples/auth.log
```

For machine-readable output:

```bash
sentinellog examples/auth.log --json
```

For a narrower policy:

```bash
sentinellog examples/auth.log --threshold 3 --window 120
```

## Expected investigation flow

```text
Raw event
   ↓
Parse + normalize
   ↓
Correlate
   ↓
Detection rule
   ↓
SecurityAlert
   ↓
Analyst investigation
```

The alerts are deliberately framed as signals. A repeated failure pattern can have benign explanations, so analysts should validate context before treating an alert as evidence of an incident.