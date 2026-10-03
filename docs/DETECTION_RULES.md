# Detection Rules

SentinelLog currently ships with three defensive authentication correlation rules.

## AUTH-001 — Repeated Authentication Failures

**Purpose:** identify repeated failed authentication for the same `source_ip + username` pair.

**Default:** 5 failures inside 300 seconds.

**Severity:** `medium` at threshold; `high` at 2× threshold.

**Reset:** a successful authentication clears the active failure sequence for that pair.

## AUTH-002 — Password Spraying Signal

**Purpose:** identify a source generating repeated failures across multiple usernames.

**Default:** 5 failures inside 300 seconds and at least 2 distinct usernames.

**Severity:** `high`.

This is a detection signal, not proof of malicious intent. Analysts should validate the source, identities, and surrounding telemetry.

## AUTH-003 — Success After Repeated Failures

**Purpose:** highlight a successful authentication following repeated failures for the same source/user pair.

**Default:** 3 or more failures inside the configured window followed by success.

**Severity:** `high`.

This correlation is useful for investigation because a successful login after repeated failures can deserve additional review, but it does not by itself establish compromise.

## Design principles

- Correlate events instead of treating every failure as an incident.
- Keep thresholds configurable.
- Preserve evidence and timestamps.
- Generate deterministic, machine-readable output.
- Avoid claiming that a detection proves attacker activity.
