# SentinelLog 🛡️

**SentinelLog** is a Python-based defensive authentication monitoring and detection-engineering project. It converts authentication telemetry into structured security signals that can support investigation and automation.

> Built for authorized systems, local labs, and defensive security research.

## Why SentinelLog?

Raw authentication logs contain useful security signals, but repeated failures are easy to miss when reviewed manually. SentinelLog provides a small, testable detection layer between raw telemetry and an analyst-facing alert.

```text
Authentication Telemetry
        ↓
      Parser
        ↓
    AuthEvent
        ↓
 Detection Engine
   ↙     ↓      ↘
AUTH-001 AUTH-002 AUTH-003
   \      |      /
      SecurityAlert
           ↓
       CLI / JSON
```

## Detection coverage

| Rule | Signal | Default | Severity |
|---|---|---:|---|
| **AUTH-001** | Repeated failures for the same source + user | 5 / 300s | Medium → High |
| **AUTH-002** | Repeated failures from one source across users | 5 / 300s, 2+ users | High |
| **AUTH-003** | Successful authentication after repeated failures | 3 / 300s | High |

These are investigation signals, not proof of compromise.

## Supported input

### SentinelLog normalized format

```text
2026-10-03T08:00:01Z user=alice ip=192.0.2.10 result=failed
```

### OpenSSH authentication logs

Common `sshd` records such as:

```text
Oct  3 08:00:01 lab sshd[1001]: Failed password for alice from 192.0.2.10 port 22 ssh2
```

The parser normalizes both into the same `AuthEvent` model.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run the synthetic normalized dataset:

```bash
sentinellog examples/auth.log
```

Run OpenSSH-style sample data:

```bash
sentinellog examples/sshd.log
```

JSON output:

```bash
sentinellog examples/auth.log --json
```

Run one specific rule:

```bash
sentinellog examples/auth.log --rule AUTH-001
sentinellog examples/auth.log --rule AUTH-002
sentinellog examples/auth.log --rule AUTH-003
```

Read telemetry from stdin:

```bash
cat examples/auth.log | sentinellog - --json
```

Tune the policy:

```bash
sentinellog examples/auth.log --threshold 3 --window 120
```

## Engineering highlights

- Immutable normalized event model
- Multiple input formats
- Bounded time-window correlation
- Three built-in detection rules
- Configurable thresholds
- Human-readable and JSON output
- Deterministic unit tests
- GitHub Actions CI across Python 3.11, 3.12 and 3.13
- No runtime dependencies outside the Python standard library

## Project structure

```text
SentinelLog/
├── examples/
│   ├── auth.log
│   └── sshd.log
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DETECTION_RULES.md
│   ├── LINKEDIN_LAUNCH.md
│   └── THREAT_MODEL.md
├── src/sentinellog/
│   ├── __init__.py
│   ├── cli.py
│   ├── detector.py
│   ├── events.py
│   └── parser.py
├── tests/
│   ├── test_detector.py
│   ├── test_rules.py
│   └── test_sentinellog.py
├── .github/workflows/ci.yml
├── LICENSE
├── pyproject.toml
└── README.md
```

## Testing

```bash
pip install -e .[test]
pytest -q
```

CI runs the test suite on Python 3.11, 3.12 and 3.13.

## Security boundaries

SentinelLog is a defensive monitoring component. It does not perform credential attacks, exploitation, unauthorized access, active scanning, or commands derived from log content.

Use only telemetry from systems you own or are explicitly authorized to monitor. Do not commit production logs, credentials, tokens, or unnecessary personal data.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for scope and limitations.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Detection Rules](docs/DETECTION_RULES.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [LinkedIn Launch Kit](docs/LINKEDIN_LAUNCH.md)

## Roadmap

### Completed in v0.3.0
- [x] Core authentication parser
- [x] OpenSSH log parsing
- [x] AUTH-001 repeated-failure detection
- [x] AUTH-002 password-spraying signal
- [x] AUTH-003 post-failure-success correlation
- [x] Configurable thresholds and time windows
- [x] CLI and stdin support
- [x] Structured JSON alerts
- [x] Unit tests and CI
- [x] Architecture, detection and threat-model documentation

### Future engineering work
- [ ] Stateful real-time tailing without re-reading the full file
- [ ] External rule configuration
- [ ] Alert persistence
- [ ] Pluggable output sinks
- [ ] Metrics and dashboard
- [ ] Additional authentication formats

## License

MIT License
