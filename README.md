# SentinelLog 🛡️

**SentinelLog** is a Python-based defensive security monitoring project that turns authentication telemetry into actionable security alerts.

> Built for authorized systems, local labs, and defensive security research.

## What it does

```text
Authentication Logs
        ↓
     Parser
        ↓
Detection Engine
        ↓
 Security Alert
        ↓
   CLI / JSON
```

### Current detection rule

**AUTH-001: Repeated Authentication Failures**

The detection engine correlates failed authentication events by `source_ip + username` inside a configurable time window. The default threshold is **5 failures within 300 seconds**.

The detector resets the failure sequence after a successful authentication and removes events that fall outside the configured window. Alerts include severity, evidence, timestamps, rule ID, and a human-readable message.

## Project structure

```text
SentinelLog/
├── examples/
│   └── auth.log
├── src/
│   └── sentinellog/
│       ├── __init__.py
│       ├── cli.py
│       ├── detector.py
│       ├── events.py
│       └── parser.py
├── tests/
│   └── test_sentinellog.py
├── .github/workflows/ci.yml
├── .gitignore
├── LICENSE
└── pyproject.toml
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run the sample telemetry:

```bash
sentinellog examples/auth.log
```

JSON output:

```bash
sentinellog examples/auth.log --json
```

Custom threshold and time window:

```bash
sentinellog examples/auth.log --threshold 3 --window 120
```

## Development

Install the test dependencies and run the full suite:

```bash
pip install -e .[test]
pytest -q
```

GitHub Actions runs the test suite against Python 3.11, 3.12, and 3.13.

## Security model

SentinelLog is a monitoring and detection tool. It does not attempt unauthorized access, exploitation, credential attacks, or automated intrusion.

Use only telemetry from systems you own or are explicitly authorized to monitor.

## Roadmap

### Phase 1: Core detector
- [x] Repository foundation
- [x] Python project structure
- [x] Authentication log parser
- [x] Failed-login detector
- [x] Configurable threshold and time window
- [x] CLI interface
- [x] JSON alerts
- [x] Unit tests
- [x] Structured security-event schema
- [x] CI test workflow

### Phase 2: Detection expansion
- [ ] Additional authentication formats
- [ ] Multiple detection rules
- [ ] Rule configuration file
- [ ] Source-level aggregation
- [ ] Successful-login-after-failures correlation

### Phase 3: Operations
- [ ] Real-time log streaming
- [ ] Alert persistence
- [ ] Web dashboard
- [ ] Security metrics

## License

MIT License
