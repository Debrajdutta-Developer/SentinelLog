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

The first detection correlates failed authentication events by `source_ip + username` inside a configurable time window. The default threshold is **5 failures within 300 seconds**.

The detector also resets the failure sequence after a successful authentication and ignores failures that fall outside the configured window.

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
│       └── parser.py
├── tests/
│   └── test_detector.py
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

Custom detection threshold and window:

```bash
sentinellog examples/auth.log --threshold 3 --window 120
```

## Development

Run tests with pytest:

```bash
pip install pytest
pytest
```

## Security model

SentinelLog is a monitoring and detection tool. It does not attempt unauthorized access, exploitation, credential attacks, or automated intrusion.

Use only telemetry from systems you own or are explicitly authorized to monitor.

## Roadmap

### Phase 1
- [x] Repository foundation
- [x] Python project structure
- [x] Authentication log parser
- [x] Failed-login detector
- [x] CLI interface
- [x] JSON alerts
- [x] Initial unit tests

### Phase 2
- [ ] Additional authentication formats
- [ ] Time-window correlation improvements
- [ ] Rule configuration
- [ ] Severity model
- [ ] Structured event schema
- [ ] Larger sample dataset

### Phase 3
- [ ] Real-time log streaming
- [ ] Alert persistence
- [ ] Web dashboard
- [ ] Security metrics

## License

MIT License
