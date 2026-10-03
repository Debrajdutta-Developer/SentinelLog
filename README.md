# SentinelLog 🛡️

**SentinelLog** is a Python-based security log monitoring and detection project focused on identifying suspicious authentication activity from structured logs.

> Built for defensive security research, local labs, and learning.

## 🎯 Project Goal

Turn raw authentication events into useful security signals:

```text
Log Events → Parser → Detection Engine → Security Event → Alert
```

The first release focuses on authentication telemetry and repeated failed-login activity.

## Planned Detection Capabilities

- Failed-login threshold detection
- Repeated authentication failures from the same source
- Successful login after repeated failures
- Source/IP aggregation
- Time-window based detection
- Structured security alerts
- JSON output for automation
- Unit tests for detection logic

## Architecture

```text
                    ┌─────────────────┐
                    │ Authentication  │
                    │      Logs       │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │     Parser      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Detection Engine│
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Security Events │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Alert / JSON    │
                    └─────────────────┘
```

## Security Scope

SentinelLog is intended for systems and log data that you own or are explicitly authorized to monitor. It does not perform offensive access or exploitation.

## Roadmap

### Phase 1
- [x] Repository foundation
- [ ] Python project structure
- [ ] Log parser
- [ ] Failed-login detector
- [ ] CLI interface
- [ ] JSON alerts

### Phase 2
- [ ] Time-window correlation
- [ ] Detection rules
- [ ] Severity classification
- [ ] Test suite
- [ ] Sample security dataset

### Phase 3
- [ ] Real-time log streaming
- [ ] Alert persistence
- [ ] Web dashboard
- [ ] Security metrics

## License

MIT License
