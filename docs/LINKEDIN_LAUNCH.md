# SentinelLog LinkedIn Launch Kit

## Suggested post

I built SentinelLog, a Python-based defensive authentication monitoring tool that turns authentication telemetry into actionable security alerts.

The first detection rule, AUTH-001, identifies repeated failed authentication attempts by correlating source IP and username inside a configurable time window.

### What I built
- Authentication event parser
- Correlation-based detection engine
- Severity classification
- Structured JSON alerts
- CLI interface
- Unit tests and CI validation

### Why I built it
Security logs contain useful signals, but raw events are difficult to monitor consistently. SentinelLog explores a practical detection-engineering workflow: normalize telemetry, correlate events, generate an alert, and preserve enough context for investigation.

The project is intentionally defensive and designed for authorized systems, local labs, and security research.

GitHub: https://github.com/DebrajDutta-Developer/SentinelLog

#Cybersecurity #SecurityEngineering #DetectionEngineering #Python #SOC #BlueTeam #CyberDefense #SecurityAutomation