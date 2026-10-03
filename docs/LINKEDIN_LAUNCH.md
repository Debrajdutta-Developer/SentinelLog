# SentinelLog LinkedIn Launch Kit

## Suggested post

I built **SentinelLog**, a Python-based defensive authentication monitoring and detection-engineering project.

Instead of treating every failed login as an isolated event, SentinelLog correlates authentication telemetry and turns repeated patterns into structured security signals.

### What I built

- Normalized authentication event model
- OpenSSH `sshd` log parsing
- **AUTH-001:** repeated failures for the same source + user
- **AUTH-002:** repeated failures across multiple usernames from one source
- **AUTH-003:** successful authentication after repeated failures
- Configurable thresholds and time windows
- Human-readable and JSON alerts
- CLI + stdin support
- Unit tests and GitHub Actions CI
- Architecture and threat-model documentation

### Why I built it

Security logs contain useful signals, but raw events are difficult to monitor consistently. SentinelLog explores a practical detection-engineering workflow:

**parse → normalize → correlate → alert → investigate**

The project is intentionally defensive and designed for authorized systems, local labs, and security research. A detection is treated as an investigation signal, not automatic proof of compromise.

GitHub: https://github.com/DebrajDutta-Developer/SentinelLog

#Cybersecurity #SecurityEngineering #DetectionEngineering #Python #SOC #BlueTeam #CyberDefense #SecurityAutomation