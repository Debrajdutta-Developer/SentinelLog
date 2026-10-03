# SentinelLog Architecture

```text
                    Authentication Telemetry
                             |
                +------------+------------+
                |                         |
          Normalized records         OpenSSH auth.log
                |                         |
                +------------+------------+
                             |
                         Parser
                             |
                         AuthEvent
                             |
                    Detection Engine
              +--------------+--------------+
              |              |              |
           AUTH-001       AUTH-002       AUTH-003
           same pair     source spray    success after
           failures                      failures
              |              |              |
              +--------------+--------------+
                             |
                       SecurityAlert
                             |
                    +--------+--------+
                    |                 |
                 CLI text           JSON
```

## Components

### Parser
Normalizes supported authentication records into a small immutable `AuthEvent` model. Current inputs are SentinelLog normalized records and common OpenSSH `sshd` authentication lines.

### Detection engine
Applies time-window correlation and produces `SecurityAlert` objects. Detection is deterministic for a supplied event set and does not perform active scanning or intrusion.

### CLI
Accepts a file path or stdin, selects an individual rule or all rules, and emits human-readable or JSON output.

### Tests and CI
The project uses pytest for regression coverage and GitHub Actions for automated testing across supported Python versions.
