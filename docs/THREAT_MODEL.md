# Threat Model

## Scope

SentinelLog is a defensive log-analysis component. It consumes authentication telemetry and produces investigation signals.

## Assets

- Authentication telemetry
- Usernames and source IP addresses contained in logs
- Detection evidence and alert output

## Relevant scenarios

1. Repeated authentication failures against one account.
2. One source repeatedly targeting multiple accounts.
3. A successful login immediately following repeated failures.
4. Malformed or unsupported records entering the parser.

## Security controls in the project

- Input parsing fails closed for unsupported records.
- Detection windows are bounded and configurable.
- Alerts preserve evidence rather than only a boolean result.
- The project does not execute commands from log content.
- The project does not attempt authentication or exploitation.

## Important limitations

A detection is a signal, not proof of compromise. IP addresses can be shared, NAT can obscure the originating device, and legitimate automation can generate repeated failures. Production deployment should combine SentinelLog output with identity, endpoint, network, and application telemetry.

## Privacy

Logs can contain sensitive operational information. Operators should minimize retention, restrict access, and avoid committing real credentials, personal data, or production logs to source control.
