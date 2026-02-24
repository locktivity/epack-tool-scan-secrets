# Overview

`epack-tool-scan-secrets` is an epack tool that scans evidence pack artifacts for potential secrets and credentials. It uses pattern matching and entropy analysis to identify likely sensitive data.

## How It Works

The tool scans all artifacts in an evidence pack and checks for:

1. **Known Secret Patterns**: Regular expressions that match common credential formats
2. **High-Entropy Strings**: Strings with Shannon entropy ≥ 4.5 bits/character (indicating likely encoded secrets)

The tool works out of the box with sensible defaults, but detection sensitivity and scope can be customized via configuration. See [configuration.md](configuration.md) for details.

## Detected Secret Types

| Type | Description |
|------|-------------|
| `aws_access_key` | AWS Access Key ID (AKIA...) |
| `aws_secret_key` | AWS Secret Access Key |
| `api_key` | Generic API key patterns |
| `github_token` | GitHub personal access tokens |
| `slack_token` | Slack API tokens |
| `private_key` | RSA, EC, DSA, OpenSSH, or PGP private keys |
| `password` | Password/secret patterns in config files |
| `jwt_token` | JSON Web Tokens |
| `connection_string` | Database connection strings (MongoDB, PostgreSQL, MySQL, Redis, AMQP) |
| `high_entropy` | High-entropy strings that may be encoded secrets |

## Output

The tool outputs a `detections.json` file containing:

```json
{
  "total": 3,
  "by_type": {
    "aws_access_key": 1,
    "private_key": 2
  },
  "by_severity": {
    "warning": 3
  },
  "detections": [
    {
      "path": "config/credentials.json",
      "type": "aws_access_key",
      "description": "Possible AWS Access Key ID detected",
      "severity": "warning"
    }
  ]
}
```

## Limitations

This tool uses heuristics and is best-effort only:

- **False positives**: Some legitimate data may be flagged (e.g., test fixtures, example values). Use `ignore_paths` to exclude known false positive sources.
- **False negatives**: Some secrets may not be detected (e.g., custom formats, obfuscated values)
- **Binary files**: Skipped automatically (detected by null bytes)

Use this tool as one layer of defense, not as the sole method for secret detection.
