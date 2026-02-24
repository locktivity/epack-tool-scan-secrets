# Examples

## Basic Usage

Run the tool on an evidence pack:

```bash
epack tool scan-secrets --pack ./my-evidence.epack
```

## Interpreting Results

### Clean Scan

```json
{
  "total": 0,
  "by_type": {},
  "by_severity": {},
  "detections": []
}
```

No potential secrets were detected in the pack.

### Detections Found

```json
{
  "total": 2,
  "by_type": {
    "aws_access_key": 1,
    "password": 1
  },
  "by_severity": {
    "warning": 2
  },
  "detections": [
    {
      "path": "artifacts/config.json",
      "type": "aws_access_key",
      "description": "Possible AWS Access Key ID detected",
      "severity": "warning"
    },
    {
      "path": "artifacts/database.yml",
      "type": "password",
      "description": "Possible password pattern detected",
      "severity": "warning"
    }
  ]
}
```

## Common Detection Scenarios

### AWS Credentials

```
# Detected pattern
AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Private Keys

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds...
-----END RSA PRIVATE KEY-----
```

### JWT Tokens

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
```

### Connection Strings

```
mongodb://user:password@localhost:27017/mydb
postgres://admin:secret@db.example.com:5432/production
```

## Handling False Positives

If the tool flags legitimate values (e.g., test fixtures), you can:

1. **Document known false positives** in your pack metadata
2. **Use separate test data** that doesn't match secret patterns
3. **Review detections** as part of your pack validation process

## Integration with CI/CD

Run secret scanning as part of your evidence pack pipeline:

```yaml
# GitHub Actions example
- name: Scan for secrets
  run: |
    epack tool scan-secrets --pack ./evidence.epack
    # Check for warnings in result.json
    if jq -e '.warnings | length > 0' result.json > /dev/null; then
      echo "Warning: Potential secrets detected"
      jq '.warnings' result.json
    fi
```
