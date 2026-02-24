# Configuration

`epack-tool-scan-secrets` works out of the box with sensible defaults, but can be customized for your environment.

## Tool Requirements

| Requirement | Value |
|-------------|-------|
| Requires Pack | Yes |
| Network Access | No |

## Configuration Options

All configuration options are optional. The tool uses sensible defaults when no configuration is provided.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entropy_threshold` | float | 4.5 | Minimum Shannon entropy (bits/char) to flag a string |
| `min_entropy_length` | int | 20 | Minimum string length for entropy checks |
| `ignore_paths` | []string | [] | Glob patterns for paths to skip |
| `disabled_detectors` | []string | [] | Detector types to disable |

### Available Detectors

The following detector types can be disabled via `disabled_detectors`:

| Detector | Description |
|----------|-------------|
| `aws_access_key` | AWS Access Key IDs (AKIA...) |
| `aws_secret_key` | AWS Secret Access Keys |
| `api_key` | Generic API key patterns |
| `github_token` | GitHub personal access tokens |
| `slack_token` | Slack API tokens |
| `private_key` | PEM-encoded private keys |
| `password` | Password assignment patterns |
| `jwt_token` | JSON Web Tokens |
| `connection_string` | Database connection URIs |
| `high_entropy` | High-entropy strings (encoded secrets) |

## Usage

### Via epack CLI

```bash
# Run with defaults
epack tool scan-secrets --pack ./my-evidence.epack

# Run with config file
epack tool scan-secrets --pack ./my-evidence.epack --config scan-config.json
```

### Via epack Build

Add to your build configuration to automatically scan during pack creation:

```yaml
# epack.yaml
tools:
  scan-secrets:
    source: locktivity/epack-tool-scan-secrets@v1
    config:
      entropy_threshold: 4.0
      ignore_paths:
        - "testdata/**"
        - "*.test.json"
      disabled_detectors:
        - high_entropy
```

## Configuration Examples

### Reduce False Positives

Lower the entropy threshold and ignore test fixtures:

```yaml
tools:
  scan-secrets:
    source: locktivity/epack-tool-scan-secrets@v1
    config:
      entropy_threshold: 5.0
      min_entropy_length: 30
      ignore_paths:
        - "testdata/**"
        - "fixtures/**"
        - "*.test.*"
```

### Focus on Specific Secrets

Disable detectors you don't need:

```yaml
tools:
  scan-secrets:
    source: locktivity/epack-tool-scan-secrets@v1
    config:
      disabled_detectors:
        - slack_token
        - high_entropy
```

### Increase Sensitivity

Lower thresholds to catch more potential secrets (may increase false positives):

```yaml
tools:
  scan-secrets:
    source: locktivity/epack-tool-scan-secrets@v1
    config:
      entropy_threshold: 3.5
      min_entropy_length: 16
```

## Output Files

| File | Description |
|------|-------------|
| `detections.json` | JSON file containing all secret detections |

## Warnings

The tool adds warnings to the pack's `result.json` for each detection:

```json
{
  "warnings": [
    {
      "code": "SECRET_DETECTED",
      "message": "aws_access_key: Possible AWS Access Key ID detected",
      "path": "config/credentials.json"
    }
  ]
}
```
