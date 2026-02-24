# epack-tool-scan-secrets

An epack tool that scans evidence pack artifacts for potential secrets and credentials.

Built with the [Component SDK](https://github.com/locktivity/epack).

See [docs/](docs/) for detailed documentation.

## Features

- **Pattern Detection**: Recognizes common secret formats:
  - AWS Access Keys and Secret Keys
  - GitHub tokens
  - Slack tokens
  - Private keys (RSA, EC, DSA, OpenSSH, PGP)
  - Passwords and secrets in config files
  - JWT tokens
  - Database connection strings

- **Entropy Analysis**: Detects high-entropy strings that may be encoded secrets

- **Best-Effort**: Heuristic-based detection with expected false positives/negatives

## Development

### Prerequisites

- Go 1.21+
- epack CLI (`go install github.com/locktivity/epack/cmd/epack@latest`)

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all
```

### SDK Development Workflow

Use the epack SDK commands for development:

```bash
# Run conformance tests (validates protocol compliance)
make sdk-test

# Run the tool with mock input
make sdk-run

# Or use epack directly
epack sdk test ./epack-tool-scan-secrets
epack sdk run ./epack-tool-scan-secrets
```

### Testing

```bash
make test
```

## Release

This project uses [SLSA Level 3](https://slsa.dev/spec/v1.0/levels#build-l3) builds for supply chain security.

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Action will:
1. Run tests and conformance checks
2. Build multi-platform binaries (linux/darwin, amd64/arm64)
3. Generate SLSA Level 3 provenance attestations
4. Publish to GitHub Releases with checksums

### Verifying Releases

Verify the SLSA provenance of downloaded binaries:

```bash
slsa-verifier verify-artifact epack-tool-scan-secrets-linux-amd64 \
  --provenance-path epack-tool-scan-secrets-linux-amd64.intoto.jsonl \
  --source-uri github.com/locktivity/epack-tool-scan-secrets
```

## License

Apache-2.0 - see [LICENSE](LICENSE)
