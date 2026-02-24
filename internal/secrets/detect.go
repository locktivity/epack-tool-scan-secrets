// Package secrets detects likely credentials in artifact bytes using heuristics.
// It is best-effort only: false positives and false negatives are expected.
package secrets

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

// Options configures detector behavior.
type Options struct {
	// EntropyThreshold is the minimum Shannon entropy to flag a string.
	// Default is 4.5 bits per character.
	EntropyThreshold float64

	// MinEntropyLength is the minimum length for entropy checks.
	// Shorter strings can have high entropy by chance. Default is 20.
	MinEntropyLength int

	// IgnorePaths is a list of glob patterns to skip.
	// Patterns are matched against artifact paths using filepath.Match.
	IgnorePaths []string

	// DisabledDetectors lists detector types to disable.
	// Use detector type names: aws_access_key, api_key, high_entropy, etc.
	DisabledDetectors []string
}

// Detection describes one heuristic match in artifact content.
type Detection struct {
	Path        string // Artifact path
	Type        DetectorType
	Description string // Human-readable description
	Severity    Severity
}

// Detector scans artifact content for potential secrets.
type Detector struct {
	// MinEntropyThreshold is the minimum Shannon entropy to flag a string.
	// Default is 4.5 bits per character, which catches most high-entropy secrets.
	MinEntropyThreshold float64

	// MinHighEntropyLength is the minimum length for entropy checks.
	// Shorter strings can have high entropy by chance.
	MinHighEntropyLength int

	// ignorePaths holds compiled glob patterns to skip.
	ignorePaths []string

	// disabledDetectors is a set of disabled detector types.
	disabledDetectors map[DetectorType]struct{}
}

type detectorRule struct {
	detectorType DetectorType
	pattern      *regexp.Regexp
	description  string
	severity     Severity
}

// NewDetector creates a detector with default settings.
func NewDetector() *Detector {
	return NewDetectorWithOptions(Options{})
}

// NewDetectorWithOptions creates a detector with custom options.
func NewDetectorWithOptions(opts Options) *Detector {
	d := &Detector{
		MinEntropyThreshold:  opts.EntropyThreshold,
		MinHighEntropyLength: opts.MinEntropyLength,
		ignorePaths:          opts.IgnorePaths,
		disabledDetectors:    make(map[DetectorType]struct{}),
	}

	// Apply defaults
	if d.MinEntropyThreshold == 0 {
		d.MinEntropyThreshold = DefaultEntropyThreshold
	}
	if d.MinHighEntropyLength == 0 {
		d.MinHighEntropyLength = DefaultMinEntropyLength
	}

	// Build disabled detectors set
	for _, name := range opts.DisabledDetectors {
		d.disabledDetectors[DetectorType(name)] = struct{}{}
	}

	return d
}

// isDetectorEnabled returns true if the detector type is enabled.
func (d *Detector) isDetectorEnabled(t DetectorType) bool {
	_, disabled := d.disabledDetectors[t]
	return !disabled
}

// shouldIgnorePath returns true if the path matches any ignore pattern.
func (d *Detector) shouldIgnorePath(path string) bool {
	for _, pattern := range d.ignorePaths {
		// Try exact match first
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Also try matching just the filename for simple patterns
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

// Common secret patterns - compiled once for efficiency.
var (
	// API key patterns
	awsKeyPattern    = regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)
	awsSecretPattern = regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key["'\s:=]+[A-Za-z0-9/+=]{40}`)
	genericAPIKey    = regexp.MustCompile(`(?i)(api[_\-]?key|apikey|api_secret)["'\s:=]+[A-Za-z0-9_\-]{20,}`)
	githubToken      = regexp.MustCompile(`(?i)(ghp_[A-Za-z0-9]{36}|github[_\-]?token["'\s:=]+[A-Za-z0-9_\-]{35,})`)
	slackToken       = regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`)

	// Private key patterns
	privateKeyHeader = regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)

	// Password/secret patterns
	passwordPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret)["'\s:=]+[^\s"']{8,}`)

	// JWT pattern (three base64url segments)
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

	// Connection string patterns
	connectionString = regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s"']+`)
)

var detectorRules = []detectorRule{
	{
		detectorType: DetectorAWSAccessKey,
		pattern:      awsKeyPattern,
		description:  DescriptionAWSAccessKey,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorAWSSecretKey,
		pattern:      awsSecretPattern,
		description:  DescriptionAWSSecretKey,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorAPIKey,
		pattern:      genericAPIKey,
		description:  DescriptionAPIKey,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorGitHubToken,
		pattern:      githubToken,
		description:  DescriptionGitHubToken,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorSlackToken,
		pattern:      slackToken,
		description:  DescriptionSlackToken,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorPrivateKey,
		pattern:      privateKeyHeader,
		description:  DescriptionPrivateKey,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorPassword,
		pattern:      passwordPattern,
		description:  DescriptionPassword,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorJWTToken,
		pattern:      jwtPattern,
		description:  DescriptionJWTToken,
		severity:     SeverityWarning,
	},
	{
		detectorType: DetectorConnectionString,
		pattern:      connectionString,
		description:  DescriptionConnectionString,
		severity:     SeverityWarning,
	},
}

// ScanBytes returns heuristic detections for path/data.
// It skips likely-binary input and may return false positives.
func (d *Detector) ScanBytes(path string, data []byte) []Detection {
	if len(data) == 0 {
		return nil
	}

	// Check if path should be ignored
	if d.shouldIgnorePath(path) {
		return nil
	}

	if isLikelyBinary(data) {
		return nil
	}

	content := string(data)
	detections := d.scanPatternDetections(path, content)

	// Check for high-entropy strings (likely secrets)
	if d.isDetectorEnabled(DetectorHighEntropy) && d.hasHighEntropyStrings(content) {
		// Only add if no other detections (avoid duplicate warnings)
		if len(detections) == 0 {
			detections = append(detections, Detection{
				Path:        path,
				Type:        DetectorHighEntropy,
				Description: DescriptionHighEntropy,
				Severity:    SeverityInfo,
			})
		}
	}

	return detections
}

// hasHighEntropyStrings checks if the content contains high-entropy strings.
func (d *Detector) hasHighEntropyStrings(content string) bool {
	// Split content into words/tokens and check each
	// Look for base64-like strings that are long and high entropy
	tokens := strings.FieldsFunc(content, func(r rune) bool {
		return entropyTokenDelimiters[r]
	})

	for _, token := range tokens {
		if d.shouldSkipEntropyToken(token) {
			continue
		}

		if shannonEntropy(token) >= d.MinEntropyThreshold {
			return true
		}
	}

	return false
}

func (d *Detector) scanPatternDetections(path, content string) []Detection {
	var detections []Detection
	for _, rule := range detectorRules {
		if !d.isDetectorEnabled(rule.detectorType) || !rule.pattern.MatchString(content) {
			continue
		}
		detections = append(detections, Detection{
			Path:        path,
			Type:        rule.detectorType,
			Description: rule.description,
			Severity:    rule.severity,
		})
	}
	return detections
}

func isLikelyBinary(data []byte) bool {
	// Simple heuristic: null bytes in first 1KB usually indicate binary content.
	sampleSize := BinaryScanSampleSize
	if len(data) < sampleSize {
		sampleSize = len(data)
	}
	for i := 0; i < sampleSize; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func (d *Detector) shouldSkipEntropyToken(token string) bool {
	if len(token) < d.MinHighEntropyLength {
		return true
	}
	if strings.Contains(token, EntropyTokenPathSeparator) &&
		(strings.HasPrefix(token, EntropyTokenPathSeparator) || strings.HasPrefix(token, EntropyTokenURLPrefix)) {
		return true
	}
	lower := strings.ToLower(token)
	return strings.HasPrefix(lower, HashPrefixSHA256) || strings.HasPrefix(lower, HashPrefixSHA1)
}

// shannonEntropy returns per-rune Shannon entropy for s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
