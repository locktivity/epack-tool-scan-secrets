package secrets

// DetectorType identifies a specific detection pattern.
type DetectorType string

// Severity identifies the severity level of a detection.
type Severity string

// Available detector types.
const (
	DetectorAWSAccessKey     DetectorType = "aws_access_key"
	DetectorAWSSecretKey     DetectorType = "aws_secret_key"
	DetectorAPIKey           DetectorType = "api_key"
	DetectorGitHubToken      DetectorType = "github_token"
	DetectorSlackToken       DetectorType = "slack_token"
	DetectorPrivateKey       DetectorType = "private_key"
	DetectorPassword         DetectorType = "password"
	DetectorJWTToken         DetectorType = "jwt_token"
	DetectorConnectionString DetectorType = "connection_string"
	DetectorHighEntropy      DetectorType = "high_entropy"
)

var allDetectors = []DetectorType{
	DetectorAWSAccessKey,
	DetectorAWSSecretKey,
	DetectorAPIKey,
	DetectorGitHubToken,
	DetectorSlackToken,
	DetectorPrivateKey,
	DetectorPassword,
	DetectorJWTToken,
	DetectorConnectionString,
	DetectorHighEntropy,
}

// AllDetectorTypes returns all available detector types.
func AllDetectorTypes() []DetectorType {
	out := make([]DetectorType, len(allDetectors))
	copy(out, allDetectors)
	return out
}

// Default detector settings.
const (
	DefaultEntropyThreshold = 4.5
	DefaultMinEntropyLength = 20
)

// Scan heuristics.
const BinaryScanSampleSize = 1024

// Entropy token parsing.
const (
	EntropyTokenPathSeparator = "/"
	EntropyTokenURLPrefix     = "http"
)

var entropyTokenDelimiters = map[rune]bool{
	' ':  true,
	'\n': true,
	'\r': true,
	'\t': true,
	'"':  true,
	'\'': true,
}

// Detection severities.
const (
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Detection descriptions.
const (
	DescriptionAWSAccessKey     = "Possible AWS Access Key ID detected"
	DescriptionAWSSecretKey     = "Possible AWS Secret Access Key detected"
	DescriptionAPIKey           = "Possible API key pattern detected"
	DescriptionGitHubToken      = "Possible GitHub token detected"
	DescriptionSlackToken       = "Possible Slack token detected"
	DescriptionPrivateKey       = "Private key detected"
	DescriptionPassword         = "Possible password pattern detected"
	DescriptionJWTToken         = "Possible JWT token detected"
	DescriptionConnectionString = "Possible database connection string detected"
	DescriptionHighEntropy      = "High-entropy string detected (possible encoded secret)"
)

// Entropy token prefixes that are intentionally ignored.
const (
	HashPrefixSHA256 = "sha256:"
	HashPrefixSHA1   = "sha1:"
)
