package secrets

import (
	"testing"
)

func TestDetector_ScanBytes(t *testing.T) {
	detector := NewDetector()
	slackTokenFixture := "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "abcdefghijklmnopqrstuvwx"

	tests := []struct {
		name           string
		path           string
		content        string
		wantDetections int
		wantTypes      []DetectorType
	}{
		{
			name:           "empty content",
			path:           "artifacts/empty.txt",
			content:        "",
			wantDetections: 0,
		},
		{
			name:           "normal text",
			path:           "artifacts/readme.txt",
			content:        "This is a normal text file with no secrets.",
			wantDetections: 0,
		},
		{
			name:           "AWS access key",
			path:           "artifacts/config.json",
			content:        `{"aws_key": "AKIAIOSFODNN7EXAMPLE"}`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorAWSAccessKey},
		},
		{
			name:           "AWS secret key",
			path:           "artifacts/env",
			content:        `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorAWSSecretKey},
		},
		{
			name:           "GitHub token",
			path:           "artifacts/token.txt",
			content:        `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorGitHubToken},
		},
		{
			name:           "private key",
			path:           "artifacts/key.pem",
			content:        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...",
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorPrivateKey},
		},
		{
			name:           "JWT token",
			path:           "artifacts/auth.json",
			content:        `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorJWTToken},
		},
		{
			name:           "password pattern",
			path:           "artifacts/config.yaml",
			content:        `password: "supersecretpassword123"`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorPassword},
		},
		{
			name:           "connection string",
			path:           "artifacts/db.conf",
			content:        `DATABASE_URL=postgres://user:password@localhost:5432/mydb`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorConnectionString},
		},
		{
			name:           "API key pattern",
			path:           "artifacts/settings.json",
			content:        `{"api_key": "sk_test_abcdefghijklmnopqrstuvwxyz"}`,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorAPIKey},
		},
		{
			name:           "Slack token",
			path:           "artifacts/slack.txt",
			content:        slackTokenFixture,
			wantDetections: 1,
			wantTypes:      []DetectorType{DetectorSlackToken},
		},
		{
			name:           "SHA256 digest should not trigger",
			path:           "artifacts/manifest.json",
			content:        `sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789`,
			wantDetections: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detections := detector.ScanBytes(tt.path, []byte(tt.content))

			if len(detections) != tt.wantDetections {
				t.Errorf("ScanBytes() got %d detections, want %d", len(detections), tt.wantDetections)
				for _, d := range detections {
					t.Logf("  detection: type=%s desc=%s", d.Type, d.Description)
				}
			}

			if len(tt.wantTypes) > 0 {
				for i, wantType := range tt.wantTypes {
					if i >= len(detections) {
						t.Errorf("missing expected detection type %s", wantType)
						continue
					}
					if detections[i].Type != wantType {
						t.Errorf("detection[%d].Type = %s, want %s", i, detections[i].Type, wantType)
					}
				}
			}
		})
	}
}

func TestDetector_SkipsBinaryFiles(t *testing.T) {
	detector := NewDetector()

	// Create content with null bytes (binary file indicator)
	binaryContent := []byte("some text\x00more text with AKIAIOSFODNN7EXAMPLE")

	detections := detector.ScanBytes("artifacts/binary.exe", binaryContent)

	if len(detections) != 0 {
		t.Errorf("expected no detections for binary file, got %d", len(detections))
	}
}

func TestShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		wantHigh bool // entropy > 3.5 (threshold for "high" entropy)
	}{
		{input: "", wantHigh: false},
		{input: "aaaaaaaaaa", wantHigh: false},       // Low entropy (repetitive)
		{input: "password123", wantHigh: false},      // Low entropy (common pattern)
		{input: "abcdefghij", wantHigh: false},       // Low entropy (sequential)
		{input: "wJalrXUtnFEMI", wantHigh: true},     // High entropy (random-looking)
		{input: "Kj3hF9xL2mN8pQ", wantHigh: true},    // High entropy (mixed case/digits)
		{input: "aB3xY9kL2mN8pQwJf", wantHigh: true}, // Longer high entropy
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			entropy := shannonEntropy(tt.input)
			isHigh := entropy > 3.5 // Lower threshold for test clarity

			if isHigh != tt.wantHigh {
				t.Errorf("shannonEntropy(%q) = %.2f, high=%v, want high=%v",
					tt.input, entropy, isHigh, tt.wantHigh)
			}
		})
	}
}

func TestDetector_MultiplePatterns(t *testing.T) {
	detector := NewDetector()

	// Content with multiple secrets
	content := `
config:
  aws_key: AKIAIOSFODNN7EXAMPLE
  password: "mysecretpassword"
  jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.sig
`
	detections := detector.ScanBytes("artifacts/multi.yaml", []byte(content))

	// Should detect at least 3 patterns
	if len(detections) < 3 {
		t.Errorf("expected at least 3 detections, got %d", len(detections))
		for _, d := range detections {
			t.Logf("  detection: type=%s", d.Type)
		}
	}

	// Check that types are present
	types := make(map[DetectorType]bool)
	for _, d := range detections {
		types[d.Type] = true
	}

	expected := []DetectorType{DetectorAWSAccessKey, DetectorPassword, DetectorJWTToken}
	for _, e := range expected {
		if !types[e] {
			t.Errorf("missing expected detection type: %s", e)
		}
	}
}

func TestDetector_LongHighEntropyString(t *testing.T) {
	detector := NewDetector()
	// Lower threshold for testing
	detector.MinEntropyThreshold = 3.5

	// A truly random-looking high-entropy string
	// Base64-encoded random bytes have high entropy
	highEntropySecret := "aB3xY9kL2mN8pQwJf7rT5sU1vX4zC6bD0eF2gH8iK"

	content := `secret_data: "` + highEntropySecret + `"`
	detections := detector.ScanBytes("artifacts/data.json", []byte(content))

	// Should detect the high entropy string
	foundHighEntropy := false
	for _, d := range detections {
		if d.Type == DetectorHighEntropy {
			foundHighEntropy = true
			break
		}
	}

	if !foundHighEntropy {
		// Log the entropy value for debugging
		entropy := shannonEntropy(highEntropySecret)
		t.Errorf("expected high_entropy detection for long random string (entropy=%.2f, threshold=%.2f)",
			entropy, detector.MinEntropyThreshold)
	}
}

func TestDetectorWithOptions_EntropyThreshold(t *testing.T) {
	// High threshold should miss some detections
	detector := NewDetectorWithOptions(Options{
		EntropyThreshold: 6.0, // Very high threshold
	})

	content := "random_data: aB3xY9kL2mN8pQwJf7rT5sU1"
	detections := detector.ScanBytes("test.txt", []byte(content))

	for _, d := range detections {
		if d.Type == DetectorHighEntropy {
			t.Error("expected no high_entropy detection with high threshold")
		}
	}

	// Low threshold should catch more
	detectorLow := NewDetectorWithOptions(Options{
		EntropyThreshold: 3.0,
	})

	detectionsLow := detectorLow.ScanBytes("test.txt", []byte(content))
	foundHighEntropy := false
	for _, d := range detectionsLow {
		if d.Type == DetectorHighEntropy {
			foundHighEntropy = true
			break
		}
	}

	if !foundHighEntropy {
		t.Error("expected high_entropy detection with low threshold")
	}
}

func TestDetectorWithOptions_IgnorePaths(t *testing.T) {
	detector := NewDetectorWithOptions(Options{
		IgnorePaths: []string{
			"testdata/*",
			"*.test.json",
			"vendor/**",
		},
	})

	awsKey := `{"key": "AKIAIOSFODNN7EXAMPLE"}`

	tests := []struct {
		path           string
		wantDetections int
	}{
		{"config/prod.json", 1},      // Should detect
		{"testdata/fixture.json", 0}, // Should ignore
		{"api.test.json", 0},         // Should ignore
		{"src/main.go", 1},           // Should detect
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			detections := detector.ScanBytes(tt.path, []byte(awsKey))
			if len(detections) != tt.wantDetections {
				t.Errorf("ScanBytes(%q) got %d detections, want %d", tt.path, len(detections), tt.wantDetections)
			}
		})
	}
}

func TestDetectorWithOptions_DisabledDetectors(t *testing.T) {
	detector := NewDetectorWithOptions(Options{
		DisabledDetectors: []string{string(DetectorAWSAccessKey), string(DetectorPassword)},
	})

	content := `
config:
  aws_key: AKIAIOSFODNN7EXAMPLE
  password: "supersecretpassword"
  token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
`
	detections := detector.ScanBytes("config.yaml", []byte(content))

	// Should only detect github_token, not aws_access_key or password
	for _, d := range detections {
		if d.Type == DetectorAWSAccessKey {
			t.Error("aws_access_key should be disabled")
		}
		if d.Type == DetectorPassword {
			t.Error("password should be disabled")
		}
	}

	// Should still detect github_token
	found := false
	for _, d := range detections {
		if d.Type == DetectorGitHubToken {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected github_token detection (not disabled)")
	}
}

func TestDetectorWithOptions_Defaults(t *testing.T) {
	// Empty options should use defaults
	detector := NewDetectorWithOptions(Options{})

	if detector.MinEntropyThreshold != DefaultEntropyThreshold {
		t.Errorf("default MinEntropyThreshold = %v, want %v", detector.MinEntropyThreshold, DefaultEntropyThreshold)
	}
	if detector.MinHighEntropyLength != DefaultMinEntropyLength {
		t.Errorf("default MinHighEntropyLength = %v, want %v", detector.MinHighEntropyLength, DefaultMinEntropyLength)
	}
}

func TestAllDetectorsConstant(t *testing.T) {
	// Verify AllDetectorTypes has all detector types.
	detectors := AllDetectorTypes()
	expected := 10
	if len(detectors) != expected {
		t.Errorf("AllDetectorTypes has %d entries, want %d", len(detectors), expected)
	}
}
