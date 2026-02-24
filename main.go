// epack-tool-scan-secrets scans evidence pack artifacts for potential secrets.
package main

import (
	"fmt"

	"github.com/locktivity/epack-tool-scan-secrets/internal/secrets"
	"github.com/locktivity/epack/componentsdk"
)

// Version is set by ldflags at build time.
var Version = "dev"

func main() {
	componentsdk.RunTool(componentsdk.ToolSpec{
		Name:         "scan-secrets",
		Version:      Version,
		Description:  "Scans evidence pack artifacts for potential secrets and credentials",
		RequiresPack: true,
		Network:      false,
	}, run)
}

func run(ctx componentsdk.ToolContext) error {
	pack := ctx.Pack()
	opts := parseConfig(ctx.Config())
	detector := secrets.NewDetectorWithOptions(opts)

	result := &ScanResult{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
		Detections: []DetectionResult{},
	}

	for _, artifact := range pack.Artifacts() {
		data, err := pack.ReadArtifact(artifact.Path)
		if err != nil {
			// Skip artifacts that can't be read
			continue
		}

		detections := detector.ScanBytes(artifact.Path, data)
		for _, d := range detections {
			result.Total++
			result.ByType[string(d.Type)]++
			result.BySeverity[string(d.Severity)]++
			result.Detections = append(result.Detections, DetectionResult{
				Path:        d.Path,
				Type:        string(d.Type),
				Description: d.Description,
				Severity:    string(d.Severity),
			})

			// Add warnings to result.json
			ctx.Warn(WarningCodeSecretDetected, fmt.Sprintf("%s: %s", d.Type, d.Description), d.Path)
		}
	}

	// Write detections output
	return ctx.WriteOutput(DetectionsOutputFile, result)
}

// ScanResult holds the aggregated scan results.
type ScanResult struct {
	Total      int               `json:"total"`
	ByType     map[string]int    `json:"by_type"`
	BySeverity map[string]int    `json:"by_severity"`
	Detections []DetectionResult `json:"detections"`
}

// DetectionResult is a single detection in the output.
type DetectionResult struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// parseConfig extracts detector options from the tool configuration.
func parseConfig(cfg map[string]any) secrets.Options {
	var opts secrets.Options

	if cfg == nil {
		return opts
	}

	if v, ok := cfg[ConfigEntropyThreshold].(float64); ok {
		opts.EntropyThreshold = v
	}

	if v, ok := cfg[ConfigMinEntropyLength].(float64); ok {
		opts.MinEntropyLength = int(v)
	}

	if v, ok := cfg[ConfigIgnorePaths].([]any); ok {
		for _, p := range v {
			if s, ok := p.(string); ok {
				opts.IgnorePaths = append(opts.IgnorePaths, s)
			}
		}
	}

	if v, ok := cfg[ConfigDisabledDetectors].([]any); ok {
		for _, d := range v {
			if s, ok := d.(string); ok {
				opts.DisabledDetectors = append(opts.DisabledDetectors, s)
			}
		}
	}

	return opts
}
