package main

// Output and warning values.
const (
	WarningCodeSecretDetected = "SECRET_DETECTED"
	DetectionsOutputFile      = "detections.json"
)

// Tool config keys.
const (
	ConfigEntropyThreshold  = "entropy_threshold"
	ConfigMinEntropyLength  = "min_entropy_length"
	ConfigIgnorePaths       = "ignore_paths"
	ConfigDisabledDetectors = "disabled_detectors"
)
