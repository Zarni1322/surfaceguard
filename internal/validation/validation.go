// Package validation provides the finding validation pipeline for SurfaceGuard.
// Every detected CVE passes through validation before being reported.
//
// The validation pipeline assesses finding quality from multiple dimensions:
//   - Fingerprint confidence (how reliable is the service detection?)
//   - Version match result (does the detected version match the CVE?)
//   - NVD version range validation (is the version in the affected range?)
//   - Evidence quality (how strong is the product identification?)
//
// Weak findings are suppressed based on configurable thresholds.
// KEV findings and confirmed version matches are never suppressed.
package validation

import (
	"fmt"
	"log/slog"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// ConfidenceLevel represents the validation confidence for a finding.
type ConfidenceLevel int

const (
	ConfidenceUnknown   ConfidenceLevel = 0
	ConfidenceLow       ConfidenceLevel = 1
	ConfidenceMedium    ConfidenceLevel = 2
	ConfidenceHigh      ConfidenceLevel = 3
	ConfidenceVeryHigh  ConfidenceLevel = 4
)

func (c ConfidenceLevel) String() string {
	switch c {
	case ConfidenceVeryHigh:
		return "Very High"
	case ConfidenceHigh:
		return "High"
	case ConfidenceMedium:
		return "Medium"
	case ConfidenceLow:
		return "Low"
	default:
		return "Unknown"
	}
}

// PriorityLevel represents the overall priority for a finding.
type PriorityLevel int

const (
	PriorityNone          PriorityLevel = 0
	PriorityInformational PriorityLevel = 1
	PriorityLow           PriorityLevel = 2
	PriorityMedium        PriorityLevel = 3
	PriorityHigh          PriorityLevel = 4
	PriorityCritical      PriorityLevel = 5
)

func (p PriorityLevel) String() string {
	switch p {
	case PriorityCritical:
		return "CRITICAL"
	case PriorityHigh:
		return "HIGH"
	case PriorityMedium:
		return "MEDIUM"
	case PriorityLow:
		return "LOW"
	case PriorityInformational:
		return "INFORMATIONAL"
	default:
		return "NONE"
	}
}

// ValidationResult holds the complete validation output for one finding.
type ValidationResult struct {
	// Confidence is the overall finding confidence level.
	Confidence ConfidenceLevel `json:"confidence"`
	// Priority is the overall finding priority.
	Priority PriorityLevel `json:"priority"`
	// RiskScore is the computed risk score (0-100).
	RiskScore float64 `json:"risk_score"`
	// Suppressed is true if this finding should be suppressed.
	Suppressed bool `json:"suppressed"`
	// SuppressionReason describes why the finding was suppressed.
	SuppressionReason string `json:"suppression_reason,omitempty"`
	// EvidenceSummary describes the reasoning behind the validation.
	EvidenceSummary string `json:"evidence_summary"`
}

// Options configures the validation pipeline thresholds.
type Options struct {
	// MinFingerprintConfidence suppresses findings below this fingerprint confidence (0-100).
	MinFingerprintConfidence int
	// MinEvidenceScore suppresses findings below this evidence quality score (0-100).
	MinEvidenceScore int
	// SuppressUnknownVersion suppresses findings with no detected version.
	SuppressUnknownVersion bool
	// SuppressVersionMismatch suppresses findings where version doesn't match the CVE.
	SuppressVersionMismatch bool
}

// DefaultOptions returns sensible default validation thresholds.
func DefaultOptions() Options {
	return Options{
		MinFingerprintConfidence: 0,   // Don't suppress by fingerprint alone
		MinEvidenceScore:         0,   // Don't suppress by evidence alone
		SuppressUnknownVersion:   false,
		SuppressVersionMismatch:  true, // Suppress findings where version is confirmed not affected
	}
}

// Validate processes a single finding through the validation pipeline.
// It computes confidence, priority, risk score, and determines whether
// the finding should be suppressed.
func Validate(finding models.Finding, opts Options) ValidationResult {
	result := ValidationResult{}

	// Stage 1: Compute finding confidence from multiple signals.
	result.Confidence = computeConfidence(finding)

	// Stage 2: Compute risk score (combines CVSS, EPSS, KEV, confidence).
	result.RiskScore = computeRiskScore(finding, result.Confidence)

	// Stage 3: Compute overall priority.
	result.Priority = computePriority(finding, result.RiskScore, result.Confidence)

	// Stage 4: Check suppression conditions.
	result.Suppressed, result.SuppressionReason = checkSuppression(finding, opts)

	// Stage 5: Build evidence summary.
	result.EvidenceSummary = buildEvidenceSummary(finding, result)

	return result
}

// computeConfidence assesses the finding confidence from all available signals.
func computeConfidence(finding models.Finding) ConfidenceLevel {
	score := 0

	// 1. Fingerprint confidence (0-100 → contributes up to 30 points).
	fpConf := finding.MatchConfidence
	if fpConf >= 90 {
		score += 30
	} else if fpConf >= 70 {
		score += 20
	} else if fpConf >= 50 {
		score += 10
	}

	// 2. Version match result (contributes up to 30 points).
	switch finding.VersionMatchResult {
	case "exact_version":
		score += 30
	case "version_range_match":
		score += 30
	case "nearby_version":
		score += 20
	case "db_version_match":
		score += 20
	case "unknown_version":
		score += 5
	case "version_mismatch":
		score -= 10
	}

	// 3. NVD version range validation (contributes up to 20 points).
	switch finding.VersionValidation {
	case "affected":
		score += 20
	case "not_affected":
		score -= 20
	case "unknown":
		score += 5
	}

	// 4. KEV bonus (finding is confirmed exploited in the wild).
	if finding.CVE.IsInKEV {
		score += 15
	}

	// 5. EPSS bonus (high probability of exploitation).
	if finding.CVE.EPSSScore != nil && *finding.CVE.EPSSScore > 0.1 {
		score += 10
	} else if finding.CVE.EPSSScore != nil && *finding.CVE.EPSSScore > 0.01 {
		score += 5
	}

	// Map score to confidence level.
	switch {
	case score >= 70:
		return ConfidenceVeryHigh
	case score >= 50:
		return ConfidenceHigh
	case score >= 30:
		return ConfidenceMedium
	case score >= 10:
		return ConfidenceLow
	default:
		return ConfidenceUnknown
	}
}

// computeRiskScore calculates a composite risk score from CVSS, EPSS, KEV,
// fingerprint confidence, and version match quality.
func computeRiskScore(finding models.Finding, conf ConfidenceLevel) float64 {
	// Base score from CVSS (0-10 scale, normalized to 0-50).
	cvssScore := 0.0
	if finding.CVE.CVSSv3 != nil {
		cvssScore = *finding.CVE.CVSSv3 * 5.0 // 0-50
	} else if finding.CVE.CVSSv2 != nil {
		cvssScore = *finding.CVE.CVSSv2 * 5.0
	}

	score := cvssScore

	// KEV multiplier: +25 for confirmed exploited in the wild.
	if finding.CVE.IsInKEV {
		score += 25
	}

	// EPSS contribution: up to +15 based on probability.
	if finding.CVE.EPSSScore != nil {
		epssContribution := *finding.CVE.EPSSScore * 15.0
		if epssContribution > 15 {
			epssContribution = 15
		}
		score += epssContribution
	}

	// Fingerprint confidence contribution (0-10).
	fpConf := finding.MatchConfidence
	score += float64(fpConf) * 0.1

	// Version match bonus/penalty.
	switch finding.VersionMatchResult {
	case "exact_version":
		score += 10
	case "version_range_match":
		score += 10
	case "nearby_version":
		score += 5
	case "db_version_match":
		score += 5
	case "version_mismatch":
		score -= 20
	case "unknown_version":
		// no change
	}

	// Version validation penalty.
	if finding.VersionValidation == "not_affected" {
		score -= 30
	}

	// Clamp to 0-100.
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// computePriority determines the final priority from risk score, confidence, and CVSS.
func computePriority(finding models.Finding, riskScore float64, conf ConfidenceLevel) PriorityLevel {
	// Override: KEV + confirmed version match = always CRITICAL.
	if finding.CVE.IsInKEV && (finding.VersionMatchResult == "exact_version" ||
		finding.VersionMatchResult == "version_range_match") {
		return PriorityCritical
	}

	// Override: KEV + affected validation = always HIGH at minimum.
	if finding.CVE.IsInKEV && finding.VersionValidation == "affected" {
		if riskScore >= 70 {
			return PriorityCritical
		}
		return PriorityHigh
	}

	// Score-based priority.
	switch {
	case riskScore >= 80:
		return PriorityCritical
	case riskScore >= 60:
		return PriorityHigh
	case riskScore >= 40:
		return PriorityMedium
	case riskScore >= 20:
		return PriorityLow
	default:
		if finding.CVE.IsInKEV {
			return PriorityMedium // KEV always at least MEDIUM
		}
		return PriorityInformational
	}
}

// checkSuppression determines if a finding should be suppressed.
// Returns true with a reason if suppression is needed.
func checkSuppression(finding models.Finding, opts Options) (bool, string) {
	// Never suppress KEV findings.
	if finding.CVE.IsInKEV {
		return false, ""
	}

	// Never suppress confirmed version matches.
	if finding.VersionMatchResult == "exact_version" ||
		finding.VersionMatchResult == "version_range_match" {
		return false, ""
	}

	// Suppress version mismatch (confirmed not affected).
	if opts.SuppressVersionMismatch && finding.VersionValidation == "not_affected" {
		slog.Debug("suppressing finding — version mismatch",
			"cve", finding.CVE.ID,
			"detected_version", finding.DetectedVersion,
		)
		return true, fmt.Sprintf("Version mismatch: detected %s is not affected by %s",
			finding.DetectedVersion, finding.CVE.ID)
	}

	// Suppress version mismatch from version match result.
	if opts.SuppressVersionMismatch && finding.VersionMatchResult == "version_mismatch" {
		slog.Debug("suppressing finding — version match result mismatch",
			"cve", finding.CVE.ID,
			"detected_version", finding.DetectedVersion,
		)
		return true, fmt.Sprintf("Version mismatch: detected %s does not match CVE version requirements",
			finding.DetectedVersion)
	}

	// Suppress low fingerprint confidence (below minimum threshold).
	if opts.MinFingerprintConfidence > 0 &&
		finding.MatchConfidence < opts.MinFingerprintConfidence {
		slog.Debug("suppressing finding — low fingerprint confidence",
			"cve", finding.CVE.ID,
			"confidence", finding.MatchConfidence,
			"threshold", opts.MinFingerprintConfidence,
		)
		return true, fmt.Sprintf("Low fingerprint confidence: %d (minimum: %d)",
			finding.MatchConfidence, opts.MinFingerprintConfidence)
	}

	return false, ""
}

// buildEvidenceSummary creates a human-readable summary of the validation reasoning.
func buildEvidenceSummary(finding models.Finding, result ValidationResult) string {
	parts := []string{}

	if finding.DetectedVersion != "" {
		parts = append(parts, fmt.Sprintf("version=%s", finding.DetectedVersion))
	}

	if finding.VersionValidation != "" {
		parts = append(parts, fmt.Sprintf("validation=%s", finding.VersionValidation))
	}

	if finding.VersionMatchResult != "" {
		parts = append(parts, fmt.Sprintf("match=%s", finding.VersionMatchResult))
	}

	parts = append(parts, fmt.Sprintf("fp_confidence=%d", finding.MatchConfidence))

	if finding.CVE.IsInKEV {
		parts = append(parts, "kev=yes")
	}

	if finding.CVE.EPSSScore != nil {
		parts = append(parts, fmt.Sprintf("epss=%.4f", *finding.CVE.EPSSScore))
	}

	return fmt.Sprintf("confidence=%s priority=%s risk=%.0f reason=[%s]",
		result.Confidence.String(),
		result.Priority.String(),
		result.RiskScore,
		joinParts(parts),
	)
}

func joinParts(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += " "
		}
		result += p
	}
	return result
}

// ValidateAll processes all findings through the validation pipeline.
// Returns validated findings (non-suppressed) and the list of suppressed findings.
func ValidateAll(findings []models.Finding, opts Options) (validated []models.Finding, suppressed []models.Finding) {
	for _, f := range findings {
		result := Validate(f, opts)
		if result.Suppressed {
			suppressed = append(suppressed, f)
			slog.Debug("finding suppressed",
				"cve", f.CVE.ID,
				"reason", result.SuppressionReason,
			)
		} else {
			validated = append(validated, f)
		}
	}
	return validated, suppressed
}
