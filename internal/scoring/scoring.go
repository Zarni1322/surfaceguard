// Package scoring provides risk scoring functionality for SurfaceGuard findings.
// The risk score combines multiple independent signals to produce a single
// 0-100 score that reflects the real-world risk of each vulnerability.
//
// Signals used:
//   - CVSS Base Score (NVD)
//   - EPSS Exploit Probability (Cyentia)
//   - CISA KEV Status (Known Exploited Vulnerabilities)
//   - Fingerprint Confidence (SurfaceGuard detection)
//   - Version Match Quality (Phase 2 version intelligence)
//   - NVD Version Range Validation (Phase 2)
package scoring

import (
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// SeverityFromCVSS returns a severity label derived from a CVSSv3 score.
// Uses the NVD standard thresholds.
func SeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "NONE"
	}
}

// CalculateRiskScore computes a composite risk score (0-100) from all available signals.
// This is an enhanced version of models.CalculateRiskScore that includes EPSS,
// KEV, fingerprint confidence, and version match quality.
func CalculateRiskScore(findings []models.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}

	totalScore := 0.0
	for _, f := range findings {
		totalScore += FindingRiskScore(f)
	}

	avg := totalScore / float64(len(findings))
	if avg > 100 {
		avg = 100
	}
	return avg
}

// FindingRiskScore computes a single finding's risk score (0-100).
func FindingRiskScore(finding models.Finding) float64 {
	score := 0.0

	// 1. CVSS base (0-10 scale → 0-50 points).
	cvss := 0.0
	if finding.CVE.CVSSv3 != nil {
		cvss = *finding.CVE.CVSSv3
	} else if finding.CVE.CVSSv2 != nil {
		cvss = *finding.CVE.CVSSv2
	}
	score += cvss * 5.0 // 0-50

	// 2. KEV: +25 for known exploited vulnerabilities.
	if finding.CVE.IsInKEV {
		score += 25
	}

	// 3. EPSS: up to +15 based on exploitation probability.
	if finding.CVE.EPSSScore != nil {
		epss := *finding.CVE.EPSSScore
		switch {
		case epss > 0.5:
			score += 15
		case epss > 0.1:
			score += 12
		case epss > 0.01:
			score += 8
		case epss > 0.001:
			score += 4
		default:
			score += 1
		}
	}

	// 4. Fingerprint confidence (0-10 points, scaled).
	score += float64(finding.MatchConfidence) * 0.1

	// 5. Version match quality.
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
	}

	// 6. NVD version range validation.
	if finding.VersionValidation == "not_affected" {
		score -= 30
	} else if finding.VersionValidation == "affected" {
		score += 5
	}

	// Clamp.
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}

// RiskLabel returns a human-readable risk label from a score.
func RiskLabel(score float64) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "NONE"
	}
}
