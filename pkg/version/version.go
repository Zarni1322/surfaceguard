// Package version provides a semantic version comparison engine for
// NVD CVE version range validation. It is independent from the CVE matcher
// and reusable by authenticated assessment, package detection, patch
// validation, and any other component that needs to compare software versions.
//
// Design:
//   - Parses versions into a structured numeric/suffix representation.
//   - Compares numerically where possible, lexicographically for suffixes.
//   - Handles vendor-specific formats (ubuntu, el, r, etc.) gracefully.
//   - Unknown or unparsable versions NEVER return "confirmed vulnerable".
//   - Thread-safe — all operations are read-only after construction.
//
// Supported formats (parsed numerically):
//   "1.2"         → {1, 2}
//   "1.2.3"       → {1, 2, 3}
//   "1.2.3.4"     → {1, 2, 3, 4}
//   "2.4.58"      → {2, 4, 58}
//   "9.8p1"       → {9, 8} suffix "p1"
//   "10.11"       → {10, 11}
//   "11.0.2"      → {11, 0, 2}
//   "1.2.3-ubuntu" → {1, 2, 3} suffix "-ubuntu"
//   "1.2.3.el8"   → {1, 2, 3} suffix "el8"
//   "1.2.3-r0"    → {1, 2, 3} suffix "r0"
//   "1.2.3a"      → {1, 2, 3} suffix "a"
//   "1.2.3_rc1"   → {1, 2, 3} suffix "_rc1"
//   "*"           → wildcard (matches anything)
//   ""            → unknown (never confirms vulnerable)
package version

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version with numeric segments
// and an optional suffix for pre-release / vendor-specific variants.
type Version struct {
	// Segments holds the numeric parts (e.g. [2, 4, 58] for "2.4.58").
	Segments []int
	// Suffix is the non-numeric trailing text (e.g. "p1", "-ubuntu", "el8").
	Suffix string
	// Raw is the original version string as provided.
	Raw string
	// Wildcard is true when the version is "*".
	Wildcard bool
	// Unknown is true when the version could not be parsed.
	Unknown bool
}

// String returns the human-readable version string.
func (v Version) String() string {
	if v.Wildcard {
		return "*"
	}
	if v.Unknown {
		return v.Raw
	}
	parts := make([]string, len(v.Segments))
	for i, s := range v.Segments {
		parts[i] = strconv.Itoa(s)
	}
	return strings.Join(parts, ".") + v.Suffix
}

// ============================================================================
// Parsing
// ============================================================================

// Parse parses a version string into a structured Version.
// Returns {Unknown: true} for unparsable input.
func Parse(raw string) Version {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Version{Raw: raw, Unknown: true}
	}
	if raw == "*" {
		return Version{Raw: raw, Wildcard: true}
	}

	// Separate the numeric part from any trailing non-numeric suffix.
	// The suffix starts at the first non-numeric, non-dot character
	// after the last numeric segment.
	// e.g. "9.8p1" → numeric="9.8", suffix="p1"
	// e.g. "8.0.36-log" → numeric="8.0.36", suffix="-log"
	numStr, suffix := splitNumericSuffix(raw)

	if numStr == "" {
		return Version{Raw: raw, Unknown: true}
	}

	segments := parseNumericSegments(numStr)
	if len(segments) == 0 {
		return Version{Raw: raw, Unknown: true}
	}

	return Version{
		Segments: segments,
		Suffix:   suffix,
		Raw:      raw,
	}
}

// splitNumericSuffix separates a version string into its numeric prefix
// and trailing non-numeric suffix.
func splitNumericSuffix(s string) (numeric, suffix string) {
	if s == "" {
		return "", ""
	}
	// Scan forwards to find where the suffix starts.
	// The suffix is the first character after a complete numeric segment
	// that is not a digit or a dot between digits.
	// e.g. "9.8p1" → numeric="9.8", suffix="p1"
	// e.g. "1.2.3-ubuntu" → numeric="1.2.3", suffix="-ubuntu"
	// e.g. "1.2.3.el8" → numeric="1.2.3", suffix=".el8"
	// e.g. "8.0.36-log" → numeric="8.0.36", suffix="-log"
	suffixStart := len(s)
	for i := 0; i < len(s); i++ {
		r := s[i]
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '.' {
			// Only consume a dot if it has a digit after it.
			if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
				continue
			}
			// Trailing dot or dot before suffix — it's part of the suffix.
			suffixStart = i
			break
		}
		// First non-digit, non-dot character.
		// Only treat it as a suffix if there's at least one digit before it.
		hasDigit := false
		for j := i - 1; j >= 0; j-- {
			if s[j] >= '0' && s[j] <= '9' {
				hasDigit = true
				break
			}
		}
		if hasDigit {
			suffixStart = i
		}
		break
	}

	numeric = s[:suffixStart]
	suffix = s[suffixStart:]

	// Clean up: if there's a dot at the end of the numeric part, remove it.
	numeric = strings.TrimRight(numeric, ".")

	if numeric == "" {
		return "", ""
	}

	// Validate that the numeric part only contains digits and dots.
	for _, r := range numeric {
		if r >= '0' && r <= '9' || r == '.' {
			continue
		}
		return "", "" // invalid
	}

	return numeric, suffix
}

// parseNumericSegments splits a dotted numeric string into integer segments.
func parseNumericSegments(s string) []int {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	segments := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		segments = append(segments, n)
	}
	return segments
}

// ============================================================================
// Comparison
// ============================================================================

// Compare compares two versions.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Wildcard versions match anything (return 0).
// Unknown versions never match (return -1 unless b is also unknown).
func Compare(a, b Version) int {
	// Wildcards match anything.
	if a.Wildcard || b.Wildcard {
		return 0
	}

	// Unknown versions are incomparable — return -1 (a is "less than" b)
	// so they are never treated as confirmed in-range.
	if a.Unknown || b.Unknown {
		if a.Unknown && b.Unknown {
			return 0
		}
		return -1
	}

	// Compare segment by segment.
	minLen := len(a.Segments)
	if len(b.Segments) < minLen {
		minLen = len(b.Segments)
	}

	for i := 0; i < minLen; i++ {
		if a.Segments[i] < b.Segments[i] {
			return -1
		}
		if a.Segments[i] > b.Segments[i] {
			return 1
		}
	}

	// All shared segments equal — the one with more segments is greater.
	if len(a.Segments) < len(b.Segments) {
		return -1
	}
	if len(a.Segments) > len(b.Segments) {
		return 1
	}

	// Same numeric segments — compare suffixes.
	// Suffixes like "p1" indicate pre-release (typically < no-suffix).
	// But this is vendor-specific; we do simple string comparison.
	// No suffix is treated as greater than any suffix.
	if a.Suffix == "" && b.Suffix != "" {
		return 1
	}
	if a.Suffix != "" && b.Suffix == "" {
		return -1
	}
	if a.Suffix < b.Suffix {
		return -1
	}
	if a.Suffix > b.Suffix {
		return 1
	}

	return 0
}

// CompareStrings parses two version strings and compares them.
func CompareStrings(a, b string) int {
	return Compare(Parse(a), Parse(b))
}

// CompareBase compares the base numeric segments of two versions, ignoring
// suffixes and segment count differences. This is the right comparison for
// NVD range validation where "10.11.8" and "10.11.8-MariaDB" should be
// treated as equal.
//
// Returns -1, 0, or 1.
func CompareBase(a, b Version) int {
	if a.Wildcard || b.Wildcard {
		return 0
	}
	if a.Unknown || b.Unknown {
		if a.Unknown && b.Unknown {
			return 0
		}
		return -1
	}
	minLen := len(a.Segments)
	if len(b.Segments) < minLen {
		minLen = len(b.Segments)
	}
	for i := 0; i < minLen; i++ {
		if a.Segments[i] < b.Segments[i] {
			return -1
		}
		if a.Segments[i] > b.Segments[i] {
			return 1
		}
	}
	// Base segments match (ignoring extra segments and suffixes) — equal.
	return 0
}

// ============================================================================
// Range Checking
// ============================================================================

// Range represents an NVD CVE version range.
// Each field maps directly to the NVD CPE match fields:
//
//	versionStartIncluding:  Lower bound (inclusive)
//	versionStartExcluding:  Lower bound (exclusive)
//	versionEndIncluding:    Upper bound (inclusive)
//	versionEndExcluding:    Upper bound (exclusive)
//
// Valid combinations:
//   - All four nil/empty: open range (any version)
//   - Only start set: minimum-only range
//   - Only end set: maximum-only range
//   - Both set: bounded range
//   - Including/Excluding determines boundary inclusivity
type Range struct {
	StartIncluding *string `json:"versionStartIncluding,omitempty"`
	StartExcluding *string `json:"versionStartExcluding,omitempty"`
	EndIncluding   *string `json:"versionEndIncluding,omitempty"`
	EndExcluding   *string `json:"versionEndExcluding,omitempty"`
}

// Validate checks whether a version falls within the affected range.
// Returns:
//
//	+1 — version is confirmed inside the range (affected)
//	 0 — version status is unknown (range is open-ended, or version unparsable)
//	-1 — version is confirmed outside the range (not affected)
//
// Design principles:
//   - Unknown/empty ranges return 0 (unknown) — never suppress.
//   - Unknown/unparsable versions return 0 (unknown) — never suppress.
//   - Only confirmed in-range returns +1.
//   - Only confirmed out-of-range returns -1.
func (r Range) Validate(v Version) int {
	// Unknown version — cannot confirm either way.
	if v.Unknown || v.Raw == "" {
		return 0
	}

	// Wildcard version matches any range.
	if v.Wildcard {
		return 0
	}

	// Open range — no constraints = unknown status.
	if r.StartIncluding == nil && r.StartExcluding == nil &&
		r.EndIncluding == nil && r.EndExcluding == nil {
		return 0
	}

	hasLowerBound := r.StartIncluding != nil || r.StartExcluding != nil
	hasUpperBound := r.EndIncluding != nil || r.EndExcluding != nil

	// Check lower bound.
	if hasLowerBound {
		var boundVersion Version
		if r.StartIncluding != nil {
			boundVersion = Parse(*r.StartIncluding)
		} else {
			boundVersion = Parse(*r.StartExcluding)
		}
		if !boundVersion.Unknown && !boundVersion.Wildcard {
			cmp := CompareBase(v, boundVersion)
			if r.StartIncluding != nil {
				// version >= startIncluding
				if cmp < 0 {
					return -1
				}
			} else {
				// version > startExcluding
				if cmp <= 0 {
					return -1
				}
			}
		}
	}

	// Check upper bound.
	if hasUpperBound {
		var boundVersion Version
		if r.EndIncluding != nil {
			boundVersion = Parse(*r.EndIncluding)
		} else {
			boundVersion = Parse(*r.EndExcluding)
		}
		if !boundVersion.Unknown && !boundVersion.Wildcard {
			cmp := CompareBase(v, boundVersion)
			if r.EndIncluding != nil {
				// version <= endIncluding
				if cmp > 0 {
					return -1
				}
			} else {
				// version < endExcluding
				if cmp >= 0 {
					return -1
				}
			}
		}
	}

	// Both bounds passed — version is in range.
	return 1
}

// ValidateStrings is a convenience wrapper that parses the version string
// and validates it against the range.
func (r Range) ValidateStrings(version string) int {
	return r.Validate(Parse(version))
}

// String returns a human-readable representation of the range.
func (r Range) String() string {
	parts := make([]string, 0, 4)
	if r.StartIncluding != nil {
		parts = append(parts, fmt.Sprintf(">=%s", *r.StartIncluding))
	}
	if r.StartExcluding != nil {
		parts = append(parts, fmt.Sprintf(">%s", *r.StartExcluding))
	}
	if r.EndIncluding != nil {
		parts = append(parts, fmt.Sprintf("<=%s", *r.EndIncluding))
	}
	if r.EndExcluding != nil {
		parts = append(parts, fmt.Sprintf("<%s", *r.EndExcluding))
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " && ")
}

// ============================================================================
// Utility
// ============================================================================

// VersionStatus returns a human-readable status label.
func VersionStatus(result int) string {
	switch result {
	case 1:
		return "Affected"
	case 0:
		return "Unknown"
	case -1:
		return "Not Affected"
	default:
		return fmt.Sprintf("Unknown (%d)", result)
	}
}

// padSegments pads a version's segments to the given length by appending zeros.
// This is used when comparing versions with different segment counts
// (e.g., "2.4" vs "2.4.0").
func padSegments(v Version, n int) Version {
	if len(v.Segments) >= n {
		return v
	}
	padded := make([]int, n)
	copy(padded, v.Segments)
	for i := len(v.Segments); i < n; i++ {
		padded[i] = 0
	}
	return Version{
		Segments: padded,
		Suffix:   v.Suffix,
		Raw:      v.Raw,
	}
}

// MustParse is like Parse but panics on invalid input.
// Only for use in tests and configuration.
func MustParse(raw string) Version {
	v := Parse(raw)
	if v.Unknown {
		panic(fmt.Sprintf("invalid version: %q", raw))
	}
	return v
}

// MaxSegments returns the maximum number of segments across a set of versions.
func MaxSegments(versions []Version) int {
	maxLen := 0
	for _, v := range versions {
		if len(v.Segments) > maxLen {
			maxLen = len(v.Segments)
		}
	}
	return maxLen
}

// ============================================================================
// Nearby Version Matching
// ============================================================================

// SameMajorMinor returns true if two versions share the same major.minor prefix.
// For example, 2.4.58 and 2.4.50 share major=2, minor=4. Version "2.4.58"
// and "2.5.0" do NOT share the same major.minor.
func SameMajorMinor(a, b Version) bool {
	if a.Unknown || b.Unknown || a.Wildcard || b.Wildcard {
		return false
	}
	if len(a.Segments) < 2 || len(b.Segments) < 2 {
		return len(a.Segments) == len(b.Segments) &&
			len(a.Segments) > 0 &&
			a.Segments[0] == b.Segments[0]
	}
	return a.Segments[0] == b.Segments[0] && a.Segments[1] == b.Segments[1]
}

// IsNearbyVersion checks whether the detected version and a database CPE version
// are compatible enough that the database version's CVEs should apply to the
// detected version. Returns true if they share the same major.minor prefix
// OR the detected version is newer within the same major.minor.
//
// For example:
//   - detected 2.4.58 matches DB CPE 2.4.50 → true (same family, detected is newer)
//   - detected 2.4.58 matches DB CPE 2.4.58 → true (exact)
//   - detected 2.4.58 matches DB CPE 2.2.15 → false (different minor)
//   - detected 2.4.0 matches DB CPE 2.4.58  → true (same family, detected is older)
func IsNearbyVersion(detected Version, dbVersion Version) bool {
	if detected.Unknown || dbVersion.Unknown || detected.Wildcard || dbVersion.Wildcard {
		return false
	}
	return SameMajorMinor(detected, dbVersion)
}

// EnsureParseVersion exposes version parsing for use by the version package tests.
var _ = fmt.Sprintf("%d", math.MaxInt64) // ensure import is used
