package version

import (
	"testing"
)

// ============================================================================
// Parsing Tests
// ============================================================================

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		wantStr   string
		wantSeg   []int
		wantSfx   string
		wantWild  bool
		wantUnk   bool
	}{
		{"1.2", "1.2", []int{1, 2}, "", false, false},
		{"1.2.3", "1.2.3", []int{1, 2, 3}, "", false, false},
		{"1.2.3.4", "1.2.3.4", []int{1, 2, 3, 4}, "", false, false},
		{"2.4.58", "2.4.58", []int{2, 4, 58}, "", false, false},
		{"9.8p1", "9.8p1", []int{9, 8}, "p1", false, false},
		{"10.11", "10.11", []int{10, 11}, "", false, false},
		{"11.0.2", "11.0.2", []int{11, 0, 2}, "", false, false},
		{"1.2.3-ubuntu", "1.2.3-ubuntu", []int{1, 2, 3}, "-ubuntu", false, false},
		{"1.2.3.el8", "1.2.3.el8", []int{1, 2, 3}, ".el8", false, false},
		{"1.2.3-r0", "1.2.3-r0", []int{1, 2, 3}, "-r0", false, false},
		{"1.2.3a", "1.2.3a", []int{1, 2, 3}, "a", false, false},
		{"1.2.3_rc1", "1.2.3_rc1", []int{1, 2, 3}, "_rc1", false, false},
		{"8.0.36-log", "8.0.36-log", []int{8, 0, 36}, "-log", false, false},
		{"10.11.8-MariaDB", "10.11.8-MariaDB", []int{10, 11, 8}, "-MariaDB", false, false},
		{"*", "*", nil, "", true, false},
		{"", "", nil, "", false, true},
		{"not-a-version", "not-a-version", nil, "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			v := Parse(tc.input)
			if v.Wildcard != tc.wantWild {
				t.Errorf("Wildcard: got %v, want %v", v.Wildcard, tc.wantWild)
			}
			if v.Unknown != tc.wantUnk {
				t.Errorf("Unknown: got %v, want %v", v.Unknown, tc.wantUnk)
			}
			if len(v.Segments) != len(tc.wantSeg) {
				t.Errorf("Segments: got %v (len=%d), want %v (len=%d)",
					v.Segments, len(v.Segments), tc.wantSeg, len(tc.wantSeg))
				return
			}
			for i := range v.Segments {
				if v.Segments[i] != tc.wantSeg[i] {
					t.Errorf("Segments[%d]: got %d, want %d", i, v.Segments[i], tc.wantSeg[i])
				}
			}
			if v.Suffix != tc.wantSfx {
				t.Errorf("Suffix: got %q, want %q", v.Suffix, tc.wantSfx)
			}
			if v.String() != tc.wantStr {
				t.Errorf("String(): got %q, want %q", v.String(), tc.wantStr)
			}
		})
	}
}

// ============================================================================
// Comparison Tests
// ============================================================================

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// Basic numeric comparison.
		{"1.0", "2.0", -1},
		{"2.0", "1.0", 1},
		{"1.0", "1.0", 0},
		{"1.0.0", "1.0.0", 0},

		// Segment depth.
		{"1.0", "1.0.0", -1},
		{"1.0.0", "1.0", 1},
		{"1.0.1", "1.0", 1},

		// Using the actual golder dataset values.
		{"2.4.49", "2.4.58", -1},
		{"2.4.58", "2.4.49", 1},

		// Suffixes: with-suffix < no-suffix (p1 is a patch/sub-release).
		{"9.8", "9.8p1", 1},
		{"9.8p1", "9.8", -1},
		{"8.9p1", "8.9", -1},
		{"8.9", "8.9p1", 1},

		// Vendor-specific suffix.
		{"10.11.8", "10.11.8-MariaDB", 1},
		{"10.11.8-MariaDB", "10.11.8", -1},
		{"8.0.36", "8.0.36-log", 1},
		{"8.0.36-log", "8.0.36", -1},

		// Wildcard.
		{"*", "1.2.3", 0},
		{"1.2.3", "*", 0},
		{"*", "*", 0},

		// Unknown.
		{"", "1.2.3", -1},
		{"1.2.3", "", -1},
		{"", "", 0},

		// Different segment counts (Apache version ranges).
		{"2.4.0", "2.4", 1},
		{"2.4", "2.4.0", -1},

		// Real-world NVD range comparisons.
		{"2.4.49", "2.4.50", -1},
		{"2.4.50", "2.4.49", 1},
	}
	for _, tc := range tests {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got := CompareStrings(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// ============================================================================
// Range Validation Tests
// ============================================================================

func strPtr(s string) *string { return &s }

func TestRangeValidate(t *testing.T) {
	tests := []struct {
		name    string
		version string
		rng     Range
		want    int // 1=affected, 0=unknown, -1=not affected
	}{
		// Open range (no bounds) — unknown.
		{"open range", "2.4.49", Range{}, 0},
		{"open range unknown version", "", Range{}, 0},

		// Minimum only: >= 2.4.0
		{"min inc above", "2.4.49", Range{StartIncluding: strPtr("2.4.0")}, 1},
		{"min inc equal", "2.4.0", Range{StartIncluding: strPtr("2.4.0")}, 1},
		{"min inc below", "2.3.99", Range{StartIncluding: strPtr("2.4.0")}, -1},

		// Minimum exclusive: > 2.4.0
		{"min exc above", "2.4.1", Range{StartExcluding: strPtr("2.4.0")}, 1},
		{"min exc equal", "2.4.0", Range{StartExcluding: strPtr("2.4.0")}, -1},
		{"min exc below", "2.3.99", Range{StartExcluding: strPtr("2.4.0")}, -1},

		// Maximum only: < 2.4.57
		{"max exc below", "2.4.49", Range{EndExcluding: strPtr("2.4.57")}, 1},
		{"max exc equal", "2.4.57", Range{EndExcluding: strPtr("2.4.57")}, -1},
		{"max exc above", "2.4.58", Range{EndExcluding: strPtr("2.4.57")}, -1},

		// Maximum inclusive: <= 2.4.57
		{"max inc below", "2.4.49", Range{EndIncluding: strPtr("2.4.57")}, 1},
		{"max inc equal", "2.4.57", Range{EndIncluding: strPtr("2.4.57")}, 1},
		{"max inc above", "2.4.58", Range{EndIncluding: strPtr("2.4.57")}, -1},

		// Bounded: >= 2.4.0, < 2.4.57
		{"bounded inside", "2.4.49", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, 1},
		{"bounded low edge", "2.4.0", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, 1},
		{"bounded high edge", "2.4.56", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, 1},
		{"bounded below", "2.3.99", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, -1},
		{"bounded above", "2.4.57", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, -1},
		{"bounded far above", "2.4.58", Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, -1},

		// Exactly bounded: >= 2.4.48, <= 2.4.49
		{"exact inside", "2.4.49", Range{StartIncluding: strPtr("2.4.48"), EndIncluding: strPtr("2.4.49")}, 1},
		{"exact above", "2.4.50", Range{StartIncluding: strPtr("2.4.48"), EndIncluding: strPtr("2.4.49")}, -1},

		// Vendor-specific format: "10.11.8-MariaDB" vs range "10.11.8" to "10.11.8"
		{"suffix inside", "10.11.8-MariaDB", Range{StartIncluding: strPtr("10.11.0"), EndIncluding: strPtr("10.11.8")}, 1},
		{"suffix vs plain range start", "10.11.8-MariaDB", Range{StartIncluding: strPtr("10.11.8"), EndIncluding: strPtr("10.11.8")}, 1},

		// The suffix means it's "less than" the plain version.
		{"suffix vs strict lower", "10.11.8-MariaDB", Range{StartExcluding: strPtr("10.11.8")}, -1},
		{"suffix vs inclusive lower", "10.11.8-MariaDB", Range{StartIncluding: strPtr("10.11.8")}, 1},

		// Unknown version → unknown status.
		{"unknown version", "", Range{StartIncluding: strPtr("2.4.0")}, 0},
		{"unparsable version", "not-a-version", Range{StartIncluding: strPtr("2.4.0")}, 0},

		// Wildcard version → unknown status.
		{"wildcard version", "*", Range{StartIncluding: strPtr("2.4.0")}, 0},

		// Red Hat style: "0:3.0.3-1.el8"
		{"redhat format", "3.0.3", Range{StartIncluding: strPtr("3.0.0"), EndExcluding: strPtr("3.0.4")}, 1},

		// Multiple segment depths.
		{"deeper version in range", "1.2.3.4", Range{StartIncluding: strPtr("1.2.0"), EndExcluding: strPtr("2.0.0")}, 1},
		{"shallower version in range", "1.2", Range{StartIncluding: strPtr("1.0.0"), EndExcluding: strPtr("2.0.0")}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := Parse(tc.version)
			got := tc.rng.Validate(v)
			if got != tc.want {
				t.Errorf("Range{%s}.Validate(%q) = %d (want %d)\n  Range: %s\n  Version: %s → segments=%v suffix=%q",
					tc.rng.String(), tc.version, got, tc.want, tc.rng.String(), v.String(), v.Segments, v.Suffix)
			}
		})
	}
}

// ============================================================================
// Edge Case Tests
// ============================================================================

func TestRangeString(t *testing.T) {
	tests := []struct {
		rng  Range
		want string
	}{
		{Range{}, "any"},
		{Range{StartIncluding: strPtr("2.4.0")}, ">=2.4.0"},
		{Range{EndExcluding: strPtr("2.4.57")}, "<2.4.57"},
		{Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.57")}, ">=2.4.0 && <2.4.57"},
		{Range{StartExcluding: strPtr("2.4.0"), EndIncluding: strPtr("2.4.57")}, ">2.4.0 && <=2.4.57"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.rng.String()
			if got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVersionStatus(t *testing.T) {
	tests := []struct {
		result int
		want   string
	}{
		{1, "Affected"},
		{0, "Unknown"},
		{-1, "Not Affected"},
	}
	for _, tc := range tests {
		got := VersionStatus(tc.result)
		if got != tc.want {
			t.Errorf("VersionStatus(%d) = %q, want %q", tc.result, got, tc.want)
		}
	}
}

func TestMustParse(t *testing.T) {
	v := MustParse("1.2.3")
	if v.Unknown {
		t.Fatal("MustParse returned unknown")
	}
	if v.String() != "1.2.3" {
		t.Errorf("got %q", v.String())
	}
}

func TestMustParsePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid version")
		}
	}()
	MustParse("")
}

// ============================================================================
// NVD Real-World Scenarios
// ============================================================================

func TestRealWorldNVDRanges(t *testing.T) {
	// Scenario: CVE-2024-???? for Apache httpd < 2.4.59
	// Apache 2.4.58 should be affected.
	rng := Range{StartIncluding: strPtr("2.4.0"), EndExcluding: strPtr("2.4.59")}

	result := rng.ValidateStrings("2.4.58")
	if result != 1 {
		t.Errorf("Apache 2.4.58 should be affected by <2.4.59, got %d", result)
	}

	result = rng.ValidateStrings("2.4.59")
	if result != -1 {
		t.Errorf("Apache 2.4.59 should NOT be affected by <2.4.59, got %d", result)
	}

	result = rng.ValidateStrings("2.4.0")
	if result != 1 {
		t.Errorf("Apache 2.4.0 should be affected (>=2.4.0), got %d", result)
	}

	// Scenario: CVE affecting OpenSSH >= 8.5, < 9.8
	// OpenSSH 9.8 should NOT be affected (version equals end).
	rng2 := Range{StartIncluding: strPtr("8.5"), EndExcluding: strPtr("9.8")}
	result = rng2.ValidateStrings("9.7")
	if result != 1 {
		t.Errorf("OpenSSH 9.7 should be affected by >=8.5,<9.8, got %d", result)
	}
	result = rng2.ValidateStrings("9.8")
	if result != -1 {
		t.Errorf("OpenSSH 9.8 should NOT be affected by >=8.5,<9.8, got %d", result)
	}
	result = rng2.ValidateStrings("8.5")
	if result != 1 {
		t.Errorf("OpenSSH 8.5 should be affected (>=8.5), got %d", result)
	}

	// Scenario: CVE affecting nginx < 1.26.0 (open-ended start)
	rng3 := Range{EndExcluding: strPtr("1.26.0")}
	result = rng3.ValidateStrings("1.25.0")
	if result != 1 {
		t.Errorf("nginx 1.25.0 should be affected by <1.26.0, got %d", result)
	}
	result = rng3.ValidateStrings("1.26.0")
	if result != -1 {
		t.Errorf("nginx 1.26.0 should NOT be affected by <1.26.0, got %d", result)
	}
	result = rng3.ValidateStrings("1.26.1")
	if result != -1 {
		t.Errorf("nginx 1.26.1 should NOT be affected by <1.26.0, got %d", result)
	}

	// Scenario: CVE affecting MySQL 8.0.x (>= 8.0.0, <= 8.0.36)
	rng4 := Range{StartIncluding: strPtr("8.0.0"), EndIncluding: strPtr("8.0.36")}
	result = rng4.ValidateStrings("8.0.35")
	if result != 1 {
		t.Errorf("MySQL 8.0.35 should be affected, got %d", result)
	}
	result = rng4.ValidateStrings("8.0.36")
	if result != 1 {
		t.Errorf("MySQL 8.0.36 should be affected (<=8.0.36), got %d", result)
	}
	result = rng4.ValidateStrings("8.0.37")
	if result != -1 {
		t.Errorf("MySQL 8.0.37 should NOT be affected, got %d", result)
	}
}
