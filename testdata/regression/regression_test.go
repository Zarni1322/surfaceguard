// Package regression provides the Golden Test Dataset framework for SurfaceGuard.
//
// It reads banner files from testdata/banners/, runs them through the detection
// pipeline (service fingerprinting, version extraction, CPE generation), and
// compares the results against expected JSON files in testdata/expected/.
//
// Every future detection change must pass these regression tests.
//
// Adding a new software:
//  1. Add a banner file to testdata/banners/<name>.txt
//  2. Add an expected JSON file to testdata/expected/<name>.json
//  3. Run: go test ./testdata/regression/
//
// No code changes required to add new test cases.
package regression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/evilhunter/surfaceguard/internal/fingerprint"
	"github.com/evilhunter/surfaceguard/pkg/cpe"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// ExpectedResult represents the expected output of fingerprinting a banner.
// This is the authoritative specification for how SurfaceGuard should
// interpret each software banner.
type ExpectedResult struct {
	// Software is a human-readable label for the software being tested.
	Software string `json:"software"`

	// BannerFile is the filename in testdata/banners/ (without path).
	BannerFile string `json:"banner_file"`

	// Port is the TCP port the service runs on.
	Port int `json:"port"`

	// Service is the expected detected service name (e.g. "http", "ssh").
	Service string `json:"service"`

	// Vendor is the expected CPE vendor.
	// Empty string means we expect no vendor mapping (unmapped product).
	Vendor string `json:"vendor"`

	// Product is the expected detected product name (e.g. "Apache httpd").
	// Empty string means we expect no product detection.
	Product string `json:"product"`

	// Version is the expected extracted version string.
	Version string `json:"version"`

	// CPE is the expected full CPE 2.3 URI.
	// Empty string means we expect no CPE generation.
	CPE string `json:"cpe"`

	// ExpectedConfidence is the typical confidence for this detection.
	ExpectedConfidence int `json:"expected_confidence"`

	// ExpectedConfidenceMin is the minimum acceptable confidence.
	ExpectedConfidenceMin int `json:"expected_confidence_min"`

	// MatchType describes the type of match: "exact", "banner_match",
	// "wrong_product_fallback", "unmapped_product", etc.
	MatchType string `json:"match_type"`

	// ExpectedCVEs lists CVE IDs that should be matched against this software.
	// Empty means no CVEs are expected (database-dependent — not validated
	// unless a test CVE database is seeded).
	ExpectedCVEs []string `json:"expected_cves"`

	// Tags for categorising and filtering tests.
	Tags []string `json:"tags"`

	// Notes explain known limitations or false positives.
	Notes string `json:"notes,omitempty"`
}

// RegressionReport holds the output of one regression test case.
type RegressionReport struct {
	Software string `json:"software"`
	Passed   bool   `json:"passed"`
	Checks   []CheckResult `json:"checks"`
}

// CheckResult holds the result of one individual check.
type CheckResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

// TestGoldenDataset runs all banner files through the detection pipeline
// and compares results against expected JSON.
func TestGoldenDataset(t *testing.T) {
	bannerDir := findTestDataDir(t, "banners")
	expectedDir := findTestDataDir(t, "expected")

	bannerFiles, err := os.ReadDir(bannerDir)
	if err != nil {
		t.Fatalf("reading banner dir %s: %v", bannerDir, err)
	}

	// Sort for deterministic order.
	sort.Slice(bannerFiles, func(i, j int) bool {
		return bannerFiles[i].Name() < bannerFiles[j].Name()
	})

	fingerprinter := fingerprint.NewServiceFingerprinter(0) // default timeout

	var totalTests, passedTests int

	for _, bf := range bannerFiles {
		if bf.IsDir() || !strings.HasSuffix(bf.Name(), ".txt") {
			continue
		}
		totalTests++

		bannerPath := filepath.Join(bannerDir, bf.Name())
		expectedPath := filepath.Join(expectedDir, strings.Replace(bf.Name(), ".txt", ".json", 1))

		t.Run(bf.Name(), func(t *testing.T) {
			// Load expected.
			expected := loadExpected(t, expectedPath)
			if expected == nil {
				t.Fatalf("no expected file for %s", bf.Name())
			}

			// Load banner.
			bannerBytes, err := os.ReadFile(bannerPath)
			if err != nil {
				t.Fatalf("reading banner %s: %v", bannerPath, err)
			}
			bannerText := strings.TrimSpace(string(bannerBytes))

			// Build the port model as the scanner would.
			port := models.Port{
				Port:   expected.Port,
				State:  "open",
				Banner: bannerText,
			}

			// Run the full fingerprint pipeline.
			port = fingerprinter.Fingerprint(port)

			report := &RegressionReport{Software: expected.Software, Passed: true}

			// Check 1: Service detection.
			checkService(t, report, port.Service, expected.Service)

			// Check 2: Product detection.
			checkProduct(t, report, port.Product, expected.Product)

			// Check 3: Version extraction.
			checkVersion(t, report, port.Version, expected.Version)

			// Check 4: CPE generation.
			checkCPE(t, report, port.CPEs, expected.CPE)

			// Check 5: CPE vendor mapping via shared package.
			checkVendor(t, report, port, expected.Vendor)

			// Check 6: Confidence range.
			checkConfidence(t, report, port.Confidence, expected.ExpectedConfidenceMin)

			// Check 7: No unexpected CPEs.
			if expected.CPE == "" && len(port.CPEs) > 0 {
				report.Passed = false
				report.Checks = append(report.Checks, CheckResult{
					Name: "no_unexpected_cpes",
					Passed: false,
					Detail: fmt.Sprintf("expected no CPEs but got %d: %v", len(port.CPEs), port.CPEs[0].CPE23URI),
				})
			}

			// Print report.
			printReport(t, report)
			if !report.Passed {
				passedTestsStr := fmt.Sprintf("%d/%d checks failed", countFails(report), len(report.Checks))
				// We use t.Error not t.Fatal so remaining tests still run.
				t.Error(passedTestsStr)
			} else {
				passedTests++
			}
		})
	}

	t.Logf("\n========================================")
	t.Logf("Golden Test Dataset Summary")
	t.Logf("========================================")
	t.Logf("Total:  %d", totalTests)
	t.Logf("Passed: %d", passedTests)
	t.Logf("Failed: %d", totalTests-passedTests)
	t.Logf("========================================")
}

// ============================================================================
// Individual Checks
// ============================================================================

func checkService(t *testing.T, r *RegressionReport, actual, expected string) {
	if actual != expected {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "service_detection",
			Passed: false,
			Detail: fmt.Sprintf("Expected Service: %s  Actual: %s", expected, actual),
		})
	}
}

func checkProduct(t *testing.T, r *RegressionReport, actual, expected string) {
	if actual != expected {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "product_detection",
			Passed: false,
			Detail: fmt.Sprintf("Expected Product: %s  Actual: %s", expected, actual),
		})
	}
}

func checkVersion(t *testing.T, r *RegressionReport, actual, expected string) {
	if expected == "" {
		return // version not expected to be detected
	}
	if actual != expected {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "version_extraction",
			Passed: false,
			Detail: fmt.Sprintf("Expected Version: %s  Actual: %s", expected, actual),
		})
	}
}

func checkCPE(t *testing.T, r *RegressionReport, cpes []models.CPE, expectedCPE string) {
	if expectedCPE == "" {
		if len(cpes) > 0 {
			r.Passed = false
			r.Checks = append(r.Checks, CheckResult{
				Name:   "cpe_generation",
				Passed: false,
				Detail: fmt.Sprintf("Expected no CPE, got %s", cpes[0].CPE23URI),
			})
		}
		return
	}
	if len(cpes) == 0 {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "cpe_generation",
			Passed: false,
			Detail: fmt.Sprintf("Expected CPE: %s  but no CPE was generated", expectedCPE),
		})
		return
	}
	if cpes[0].CPE23URI != expectedCPE {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "cpe_generation",
			Passed: false,
			Detail: fmt.Sprintf("Expected CPE: %s  Actual: %s", expectedCPE, cpes[0].CPE23URI),
		})
	}
}

func checkVendor(t *testing.T, r *RegressionReport, port models.Port, expectedVendor string) {
	if expectedVendor == "" {
		return // no vendor mapping expected
	}
	// Look up the CPE vendor for this product using the shared package.
	if port.Product != "" {
		c := cpe.FromProduct(port.Product, port.Version)
		if c != nil && c.Vendor != expectedVendor {
			r.Passed = false
			r.Checks = append(r.Checks, CheckResult{
				Name:   "vendor_detection",
				Passed: false,
				Detail: fmt.Sprintf("Expected Vendor: %s  Actual: %s (via product %q)", expectedVendor, c.Vendor, port.Product),
			})
		}
	}
}

func checkConfidence(t *testing.T, r *RegressionReport, actual, minExpected int) {
	if actual < minExpected {
		r.Passed = false
		r.Checks = append(r.Checks, CheckResult{
			Name:   "confidence",
			Passed: false,
			Detail: fmt.Sprintf("Expected min confidence: %d  Actual: %d", minExpected, actual),
		})
	}
}

// ============================================================================
// Helpers
// ============================================================================

func findTestDataDir(t *testing.T, subdir string) string {
	t.Helper()
	// Walk up from the test file location to find testdata/.
	// In Go test execution, the working directory is the package directory.
	candidates := []string{
		filepath.Join("testdata", subdir),
		filepath.Join("..", "..", "testdata", subdir),
		filepath.Join("..", "..", "..", "testdata", subdir),
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	t.Fatalf("cannot find testdata/%s directory (tried %v)", subdir, candidates)
	return ""
}

func loadExpected(t *testing.T, path string) *ExpectedResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var exp ExpectedResult
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatalf("parsing expected %s: %v", path, err)
		return nil
	}
	return &exp
}

func printReport(t *testing.T, r *RegressionReport) {
	if len(r.Checks) == 0 {
		return // nothing to report if all checks implicitly passed
	}
	t.Logf("")
	t.Logf("  %s:", r.Software)
	for _, c := range r.Checks {
		if c.Passed {
			continue // only print failures and details
		}
		t.Logf("    FAIL: %s", c.Name)
		if c.Detail != "" {
			t.Logf("      %s", c.Detail)
		}
	}
}

func countFails(r *RegressionReport) int {
	count := 0
	for _, c := range r.Checks {
		if !c.Passed {
			count++
		}
	}
	return count
}

// TestVendorConsistency verifies that every entry in ProductVendor has a
// corresponding ProductName entry and vice versa.
func TestVendorConsistency(t *testing.T) {
	var issues []string

	for k := range cpe.ProductVendor {
		if _, ok := cpe.ProductName[k]; !ok {
			issues = append(issues, fmt.Sprintf("ProductVendor[%q] has no ProductName entry", k))
		}
	}
	for k := range cpe.ProductName {
		if _, ok := cpe.ProductVendor[k]; !ok {
			issues = append(issues, fmt.Sprintf("ProductName[%q] has no ProductVendor entry", k))
		}
	}

	for _, issue := range issues {
		t.Error(issue)
	}
	if len(issues) == 0 {
		t.Log("Vendor/product map consistency: PASS")
	}
}

// TestCVERegression validates that a given software's detected CPE matches
// against known CVEs in the local database. This test is experimental and
// requires a populated CVE database. It is skipped when no database is present.
//
// Future: expand to run the full matcher.MatchPort against seeded test CVEs.
func TestCVERegression(t *testing.T) {
	// Placeholder for CVE matching regression tests that will be implemented
	// after the CVE database seeding test infrastructure is in place.
	// Expected implementation:
	//   1. For each expected JSON with non-empty expected_cves
	//   2. Seed test CVEs into the database
	//   3. Run MatchPort for the detected CPE
	//   4. Verify expected CVEs are matched
	//   5. Verify NO unexpected CVEs are returned
	t.Skip("CVE regression testing requires database seeding — to be implemented when CVE version-range validation is added")
}
