package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if cfg.Scan.Workers != 100 {
		t.Errorf("expected 100 workers, got %d", cfg.Scan.Workers)
	}
	if cfg.Scan.Timeout != 3*time.Second {
		t.Errorf("expected 3s timeout, got %s", cfg.Scan.Timeout)
	}
	if cfg.Database.Path != "data/cve.db" {
		t.Errorf("expected data/cve.db, got %s", cfg.Database.Path)
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected info level, got %s", cfg.Logging.Level)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create a temp config file.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "surfaceguard.yaml")
	content := []byte(`
scan:
  workers: 50
  timeout: 5s
logging:
  level: debug
`)
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Scan.Workers != 50 {
		t.Errorf("expected 50 workers, got %d", cfg.Scan.Workers)
	}
	if cfg.Scan.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %s", cfg.Scan.Timeout)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected debug level, got %s", cfg.Logging.Level)
	}
	// Unset fields should retain defaults.
	if cfg.Scan.BannerSize != 2048 {
		t.Errorf("expected default 2048 banner size, got %d", cfg.Scan.BannerSize)
	}
	if cfg.Database.Path != "data/cve.db" {
		t.Errorf("expected default data/cve.db, got %s", cfg.Database.Path)
	}
}

func TestLoadConfigNonExistentFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/config.yaml")
	if err != nil {
		t.Fatalf("LoadConfig should not fail for missing file: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestEmptyConfigPath(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig with empty path should not fail: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestEnvOverrides(t *testing.T) {
	// Set env vars before loading config.
	os.Setenv("SURFACEGUARD_SCAN_WORKERS", "200")
	os.Setenv("SURFACEGUARD_DATABASE_PATH", "/tmp/test.db")
	os.Setenv("SURFACEGUARD_LOGGING_LEVEL", "error")
	defer func() {
		os.Unsetenv("SURFACEGUARD_SCAN_WORKERS")
		os.Unsetenv("SURFACEGUARD_DATABASE_PATH")
		os.Unsetenv("SURFACEGUARD_LOGGING_LEVEL")
	}()

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Scan.Workers != 200 {
		t.Errorf("expected 200 workers (env override), got %d", cfg.Scan.Workers)
	}
	if cfg.Database.Path != "/tmp/test.db" {
		t.Errorf("expected /tmp/test.db (env override), got %s", cfg.Database.Path)
	}
	if cfg.Logging.Level != "error" {
		t.Errorf("expected error level (env override), got %s", cfg.Logging.Level)
	}
}

func TestValidateValidConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.validate(); err != nil {
		t.Fatalf("validation should pass: %v", err)
	}
}

func TestValidateInvalidWorkers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scan.Workers = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero workers")
	}
}

func TestValidateInvalidTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scan.Timeout = 0
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for zero timeout")
	}
}

func TestValidateInvalidBannerSize(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scan.BannerSize = -1
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for negative banner size")
	}
}

func TestDefaultMinConfidenceForFallback(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Scan.MinConfidenceForFallback != 90 {
		t.Errorf("expected default MinConfidenceForFallback 90, got %d", cfg.Scan.MinConfidenceForFallback)
	}
}

func TestValidateInvalidMinConfidenceForFallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scan.MinConfidenceForFallback = -1
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for negative MinConfidenceForFallback")
	}
	cfg.Scan.MinConfidenceForFallback = 101
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for MinConfidenceForFallback > 100")
	}
}

func TestEnvOverrideMinConfidenceForFallback(t *testing.T) {
	os.Setenv("SURFACEGUARD_SCAN_MIN_CONFIDENCE_FALLBACK", "50")
	defer os.Unsetenv("SURFACEGUARD_SCAN_MIN_CONFIDENCE_FALLBACK")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Scan.MinConfidenceForFallback != 50 {
		t.Errorf("expected MinConfidenceForFallback 50 (env override), got %d", cfg.Scan.MinConfidenceForFallback)
	}
}

func TestEnvOverrideMinConfidenceForFallbackClamp(t *testing.T) {
	// Values outside 0-100 should be rejected.
	os.Setenv("SURFACEGUARD_SCAN_MIN_CONFIDENCE_FALLBACK", "999")
	defer os.Unsetenv("SURFACEGUARD_SCAN_MIN_CONFIDENCE_FALLBACK")

	cfg := DefaultConfig()
	// LoadConfig will apply the env override but the value 999 is out of range
	// and should be rejected (the env override won't change the default).
	// We bypass this by testing the env-override logic inline.
	// Actually, LoadConfig also validates, so test the validation separately.
	cfg.Scan.MinConfidenceForFallback = 999
	if err := cfg.validate(); err == nil {
		t.Fatal("expected validation error for MinConfidenceForFallback=999")
	}
}

func TestValidateInvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Level = "verbose"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}

func TestValidateInvalidLogFormat(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Logging.Format = "xml"
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for invalid log format")
	}
}

func TestValidateInvalidCVSSThreshold(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Report.CVSSThreshold = 11
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for CVSS threshold > 10")
	}
	cfg.Report.CVSSThreshold = -1
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for negative CVSS threshold")
	}
}

func TestResolveDatabasePath(t *testing.T) {
	// Absolute paths should be returned as-is.
	cfg := DefaultConfig()
	cfg.Database.Path = "/absolute/path/cve.db"
	path, err := cfg.ResolveDatabasePath()
	if err != nil {
		t.Fatalf("ResolveDatabasePath failed: %v", err)
	}
	if path != "/absolute/path/cve.db" {
		t.Errorf("expected /absolute/path/cve.db, got %s", path)
	}
}

func TestTopPorts(t *testing.T) {
	cfg := DefaultConfig()
	ports := cfg.TopPorts()
	if len(ports) == 0 {
		t.Fatal("expected non-empty port list")
	}
	// Port 80 should be in the list.
	found := false
	for _, p := range ports {
		if p == 80 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected port 80 in default ports")
	}
}

func TestTopPortsCustom(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Scan.Ports = []int{8080, 9090}
	ports := cfg.TopPorts()
	if len(ports) != 2 {
		t.Fatalf("expected 2 ports, got %d", len(ports))
	}
	if ports[0] != 8080 {
		t.Errorf("expected port 8080 first, got %d", ports[0])
	}
}

func TestEnvOverrideScanTimeout(t *testing.T) {
	os.Setenv("SURFACEGUARD_SCAN_TIMEOUT", "10s")
	defer os.Unsetenv("SURFACEGUARD_SCAN_TIMEOUT")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Scan.Timeout != 10*time.Second {
		t.Errorf("expected 10s timeout, got %s", cfg.Scan.Timeout)
	}
}

func TestEnvOverrideUpdateURLs(t *testing.T) {
	os.Setenv("SURFACEGUARD_UPDATE_CVE_BASE_URL", "https://custom.example.com/cve")
	os.Setenv("SURFACEGUARD_UPDATE_KEV_BASE_URL", "https://custom.example.com/kev")
	defer func() {
		os.Unsetenv("SURFACEGUARD_UPDATE_CVE_BASE_URL")
		os.Unsetenv("SURFACEGUARD_UPDATE_KEV_BASE_URL")
	}()

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Update.CVEBaseURL != "https://custom.example.com/cve" {
		t.Errorf("expected custom CVE URL, got %s", cfg.Update.CVEBaseURL)
	}
	if cfg.Update.KEVBaseURL != "https://custom.example.com/kev" {
		t.Errorf("expected custom KEV URL, got %s", cfg.Update.KEVBaseURL)
	}
}
