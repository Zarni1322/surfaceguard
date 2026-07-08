// Package config provides YAML-based configuration with environment variable
// overrides. It follows the principle that config should be:
//  1. Version-controllable via configs/surfaceguard.yaml (defaults)
//  2. Overridable via environment variables (deployment)
//  3. Discoverable via --help flags (CLI)
//
// The Config struct is the single source of truth for all tunable parameters.
package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// AssessmentConfig configures authenticated scanning.
type AssessmentConfig struct {
	SSHKeyDir   string `yaml:"ssh_key_dir"`
	EncryptKey  string `yaml:"encryption_key"`
	ConnTimeout string `yaml:"conn_timeout"`
}

// EASMConfig configures External Attack Surface Management.
type EASMConfig struct {
	Workers       int    `yaml:"workers"`
	PortScanLevel string `yaml:"port_scan_level"` // fast, full
	Screenshots   bool   `yaml:"screenshots"`
	WordlistDir   string `yaml:"wordlist_dir"`
}

// Config holds all scanner configuration loaded from YAML + env overrides.
type Config struct {
	// Scan settings
	Scan ScanConfig `yaml:"scan"`
	// Database settings
	Database DatabaseConfig `yaml:"database"`
	// Update settings
	Update UpdateConfig `yaml:"update"`
	// Logging settings
	Logging LoggingConfig `yaml:"logging"`
	// Report settings
	Report ReportConfig `yaml:"report"`
	// Assessment settings
	Assessment AssessmentConfig `yaml:"assessment"`
	// EASM settings
	EASM EASMConfig `yaml:"easm"`
	// Banner settings
	ShowBanner bool `yaml:"show_banner"`
	// Config file path (not from YAML, set programmatically)
	configPath string
}

// ScanConfig configures port scanning behaviour.
type ScanConfig struct {
	// Default ports to scan (top N ports or comma-separated)
	Ports       []int         `yaml:"ports"`
	Workers     int           `yaml:"workers"`
	Timeout     time.Duration `yaml:"timeout"`
	BannerSize  int           `yaml:"banner_size"`
	Fingerprint bool          `yaml:"fingerprint"`
	RateLimit   int           `yaml:"rate_limit"` // max packets per second (0=unlimited)
}

// DatabaseConfig configures the local SQLite database.
type DatabaseConfig struct {
	Path            string `yaml:"path"`
	MaxOpenConns    int    `yaml:"max_open_conns"`
	MaxIdleConns    int    `yaml:"max_idle_conns"`
	ConnMaxLifetime string `yaml:"conn_max_lifetime"`
}

// UpdateConfig configures CVE/CPE/KEV data feed downloads.
type UpdateConfig struct {
	Enabled       bool   `yaml:"enabled"`
	CVEBaseURL    string `yaml:"cve_base_url"`
	CPEBaseURL    string `yaml:"cpe_base_url"`
	KEVBaseURL    string `yaml:"kev_base_url"`
	EPSSBaseURL   string `yaml:"epss_base_url"`
	HTTPTimeout   string `yaml:"http_timeout"`
	RetryCount    int    `yaml:"retry_count"`
	RetryDelay    string `yaml:"retry_delay"`
	MaxRetryDelay string `yaml:"max_retry_delay"`
	Incremental   bool   `yaml:"incremental"`
	DownloadsDir  string `yaml:"downloads_dir"`
}

// LoggingConfig configures structured logging.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // debug, info, warn, error
	Format string `yaml:"format"` // text, json
}

// ReportConfig configures report output.
type ReportConfig struct {
	DefaultFormat string  `yaml:"default_format"` // console, json, html
	HTMLTemplate  string  `yaml:"html_template"`
	CVSSThreshold float64 `yaml:"cvss_threshold"`
}

const (
	// DefaultConfigPath is the default path to the YAML config file.
	DefaultConfigPath = "configs/surfaceguard.yaml"
	// EnvPrefix is the prefix for environment variable overrides.
	EnvPrefix = "SURFACEGUARD_"
)

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Scan: ScanConfig{
			Ports:       []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9000, 9090, 27017},
			Workers:     100,
			Timeout:     3 * time.Second,
			BannerSize:  2048,
			Fingerprint: true,
			RateLimit:   0,
		},
		Database: DatabaseConfig{
			Path:            "data/cve.db",
			MaxOpenConns:    1,
			MaxIdleConns:    1,
			ConnMaxLifetime: "30m",
		},
		Update: UpdateConfig{
			Enabled:       true,
			CVEBaseURL:    "https://services.nvd.nist.gov/rest/json/cves/2.0",
			CPEBaseURL:    "https://services.nvd.nist.gov/rest/json/cpes/2.0",
			KEVBaseURL:    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			EPSSBaseURL:   "https://epss.cyentia.com/epss_scores-current.csv.gz",
			HTTPTimeout:   "300s",
			RetryCount:    3,
			RetryDelay:    "5s",
			MaxRetryDelay: "60s",
			Incremental:   true,
			DownloadsDir:  "downloads",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Report: ReportConfig{
			DefaultFormat: "console",
			HTMLTemplate:  "",
			CVSSThreshold: 0.0,
		},
		Assessment: AssessmentConfig{
			SSHKeyDir:   "ssh_keys",
			EncryptKey:  "",
			ConnTimeout: "10s",
		},
		EASM: EASMConfig{
			Workers:       50,
			PortScanLevel: "fast",
			Screenshots:   false,
			WordlistDir:   "assets/wordlists",
		},
		ShowBanner: true,
	}
}

// LoadConfig reads configuration from the specified YAML file, applies
// defaults for any missing fields, then overrides with environment variables.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	cfg.configPath = path
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("reading config file %s: %w", path, err)
			}
			// Config file doesn't exist — that's OK, use defaults + env overrides.
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parsing config file %s: %w", path, err)
			}
		}
	}
	// Apply environment variable overrides.
	cfg.applyEnvOverrides()
	// Validate the config.
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// ConfigPath returns the path to the loaded config file.
func (c *Config) ConfigPath() string {
	return c.configPath
}

// applyEnvOverrides reads environment variables with the SURFACEGUARD_ prefix
// and overrides corresponding config fields. Supports SURFACEGUARD_SCAN_WORKERS,
// SURFACEGUARD_DATABASE_PATH, etc. and their underscore-delimited hierarchy.
func (c *Config) applyEnvOverrides() {
	// Scan overrides
	if v := os.Getenv(EnvPrefix + "SCAN_WORKERS"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.Scan.Workers = i
		}
	}
	if v := os.Getenv(EnvPrefix + "SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Scan.Timeout = d
		}
	}
	if v := os.Getenv(EnvPrefix + "SCAN_BANNER_SIZE"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.Scan.BannerSize = i
		}
	}
	if v := os.Getenv(EnvPrefix + "SCAN_RATE_LIMIT"); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			c.Scan.RateLimit = i
		}
	}
	// Database overrides
	if v := os.Getenv(EnvPrefix + "DATABASE_PATH"); v != "" {
		c.Database.Path = v
	}
	// Update overrides
	if v := os.Getenv(EnvPrefix + "UPDATE_ENABLED"); v != "" {
		c.Update.Enabled = strings.ToLower(v) == "true"
	}
	if v := os.Getenv(EnvPrefix + "UPDATE_CVE_BASE_URL"); v != "" {
		c.Update.CVEBaseURL = v
	}
	if v := os.Getenv(EnvPrefix + "UPDATE_KEV_BASE_URL"); v != "" {
		c.Update.KEVBaseURL = v
	}
	if v := os.Getenv(EnvPrefix + "UPDATE_EPSS_BASE_URL"); v != "" {
		c.Update.EPSSBaseURL = v
	}
	// Logging overrides
	if v := os.Getenv(EnvPrefix + "LOGGING_LEVEL"); v != "" {
		c.Logging.Level = v
	}
	if v := os.Getenv(EnvPrefix + "LOGGING_FORMAT"); v != "" {
		c.Logging.Format = v
	}
	// Report overrides
	if v := os.Getenv(EnvPrefix + "REPORT_DEFAULT_FORMAT"); v != "" {
		c.Report.DefaultFormat = v
	}
	if v := os.Getenv(EnvPrefix + "REPORT_CVSS_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			c.Report.CVSSThreshold = f
		}
	}
}

// validate checks that the configuration is internally consistent.
func (c *Config) validate() error {
	if c.Scan.Workers <= 0 {
		return fmt.Errorf("scan.workers must be positive (got %d)", c.Scan.Workers)
	}
	if c.Scan.Timeout <= 0 {
		return fmt.Errorf("scan.timeout must be positive (got %s)", c.Scan.Timeout)
	}
	if c.Scan.BannerSize <= 0 {
		return fmt.Errorf("scan.banner_size must be positive (got %d)", c.Scan.BannerSize)
	}
	if c.Database.Path == "" {
		return fmt.Errorf("database.path must not be empty")
	}
	if c.Logging.Level != "" {
		switch strings.ToLower(c.Logging.Level) {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("logging.level must be one of: debug, info, warn, error (got %q)", c.Logging.Level)
		}
	}
	if c.Logging.Format != "" {
		switch strings.ToLower(c.Logging.Format) {
		case "text", "json":
		default:
			return fmt.Errorf("logging.format must be one of: text, json (got %q)", c.Logging.Format)
		}
	}
	if c.Report.CVSSThreshold < 0 || c.Report.CVSSThreshold > 10 {
		return fmt.Errorf("report.cvss_threshold must be 0-10 (got %.1f)", c.Report.CVSSThreshold)
	}
	return nil
}

// ResolveDownloadsDir returns the absolute path to the downloads directory.
func (c *Config) ResolveDownloadsDir() (string, error) {
	if filepath.IsAbs(c.Update.DownloadsDir) {
		return c.Update.DownloadsDir, nil
	}
	return filepath.Abs(c.Update.DownloadsDir)
}

// ResolveDatabasePath returns the absolute path to the database,
// resolving relative paths relative to the config file's directory.
func (c *Config) ResolveDatabasePath() (string, error) {
	if filepath.IsAbs(c.Database.Path) {
		return c.Database.Path, nil
	}
	// Always resolve relative to CWD, not the config file directory,
	// so the database path is predictable regardless of config file location.
	return filepath.Abs(c.Database.Path)
}

// TopPorts returns the list of ports to scan. If no ports configured,
// returns the top 1000 common ports (delegated to caller for brevity here).
func (c *Config) TopPorts() []int {
	if len(c.Scan.Ports) == 0 {
		return defaultTopPorts()
	}
	return c.Scan.Ports
}

// defaultTopPorts returns the top 30 most commonly open ports.
func defaultTopPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
		993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
		6379, 8080, 8443, 9000, 9090, 27017,
	}
}
