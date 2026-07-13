// Package main is the CLI entrypoint for SurfaceGuard.
//
// Commands:
//
//	scanner scan <target> [flags]   — Run a vulnerability scan
//	scanner update [flags]          — Update CVE/CPE/KEV/EPSS databases
//	scanner db info                 — Show database information
//	scanner db verify               — Run integrity check
//	scanner db vacuum               — Optimize database
//	scanner version                 — Show version information
//
// Dependency injection is wired here using the provided packages.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/evilhunter/surfaceguard/internal/banner"
	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/easm"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/internal/report"
	"github.com/evilhunter/surfaceguard/internal/scanner"
	"github.com/evilhunter/surfaceguard/internal/updater"
	"github.com/evilhunter/surfaceguard/pkg/models"
	"github.com/evilhunter/surfaceguard/pkg/portscan"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
// Version is set at build time via -ldflags.
var Version = "1.0.0-dev"

func main() {
	if err := execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func execute() error {
	// Load configuration.
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Set up logging.
	logger := setupLogger(cfg.Logging.Level, cfg.Logging.Format)

	// Create root command.
	var noBanner bool
	rootCmd := &cobra.Command{
		Use:   "surfaceguard",
		Short: "Enterprise Infrastructure Vulnerability Scanner",
		Long: `SurfaceGuard identifies exposed services and matches them against known CVEs using safe fingerprinting techniques.
services and matches them against known CVEs using safe fingerprinting techniques.

The scanner NEVER exploits vulnerabilities, attempts authentication, or performs
any destructive actions. It only identifies potential vulnerabilities based on
detected versions and publicly available vulnerability intelligence.`,
		Version:      Version,
		SilenceUsage: true,
		// Show banner before any command runs.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Only show for actual commands, not for help or completion.
			if cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			showStartupBanner(cfg, noBanner)
			return nil
		},
	}

	rootCmd.PersistentFlags().BoolVar(&noBanner, "no-banner", !cfg.ShowBanner, "Suppress startup banner")

	// Add subcommands.
	rootCmd.AddCommand(newScanCmd(cfg, logger))
	rootCmd.AddCommand(newUpdateCmd(cfg, logger))
	rootCmd.AddCommand(newDBCmd(cfg, logger))
	rootCmd.AddCommand(newExportCmd(cfg, logger))
	rootCmd.AddCommand(newVersionCmd())
	rootCmd.AddCommand(newEASMCmd(cfg, logger))

	return rootCmd.Execute()
}

// showStartupBanner displays the startup banner with dynamic information.
func showStartupBanner(cfg *config.Config, noBanner bool) {
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		banner.Display(banner.Info{
			Version:    Version,
			BuildDate:  banner.DefaultBuildDate(),
			DBVersion:  "N/A",
			FeedStatus: "Unknown",
		}, noBanner)
		return
	}

	// Try to open database to read metadata.
	db, err := database.NewSQLiteDatabase(context.Background(), dbPath)
	if err != nil {
		banner.Display(banner.Info{
			Version:    Version,
			BuildDate:  banner.DefaultBuildDate(),
			DBVersion:  "N/A",
			FeedStatus: "Unknown",
		}, noBanner)
		return
	}
	defer db.Close()

	info, err := db.Info(context.Background())
	if err != nil {
		banner.Display(banner.Info{
			Version:    Version,
			BuildDate:  banner.DefaultBuildDate(),
			DBVersion:  "N/A",
			FeedStatus: "Unknown",
		}, noBanner)
		return
	}

	lastUpdateStr := ""
	if !info.LastUpdated.IsZero() && info.LastUpdated.Year() > 1 {
		lastUpdateStr = info.LastUpdated.Format("2006-01-02 15:04:05 UTC")
	}

	banner.Display(banner.Info{
		Version:        Version,
		BuildDate:      banner.DefaultBuildDate(),
		DBVersion:      fmt.Sprintf("%d", info.SchemaVersion),
		FeedStatus:     banner.FeedStatusLabel(info.LastUpdated),
		LastFeedUpdate: lastUpdateStr,
		CVEcount:       info.CVECount,
		KEVcount:       info.KEVCount,
		EPSScount:      info.EPSSCount,
	}, noBanner)
}

// loadConfig loads configuration from the default path or environment.
func loadConfig() (*config.Config, error) {
	// Look for config in several locations.
	configPaths := []string{
		config.DefaultConfigPath,
		filepath.Join(os.Getenv("HOME"), ".surfaceguard.yaml"),
		"/etc/surfaceguard/surfaceguard.yaml",
	}

	var cfg *config.Config
	var lastErr error
	for _, path := range configPaths {
		if _, err := os.Stat(path); err == nil {
			cfg, err = config.LoadConfig(path)
			if err == nil {
				return cfg, nil
			}
			lastErr = err
		}
	}

	// If no config file found, use defaults.
	if lastErr == nil {
		return config.LoadConfig("")
	}
	return nil, lastErr
}

// setupLogger creates a structured logger with the given level and format.
func setupLogger(level, format string) *slog.Logger {
	var logLevel slog.Level
	switch strings.ToLower(level) {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: logLevel}

	var handler slog.Handler
	switch strings.ToLower(format) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	return slog.New(handler)
}

// ============================================================================
// Scan Command
// ============================================================================

type scanFlags struct {
	ports         string
	workers       int
	timeout       string
	format        string
	output        string
	cvssThreshold float64
	fingerprint   bool
	file          string
		useDB         bool
}

func newScanCmd(cfg *config.Config, logger *slog.Logger) *cobra.Command {
	f := &scanFlags{}

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan a target for vulnerabilities",
		Long: `Scan a domain, IPv4 address, or CIDR range for open ports and
vulnerabilities. Uses safe fingerprinting techniques — never exploits or
probes beyond banner grabbing.

Examples:
  scanner scan example.com
  scanner scan 10.0.0.1 --ports 80,443,8080
  scanner scan 10.0.0.0/24 --workers 200 --format json
  scanner scan example.com --cvss-threshold 7.0 --format html --output report.html`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd, cfg, logger, f, args[0])
		},
	}

	// Flags.
	cmd.Flags().StringVarP(&f.ports, "ports", "p", "", "Port(s) to scan (e.g. '80,443' or '1-1000')")
	cmd.Flags().IntVarP(&f.workers, "workers", "w", cfg.Scan.Workers, "Number of concurrent workers")
	cmd.Flags().StringVar(&f.timeout, "timeout", cfg.Scan.Timeout.String(), "Connection timeout per port")
	cmd.Flags().StringVarP(&f.format, "format", "f", cfg.Report.DefaultFormat, "Output format (console, json, html)")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "Write report to file (instead of stdout)")
	cmd.Flags().Float64Var(&f.cvssThreshold, "cvss-threshold", cfg.Report.CVSSThreshold, "Minimum CVSSv3 score to report")
	cmd.Flags().BoolVar(&f.fingerprint, "fingerprint", cfg.Scan.Fingerprint, "Enable HTTP fingerprinting")
	cmd.Flags().StringVarP(&f.file, "file", "T", "", "File containing targets (one per line)")
	cmd.Flags().BoolVar(&f.useDB, "db", false, "Enable CPE database matching (requires NVD database)")

	return cmd
}

func runScan(cmd *cobra.Command, cfg *config.Config, logger *slog.Logger, f *scanFlags, targetArg string) error {
	ctx, cancel := signalContext()
	defer cancel()

	// Parse the target.
	target, err := parseTarget(targetArg)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Build scan options.
	opts := models.DefaultScanOptions()

	// Parse ports.
	if f.ports != "" {
		ports, err := portscan.ParsePorts(f.ports)
		if err != nil {
			return fmt.Errorf("invalid ports: %w", err)
		}
		opts.Ports = ports
	} else {
		opts.Ports = cfg.TopPorts()
	}
	opts.Workers = f.workers
	opts.FingerprintHTTP = f.fingerprint
	opts.CVSSThreshold = f.cvssThreshold
	opts.OutputFormat = f.format
	opts.OutputFile = f.output

		// Phase E: Database + CPE matcher are optional. Without --db, only template engine runs.
		var m *matcher.Matcher
		if f.useDB {
			dbPath, err := cfg.ResolveDatabasePath()
			if err != nil {
				return fmt.Errorf("resolving database path: %w", err)
			}
			if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
				return fmt.Errorf("creating data directory: %w", err)
			}
			db, err := database.NewSQLiteDatabase(ctx, dbPath)
			if err != nil {
				return fmt.Errorf("opening database: %w", err)
			}
			defer db.Close()
			m = matcher.NewWithOptions(db, matcher.Options{
				MinConfidenceForFallback: cfg.Scan.MinConfidenceForFallback,
			})
			logger.Info("CPE database enabled")
		}
		s := scanner.NewWithMatcher(cfg, m, "templates", logger)

	// Run the scan.
	logger.Info("starting scan", "target", targetArg, "ports", len(opts.Ports))
	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Generate report.
	var writer *os.File
	if f.output != "" {
		writer, err = os.Create(f.output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer writer.Close()
		logger.Info("writing report", "path", f.output, "format", f.format)
	} else {
		writer = os.Stdout
	}

	var fmtType report.Format
	switch f.format {
	case "json":
		fmtType = report.FormatJSON
	case "html":
		fmtType = report.FormatHTML
	default:
		fmtType = report.FormatConsole
	}

	if err := report.Generate(writer, result, fmtType); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	return nil
}

// ============================================================================
// Export Command
// ============================================================================

type exportFlags struct {
	format string
	output string
}

func newExportCmd(cfg *config.Config, logger *slog.Logger) *cobra.Command {
	f := &exportFlags{}
	cmd := &cobra.Command{
		Use:   "export <report.json>",
		Short: "Export scan results (JSON/HTML)",
		Long: `Export scan results to a file. Reads scan history from the database
and generates a report in the specified format.

Examples:
  scanner export report.html --format html
  scanner export results.json --format json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.output = args[0]
			return runExport(cmd, cfg, logger, f)
		},
	}
	cmd.Flags().StringVarP(&f.format, "format", "f", "html", "Output format (html, json)")
	return cmd
}

func runExport(cmd *cobra.Command, cfg *config.Config, logger *slog.Logger, f *exportFlags) error {
	if f.format != "html" && f.format != "json" {
		return fmt.Errorf("unsupported format: %s (use html or json)", f.format)
	}
	ctx := context.Background()
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	info, _ := db.Info(ctx)
	fmt.Printf("Database: %d CVEs, %d KEV, %d EPSS (schema v%d)\n",
		info.CVECount, info.KEVCount, info.EPSSCount, info.SchemaVersion)
	fmt.Printf("Writing %s report to %s\n", f.format, f.output)

	// Build a minimal ScanResult for the report.
	result := &models.ScanResult{
		Target:    models.Target{Raw: "NVD Database Export"},
		StartedAt: time.Now(),
		Duration:  0,
	}

	var fmtType report.Format
	switch f.format {
	case "json":
		fmtType = report.FormatJSON
	default:
		fmtType = report.FormatHTML
	}

	writer, err := os.Create(f.output)
	if err != nil {
		return fmt.Errorf("creating file: %w", err)
	}
	defer writer.Close()

	return report.Generate(writer, result, fmtType)
}

// ============================================================================
// Update Command
// ============================================================================

func newUpdateCmd(cfg *config.Config, logger *slog.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Update vulnerability databases",
		Long: `Download and update CVE, CPE, KEV, and EPSS data from public sources.
Uses incremental updates when possible.

Examples:
  scanner update`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd, cfg, logger)
		},
	}
}

func runUpdate(cmd *cobra.Command, cfg *config.Config, logger *slog.Logger) error {
	ctx, cancel := signalContext()
	defer cancel()

	logger.Info("checking for updates")

	// Open database.
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("creating data directory: %w", err)
	}

	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Create updater.
	u := updater.New(&cfg.Update, db, logger)

	stats, err := u.RunAll(ctx)
	if err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Printf("NVD:   Inserted %d / Updated %d\n", stats.CVEsInserted, stats.CVEsUpdated)
	fmt.Printf("KEV:   Inserted %d\n", stats.KEVInserted)
	fmt.Printf("EPSS:  Inserted %d\n", stats.EPSSInserted)
	fmt.Println("========================================")
	if len(stats.Errors) > 0 {
		fmt.Printf("Errors: %d\n", len(stats.Errors))
		for _, e := range stats.Errors {
			fmt.Printf("  - %s\n", e)
		}
	} else {
		fmt.Println("Database updated successfully.")
	}
	fmt.Println()

	return nil
}

// ============================================================================
// DB Commands
// ============================================================================

func newDBCmd(cfg *config.Config, logger *slog.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Database management commands",
		Long:  `Manage the local CVE database: view info, verify integrity, optimize.`,
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "info",
		Short: "Show database information",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBInfo(cfg, logger)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Run database integrity check",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBVerify(cfg, logger)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "vacuum",
		Short: "Optimize database (reclaim space)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDBVacuum(cfg, logger)
		},
	})

	return cmd
}

func runDBInfo(cfg *config.Config, logger *slog.Logger) error {
	ctx := context.Background()

	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}

	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	info, err := db.Info(ctx)
	if err != nil {
		return fmt.Errorf("getting database info: %w", err)
	}

	fmt.Println("Database Information")
	fmt.Println("====================")
	fmt.Printf("  Database Version:   %d\n", info.SchemaVersion)
	fmt.Printf("  Last Updated:       %s\n", info.LastUpdated.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("  Total CVEs:         %d\n", info.CVECount)
	fmt.Printf("  Total CPEs:         %d\n", info.CPECount)
	fmt.Printf("  Total Products:     %d\n", info.ProductCount)
	fmt.Printf("  Total Vendors:      %d\n", info.VendorCount)
	fmt.Printf("  Total KEV Entries:  %d\n", info.KEVCount)
	fmt.Printf("  Total EPSS Entries: %d\n", info.EPSSCount)
	fmt.Printf("  Integrity Check:    %v\n", info.IntegrityOK)

	return nil
}

func runDBVerify(cfg *config.Config, logger *slog.Logger) error {
	ctx := context.Background()

	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}

	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	ok, err := db.Verify(ctx)
	if err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	if ok {
		fmt.Println("Database integrity: OK")
	} else {
		fmt.Println("Database integrity: FAILED")
		return fmt.Errorf("database integrity check failed")
	}

	return nil
}

func runDBVacuum(cfg *config.Config, logger *slog.Logger) error {
	ctx := context.Background()

	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}

	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	fmt.Println("Optimizing database...")

	if err := db.Vacuum(ctx); err != nil {
		return fmt.Errorf("vacuum failed: %w", err)
	}

	fmt.Println("Database optimized successfully.")
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// ============================================================================
// EASM Command
// ============================================================================

type easmFlags struct {
	wordlist     string
	ports        string
	customPorts  string
	screenshots  bool
	workers      int
	format       string
	output       string
	wordlistFile string
}

func newEASMCmd(cfg *config.Config, logger *slog.Logger) *cobra.Command {
	f := &easmFlags{}

	cmd := &cobra.Command{
		Use:   "easm <target>",
		Short: "External Attack Surface Management scan",
		Long: `Discover external assets and assess their exposure.

Runs the full EASM pipeline: passive subdomain discovery, optional DNS bruteforce,
wildcard detection, DNS resolution, alive validation, port scanning, service
fingerprinting, and CVE/KEV/EPSS correlation.

Examples:
  surfaceguard easm example.com
  surfaceguard easm example.com --wordlist medium
  surfaceguard easm 192.168.1.0/24 --ports full
  surfaceguard easm example.com --wordlist custom --wordlist-file mylist.txt`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEASM(cmd, cfg, logger, f, args[0])
		},
	}

	cmd.Flags().StringVarP(&f.wordlist, "wordlist", "w", "passive", "Wordlist size: passive, small, medium, large, custom")
	cmd.Flags().StringVar(&f.ports, "ports", "fast", "Port scan level: fast, full")
	cmd.Flags().StringVar(&f.customPorts, "custom-ports", "", "Custom ports (when --ports=custom)")
	cmd.Flags().BoolVar(&f.screenshots, "screenshots", false, "Enable screenshot capture (HTTP/HTTPS)")
	cmd.Flags().IntVarP(&f.workers, "workers", "W", cfg.EASM.Workers, "Number of workers")
	cmd.Flags().StringVarP(&f.format, "format", "f", "console", "Output format: console, json, html")
	cmd.Flags().StringVarP(&f.output, "output", "o", "", "Write report to file")
	cmd.Flags().StringVar(&f.wordlistFile, "wordlist-file", "", "Custom wordlist file path")

	return cmd
}

func runEASM(cmd *cobra.Command, cfg *config.Config, logger *slog.Logger, f *easmFlags, target string) error {
	ctx, cancel := signalContext()
	defer cancel()

	// Parse the target.
	targetType, err := detectTargetType(target)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// Open database.
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return fmt.Errorf("resolving database path: %w", err)
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Create matcher and orchestrator.
	m := matcher.NewWithOptions(db, matcher.Options{
		MinConfidenceForFallback: cfg.Scan.MinConfidenceForFallback,
	})
	orch := easm.NewOrchestrator(cfg, db, m, logger)

	// Build scan request.
	req := models.EASMScanRequest{
		Target:  target,
		Workers: f.workers,
		Ports:   models.EASMPortLevel(f.ports),
	}
	switch targetType {
	case "domain":
		req.ScanType = models.EASMScanDomain
		req.Wordlist = models.EASMWordlistSize(f.wordlist)
		if f.wordlistFile != "" {
			req.Wordlist = models.EASMWordlistCustom
		}
	case "cidr":
		req.ScanType = models.EASMScanCIDR
		req.Wordlist = models.EASMWordlistPassive
	case "ip":
		req.ScanType = models.EASMScanIP
		req.Wordlist = models.EASMWordlistPassive
	}

	// Run the EASM pipeline.
	result, err := orch.Run(ctx, req, nil)
	if err != nil {
		return fmt.Errorf("EASM scan failed: %w", err)
	}

	// Print summary.
	fmt.Println()
	fmt.Println("========================================")
	fmt.Printf("  EASM Scan Complete: %s\n", target)
	fmt.Println("========================================")
	fmt.Printf("  Status:      %s\n", result.Scan.Status)
	fmt.Printf("  Assets:      %d total, %d alive\n", result.Scan.TotalAssets, result.Scan.AliveAssets)
	fmt.Printf("  Services:    %d\n", result.Scan.TotalServices)
	fmt.Printf("  CVEs Found:  %d (C:%d H:%d M:%d L:%d)\n",
		result.Scan.TotalCVEs, result.Scan.CriticalCVEs,
		result.Scan.HighCVEs, result.Scan.MediumCVEs, result.Scan.LowCVEs)
	if result.Scan.KEVCVEs > 0 {
		fmt.Printf("  KEV:         %d\n", result.Scan.KEVCVEs)
	}
	fmt.Println("========================================")
	fmt.Println()

	return nil
}

// detectTargetType determines whether the target is a domain, CIDR, or IP.
func detectTargetType(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		if _, _, err := net.ParseCIDR(raw); err == nil {
			return "cidr", nil
		}
		return "", fmt.Errorf("invalid CIDR: %s", raw)
	}
	if net.ParseIP(raw) != nil {
		return "ip", nil
	}
	if strings.Contains(raw, ".") {
		return "domain", nil
	}
	return "", fmt.Errorf("unrecognized target: %s", raw)
}

// ============================================================================
// Version Command
// ============================================================================

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("SurfaceGuard v%s\n", Version)
			fmt.Printf("Build: %s\n", Version)
			fmt.Printf("License: MIT\n")
		},
	}
}

// parseTarget creates a Target from a raw input string (domain or IP).
func parseTarget(raw string) (*models.Target, error) {
	// Try as IP first.
	if strings.Contains(raw, "/") {
		// CIDR notation — future: expand to IP range.
		return nil, fmt.Errorf("CIDR ranges not yet supported, use a single IP or domain")
	}

	if ip := os.Getenv("SURFACEGUARD_TARGET_OVERRIDE"); ip != "" {
		raw = ip
	}

	// Try as IP.
	if strings.Count(raw, ".") == 3 || strings.Contains(raw, ":") {
		if t, err := models.NewTargetFromIP(raw); err == nil {
			return t, nil
		}
	}

	// Try as domain.
	if t, err := models.NewTargetFromDomain(raw); err == nil {
		return t, nil
	}

	return nil, fmt.Errorf("could not parse target: %s (must be a domain or IPv4 address)", raw)
}

// signalContext returns a context that cancels on SIGINT or SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}
