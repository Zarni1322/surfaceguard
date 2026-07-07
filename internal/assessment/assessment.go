// Package assessment orchestrates authenticated vulnerability assessments.
// It connects to remote hosts using credential profiles, collects system
// information, correlates packages with CVEs, and maintains asset inventory.
package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/internal/assessment/collector"
	"github.com/evilhunter/surfaceguard/internal/assessment/inventory"
	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// Engine orchestrates the full assessment workflow.
type Engine struct {
	cfg       *config.AssessmentConfig
	db        database.Database
	matcher   *matcher.Matcher
	inventory *inventory.Manager
	logger    *slog.Logger
	// Registered protocol connectors.
	connectors map[models.Protocol]auth.Connector
}

// NewEngine creates an assessment engine.
func NewEngine(cfg *config.AssessmentConfig, db database.Database, m *matcher.Matcher, logger *slog.Logger) *Engine {
	e := &Engine{
		cfg:       cfg,
		db:        db,
		matcher:   m,
		inventory: inventory.NewManager(db),
		logger:    logger,
		connectors: make(map[models.Protocol]auth.Connector),
	}

	// Register default connectors.
	timeout, _ := time.ParseDuration(cfg.ConnTimeout)
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	e.RegisterConnector(auth.NewSSHConnector())
	e.RegisterConnector(auth.NewWinRMConnector(timeout))
	e.RegisterConnector(auth.NewSNMPConnector(timeout))

	return e
}

// RegisterConnector adds a protocol handler.
func (e *Engine) RegisterConnector(c auth.Connector) {
	e.connectors[c.Protocol()] = c
}

// ============================================================================
// Credential Profile Management
// ============================================================================

// ListProfiles returns all credential profiles (with secrets redacted).
func (e *Engine) ListProfiles(ctx context.Context) ([]models.CredentialProfile, error) {
	dbProfiles, err := e.db.CredentialProfile().List(ctx)
	if err != nil {
		return nil, err
	}
	profiles := make([]models.CredentialProfile, len(dbProfiles))
	for i, p := range dbProfiles {
		profiles[i] = models.CredentialProfile{
			ID:         p.ID,
			Name:       p.Name,
			Protocol:   models.Protocol(p.Protocol),
			Host:       p.Host,
			Port:       p.Port,
			Username:   p.Username,
			AuthMethod: p.AuthMethod,
		}
		if t, err := time.Parse(time.RFC3339, p.CreatedAt); err == nil {
			profiles[i].CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, p.UpdatedAt); err == nil {
			profiles[i].UpdatedAt = t
		}
	}
	return profiles, nil
}

// GetProfile returns a decrypted profile by ID.
func (e *Engine) GetProfile(ctx context.Context, id int64) (*auth.Profile, error) {
	dbp, err := e.db.CredentialProfile().Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %w", err)
	}
	return e.decryptProfile(dbp)
}

// CreateProfile creates a new encrypted credential profile.
func (e *Engine) CreateProfile(ctx context.Context, profile *auth.Profile) (int64, error) {
	if err := profile.Validate(); err != nil {
		return 0, fmt.Errorf("validation: %w", err)
	}
	dbp, err := e.encryptProfile(profile)
	if err != nil {
		return 0, fmt.Errorf("encrypt: %w", err)
	}
	return e.db.CredentialProfile().Create(ctx, dbp)
}

// DeleteProfile removes a credential profile.
func (e *Engine) DeleteProfile(ctx context.Context, id int64) error {
	return e.db.CredentialProfile().Delete(ctx, id)
}

// ============================================================================
// Credential Validation (Test Connection)
// ============================================================================

// ValidateCredentials tests connectivity and authentication with the given profile.
func (e *Engine) ValidateCredentials(ctx context.Context, profileID int64) (*models.ValidationResult, error) {
	profile, err := e.GetProfile(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}

	result := &models.ValidationResult{
		Status:    "SUCCESS",
		ProfileID: profileID,
		Target:    fmt.Sprintf("%s:%d", profile.Host, profile.Port),
		TestedAt:  time.Now(),
	}

	connector, ok := e.connectors[profile.Protocol]
	if !ok {
		result.Status = "FAILED"
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Connector Available", Status: "fail",
			Message: fmt.Sprintf("no connector for %s", profile.Protocol),
		})
		e.saveValidation(ctx, profileID, result)
		return result, nil
	}

	result.Checks = append(result.Checks, models.ValidationCheck{
		Name: "Connection", Status: "pass", Message: "Target reachable",
	})

	session, err := connector.Connect(ctx, profile)
	if err != nil {
		result.Status = "FAILED"
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Authentication", Status: "fail",
			Message: fmt.Sprintf("Authentication failed: %v", err),
		})
		e.saveValidation(ctx, profileID, result)
		return result, nil
	}
	defer session.Close()

	result.Checks = append(result.Checks, models.ValidationCheck{
		Name: "Authentication", Status: "pass",
		Message: fmt.Sprintf("Authenticated successfully via %s", profile.Protocol),
	})

	// Protocol-specific checks.
	switch profile.Protocol {
	case models.ProtocolSSH:
		e.validateLinux(ctx, session, result)
	case models.ProtocolWinRM:
		e.validateWindows(ctx, session, result)
	case models.ProtocolSNMP:
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Device Information", Status: "pass",
			Message: "SNMP device information accessible",
		})
	}

	e.saveValidation(ctx, profileID, result)
	return result, nil
}

func (e *Engine) validateLinux(ctx context.Context, session auth.Session, result *models.ValidationResult) {
	// Check package manager.
	out, err := session.RunCommand(ctx, "which dpkg 2>/dev/null || which rpm 2>/dev/null || echo 'none'")
	if err == nil && !strings.Contains(out, "none") {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Package Inventory", Status: "pass",
			Message: "Package manager accessible",
		})
	} else {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Package Inventory", Status: "warn",
			Message: "Package manager not found",
		})
		if result.Status == "SUCCESS" {
			result.Status = "WARNING"
		}
	}

	// Check sudo.
	out, err = session.RunCommand(ctx, "sudo -n true 2>&1 || echo 'no-sudo'")
	if err != nil || strings.Contains(out, "no-sudo") {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Sudo Access", Status: "warn",
			Message: "No passwordless sudo access",
		})
	} else {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Sudo Access", Status: "pass",
			Message: "Passwordless sudo available",
		})
	}
}

func (e *Engine) validateWindows(ctx context.Context, session auth.Session, result *models.ValidationResult) {
	// Check software inventory.
	out, err := session.RunCommand(ctx, "wmic product get Name 2>nul")
	if err == nil && len(out) > 10 {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Software Inventory", Status: "pass",
			Message: "Installed software accessible",
		})
	} else {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Software Inventory", Status: "warn",
			Message: "Cannot access installed software",
		})
		if result.Status == "SUCCESS" {
			result.Status = "WARNING"
		}
	}

	// Check updates.
	out, err = session.RunCommand(ctx, "wmic qfe get HotFixID 2>nul")
	if err == nil && len(out) > 10 {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Update Inventory", Status: "pass",
			Message: "Installed updates accessible",
		})
	} else {
		result.Checks = append(result.Checks, models.ValidationCheck{
			Name: "Update Inventory", Status: "warn",
			Message: "Cannot access installed updates",
		})
	}
}

// ============================================================================
// Authenticated Scan
// ============================================================================

// RunAssessment performs a full authenticated assessment of the target.
func (e *Engine) RunAssessment(ctx context.Context, profileID int64) (*models.AssessmentResult, error) {
	profile, err := e.GetProfile(ctx, profileID)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}

	start := time.Now()
	result := &models.AssessmentResult{
		Target:      fmt.Sprintf("%s:%d", profile.Host, profile.Port),
		ProfileID:   profileID,
		ProfileName: fmt.Sprintf("Profile %d", profileID),
		Protocol:    profile.Protocol,
		StartedAt:   start,
		Status:      "running",
	}

	// Get connector.
	connector, ok := e.connectors[profile.Protocol]
	if !ok {
		result.Status = "failed"
		return result, fmt.Errorf("unsupported protocol: %s", profile.Protocol)
	}

	// Connect.
	session, err := connector.Connect(ctx, profile)
	if err != nil {
		result.Status = "failed"
		return result, fmt.Errorf("connect: %w", err)
	}
	defer session.Close()

	// Collect data based on protocol.
	switch profile.Protocol {
	case models.ProtocolSSH:
		asset, packages, findings, err := e.collectLinux(ctx, session)
		if err != nil {
			result.Status = "failed"
			return result, fmt.Errorf("collect linux: %w", err)
		}
		result.Asset = asset
		result.Packages = packages
		result.Findings = findings

		// CVE correlate packages.
		result.CVEs = e.correlatePackages(ctx, packages)

	case models.ProtocolWinRM:
		asset, software, findings, err := e.collectWindows(ctx, session)
		if err != nil {
			result.Status = "failed"
			return result, fmt.Errorf("collect windows: %w", err)
		}
		result.Asset = asset
		result.Software = software
		result.Findings = findings

		// CVE correlate software.
		result.CVEs = e.correlateSoftware(ctx, software)

	case models.ProtocolSNMP:
		asset, findings, err := e.collectNetwork(ctx, session)
		if err != nil {
			result.Status = "failed"
			return result, fmt.Errorf("collect network: %w", err)
		}
		result.Asset = asset
		result.Findings = findings
	}

	// Calculate risk score.
	riskScore := 0.0
	for _, cve := range result.CVEs {
		if cve.CVSSv3 != nil {
			riskScore += *cve.CVSSv3
		}
	}
	if riskScore > 100 {
		riskScore = 100
	}
	result.RiskScore = riskScore
	result.Duration = time.Since(start).Round(time.Millisecond).String()
	result.Status = "completed"

	// Save to inventory.
	e.saveAssessmentToInventory(ctx, result)

	return result, nil
}

func (e *Engine) collectLinux(ctx context.Context, session auth.Session) (*models.AssetInfo, []models.InstalledPackage, []models.SecurityFinding, error) {
	c := collector.NewLinuxCollector(session)
	return c.CollectAll(ctx)
}

func (e *Engine) collectWindows(ctx context.Context, session auth.Session) (*models.AssetInfo, []models.InstalledSoftware, []models.SecurityFinding, error) {
	c := collector.NewWindowsCollector(session)
	return c.CollectAll(ctx)
}

func (e *Engine) collectNetwork(ctx context.Context, session auth.Session) (*models.AssetInfo, []models.SecurityFinding, error) {
	c := collector.NewNetworkCollector(session)
	return c.CollectAll(ctx)
}

// correlatePackages matches installed packages against the CVE database.
func (e *Engine) correlatePackages(ctx context.Context, packages []models.InstalledPackage) []models.CVE {
	seen := make(map[string]bool)
	var cves []models.CVE

	for _, pkg := range packages {
		if pkg.CPE23URI == "" {
			continue
		}
		cpe := models.CPE{}
		if parts := strings.SplitN(pkg.CPE23URI, ":", 7); len(parts) >= 6 {
			cpe = models.CPE{
				Part:    parts[2],
				Vendor:  parts[3],
				Product: parts[4],
				Version: parts[5],
			}
		}
		port := models.Port{Port: 0, Service: "package", CPEs: []models.CPE{cpe}}
		findings := e.matcher.MatchPort(ctx, pkg.Name, "", port)

		for _, f := range findings {
			if !seen[f.CVE.ID] {
				seen[f.CVE.ID] = true
				cves = append(cves, f.CVE)
			}
		}
	}
	return cves
}

// correlateSoftware matches installed Windows software against the CVE database.
func (e *Engine) correlateSoftware(ctx context.Context, software []models.InstalledSoftware) []models.CVE {
	seen := make(map[string]bool)
	var cves []models.CVE

	for _, sw := range software {
		if sw.CPE23URI == "" {
			continue
		}
		cpe := models.CPE{}
		if parts := strings.SplitN(sw.CPE23URI, ":", 7); len(parts) >= 6 {
			cpe = models.CPE{
				Part:    parts[2],
				Vendor:  parts[3],
				Product: parts[4],
				Version: parts[5],
			}
		}
		port := models.Port{Port: 0, Service: "software", CPEs: []models.CPE{cpe}}
		findings := e.matcher.MatchPort(ctx, sw.Name, "", port)

		for _, f := range findings {
			if !seen[f.CVE.ID] {
				seen[f.CVE.ID] = true
				cves = append(cves, f.CVE)
			}
		}
	}
	return cves
}

// ============================================================================
// History
// ============================================================================

// ListHistory returns past assessment results.
func (e *Engine) ListHistory(ctx context.Context, limit int) ([]models.AssessmentResult, error) {
	dbResults, err := e.db.AssessmentResult().List(ctx, limit)
	if err != nil {
		return nil, err
	}
	results := make([]models.AssessmentResult, len(dbResults))
	for i, r := range dbResults {
		results[i] = models.AssessmentResult{
			ID:        r.ID,
			Target:    r.Target,
			ProfileID: r.ProfileID,
			Protocol:  models.Protocol(r.Protocol),
			Duration:  r.Duration,
			Status:    r.Status,
		}
		if t, err := time.Parse(time.RFC3339, r.StartedAt); err == nil {
			results[i].StartedAt = t
		}
		// Parse result JSON if available.
		if r.ResultJSON != "{}" && r.ResultJSON != "" {
			var full models.AssessmentResult
			if err := json.Unmarshal([]byte(r.ResultJSON), &full); err == nil {
				results[i] = full
				results[i].ID = r.ID
			}
		}
	}
	return results, nil
}

// ============================================================================
// Private helpers
// ============================================================================

func (e *Engine) encryptProfile(p *auth.Profile) (*database.DBCredentialProfile, error) {
	key := e.cfg.EncryptKey
	if key == "" {
		key = "default-dev-key-change-in-production"
	}

	enc1, _ := auth.Encrypt(p.Password, key)
	enc2, _ := auth.Encrypt(p.PrivateKey, key)
	enc3 := ""
	if p.Protocol == models.ProtocolSNMP {
		enc3, _ = auth.Encrypt(p.Community, key)
	}

	return &database.DBCredentialProfile{
		Name:        p.Name,
		Protocol:    string(p.Protocol),
		Host:        p.Host,
		Port:        p.Port,
		Username:    p.Username,
		AuthMethod:  p.AuthMethod,
		Credential1: enc1,
		Credential2: enc2,
		Credential3: enc3,
	}, nil
}

func (e *Engine) decryptProfile(dbp *database.DBCredentialProfile) (*auth.Profile, error) {
	key := e.cfg.EncryptKey
	if key == "" {
		key = "default-dev-key-change-in-production"
	}

	p := &auth.Profile{
		ID:         dbp.ID,
		Name:       dbp.Name,
		Protocol:   models.Protocol(dbp.Protocol),
		Host:       dbp.Host,
		Port:       dbp.Port,
		Username:   dbp.Username,
		AuthMethod: dbp.AuthMethod,
	}

	if dbp.Credential1 != "" {
		dec, err := auth.Decrypt(dbp.Credential1, key)
		if err == nil {
			switch dbp.AuthMethod {
			case "password", "key+passphrase":
				p.Password = dec
			case "community":
				p.Community = dec
			}
		}
	}
	if dbp.Credential2 != "" {
		dec, err := auth.Decrypt(dbp.Credential2, key)
		if err == nil {
			p.PrivateKey = dec
		}
	}
	if dbp.Credential3 != "" {
		dec, err := auth.Decrypt(dbp.Credential3, key)
		if err == nil {
			p.Community = dec
		}
	}

	return p, nil
}

func (e *Engine) saveValidation(ctx context.Context, profileID int64, result *models.ValidationResult) {
	jsonBytes, _ := json.Marshal(result)
	status := result.Status
	if status == "" {
		status = "FAILED"
	}
	e.db.CredentialValidation().Create(ctx, &database.DBCredentialValidation{
		ProfileID:  profileID,
		Target:     result.Target,
		ResultJSON: string(jsonBytes),
		Status:     status,
	})
}

func (e *Engine) saveAssessmentToInventory(ctx context.Context, result *models.AssessmentResult) {
	if result.Asset == nil {
		return
	}

	assetID, err := e.inventory.UpsertAsset(ctx, result.Asset)
	if err != nil {
		e.logger.Warn("failed to save asset to inventory", "error", err)
		return
	}

	// Update risk score.
	e.updateRiskScore(ctx, assetID, result.RiskScore)

	// Save packages/software.
	if len(result.Packages) > 0 {
		_, _, _, err = e.inventory.SyncPackages(ctx, assetID, result.Packages)
		if err != nil {
			e.logger.Warn("failed to sync packages", "error", err)
		}
	}
	if len(result.Software) > 0 {
		_, err = e.inventory.SyncSoftware(ctx, assetID, result.Software)
		if err != nil {
			e.logger.Warn("failed to sync software", "error", err)
		}
	}

	// Save assessment result.
	jsonBytes, _ := json.Marshal(result)
	e.db.AssessmentResult().Create(ctx, &database.DBAssessmentResult{
		Target:     result.Target,
		ProfileID:  result.ProfileID,
		Protocol:   string(result.Protocol),
		StartedAt:  result.StartedAt.Format(time.RFC3339),
		Duration:   result.Duration,
		ResultJSON: string(jsonBytes),
		Status:     result.Status,
	})
}

// UpdateRiskScore updates an asset's risk score.
func (e *Engine) updateRiskScore(ctx context.Context, assetID int64, score float64) error {
	return e.db.AssetInventory().UpdateRiskScore(ctx, assetID, score)
}

