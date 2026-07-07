package collector

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// WindowsCollector gathers data from Windows hosts via WinRM.
type WindowsCollector struct {
	session auth.Session
}

// NewWindowsCollector creates a collector for the given WinRM session.
func NewWindowsCollector(session auth.Session) *WindowsCollector {
	return &WindowsCollector{session: session}
}

// CollectAll runs all Windows data collection commands and returns combined info.
func (c *WindowsCollector) CollectAll(ctx context.Context) (*models.AssetInfo, []models.InstalledSoftware, []models.SecurityFinding, error) {
	hostname, _ := c.run(ctx, "hostname")
	osInfo, _ := c.run(ctx, "wmic os get Caption,BuildNumber /format:csv 2>nul")
	os := parseWindowsOS(osInfo)
	build := parseWindowsBuild(osInfo)
	if build != "" {
		os = os + " (Build " + build + ")"
	}

	asset := &models.AssetInfo{
		Hostname:  strings.TrimSpace(hostname),
		OS:        os,
		AssetType: "windows",
	}

	software := c.collectSoftware(ctx)
	findings := c.collectSecurityFindings(ctx)

	return asset, software, findings, nil
}

// collectSoftware gets installed software from the Windows registry.
func (c *WindowsCollector) collectSoftware(ctx context.Context) []models.InstalledSoftware {
	output, err := c.run(ctx, `wmic product get Name,Version,Vendor,InstallDate /format:csv 2>nul`)
	if err != nil || len(output) < 10 {
		return nil
	}

	var software []models.InstalledSoftware
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines[1:] { // skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 4 {
			continue
		}
		sw := models.InstalledSoftware{
			Name:        strings.TrimSpace(parts[1]),
			Version:     strings.TrimSpace(parts[2]),
			Vendor:      strings.TrimSpace(parts[3]),
			CPE23URI: fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*",
				strings.ToLower(strings.ReplaceAll(parts[1], " ", "_")),
				strings.TrimSpace(parts[2])),
		}
		if len(parts) >= 5 {
			sw.InstallDate = strings.TrimSpace(parts[4])
		}
		software = append(software, sw)
	}
	return software
}

// collectSecurityFindings runs lightweight security checks on Windows.
func (c *WindowsCollector) collectSecurityFindings(ctx context.Context) []models.SecurityFinding {
	var findings []models.SecurityFinding

	// 1. Guest account status.
	guest, _ := c.run(ctx, `wmic useraccount where Name='Guest' get Disabled /format:csv 2>nul`)
	if !strings.Contains(strings.ToLower(guest), "true") && !strings.Contains(strings.ToLower(guest), "yes") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "win-guest-account", Name: "Guest Account Enabled",
			Severity: "HIGH", Status: "fail",
		})
	}

	// 2. Firewall status.
	fw, _ := c.run(ctx, `netsh advfirewall show allprofiles state 2>nul`)
	if strings.Contains(strings.ToLower(fw), "off") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "win-firewall", Name: "Windows Firewall Disabled",
			Severity: "HIGH", Status: "fail",
		})
	}

	// 3. Windows Defender status.
	defender, _ := c.run(ctx, `powershell -Command "Get-MpComputerStatus | Select-Object -Property RealTimeProtectionEnabled" 2>nul`)
	if !strings.Contains(strings.ToLower(defender), "true") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "win-defender", Name: "Windows Defender Disabled",
			Severity: "HIGH", Status: "warn",
		})
	}

	// 4. SMBv1 status.
	smb1, _ := c.run(ctx, `powershell -Command "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol 2>$null | Select-Object -ExpandProperty State" 2>nul`)
	if strings.Contains(strings.ToLower(smb1), "enabled") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "win-smbv1", Name: "SMBv1 Enabled",
			Severity: "HIGH", Status: "fail",
		})
	}

	// 5. BitLocker status.
	bitlocker, _ := c.run(ctx, `powershell -Command "Get-BitLockerVolume -MountPoint C: 2>$null | Select-Object -ExpandProperty ProtectionStatus" 2>nul`)
	if !strings.Contains(strings.ToLower(bitlocker), "on") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "win-bitlocker", Name: "BitLocker Not Enabled",
			Severity: "MEDIUM", Status: "warn",
		})
	}

	return findings
}

func (c *WindowsCollector) run(ctx context.Context, cmd string) (string, error) {
	return c.session.RunCommand(ctx, cmd)
}

// ============================================================================
// Parsing helpers
// ============================================================================

func parseWindowsOS(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			name := strings.TrimSpace(parts[1])
			if name != "" && !strings.HasPrefix(name, "Caption") {
				return name
			}
		}
	}
	return "Windows"
}

func parseWindowsBuild(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ",")
		if len(parts) >= 3 {
			build := strings.TrimSpace(parts[2])
			if build != "" && build != "BuildNumber" {
				return build
			}
		}
	}
	return ""
}

// Ensure unused import is suppressed.
var _ = fmt.Sprintf
var _ = regexp.Compile
