// Package collector gathers system information from Linux, Windows, and
// network devices through authenticated sessions.
package collector

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// LinuxCollector gathers data from Linux hosts via SSH.
type LinuxCollector struct {
	session auth.Session
}

// NewLinuxCollector creates a collector for the given SSH session.
func NewLinuxCollector(session auth.Session) *LinuxCollector {
	return &LinuxCollector{session: session}
}

// CollectAll runs all Linux data collection commands and returns combined info.
func (c *LinuxCollector) CollectAll(ctx context.Context) (*models.AssetInfo, []models.InstalledPackage, []models.SecurityFinding, error) {
	hostname, _ := c.run(ctx, "hostname -f 2>/dev/null || hostname")
	osRelease, _ := c.run(ctx, "cat /etc/os-release 2>/dev/null | head -20")
	kernel, _ := c.run(ctx, "uname -r")
	arch, _ := c.run(ctx, "uname -m")

	asset := &models.AssetInfo{
		Hostname:      strings.TrimSpace(hostname),
		OS:            parseOSFromRelease(osRelease),
		Distro:        parseDistroFromRelease(osRelease),
		KernelVersion: strings.TrimSpace(kernel),
		Architecture:  strings.TrimSpace(arch),
		AssetType:     "linux",
	}

	packages := c.collectPackages(ctx)
	findings := c.collectSecurityFindings(ctx)

	return asset, packages, findings, nil
}

// collectPackages gets installed packages via dpkg or rpm and generates
// proper CPE 2.3 URIs using the NVD vendor/product mapping (vendor_map.go).
// When no mapping exists, it falls back to the legacy wildcard-vendor CPE.
func (c *LinuxCollector) collectPackages(ctx context.Context) []models.InstalledPackage {
	// Try dpkg-query first (Debian/Ubuntu), fall back to rpm (RHEL/Fedora).
	output, err := c.run(ctx, "dpkg-query -W -f '${Package} ${Version} ${Architecture}\\n' 2>/dev/null")
	if err != nil || len(output) < 10 {
		output, err = c.run(ctx, "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\\n' 2>/dev/null")
		if err != nil || len(output) < 10 {
			return nil
		}
	}

	var packages []models.InstalledPackage
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pkgName := strings.ToLower(parts[0])
		pkgVersion := parts[1]

		pkg := models.InstalledPackage{
			Name:    parts[0],
			Version: pkgVersion,
			Status:  "installed",
		}
		if len(parts) >= 3 {
			pkg.Arch = parts[2]
		}
		// Generate a CPE 2.3 URI — prefer the NVD vendor map, fall back to wildcard.
		pkg.CPE23URI = generateCPE23URI(pkgName, pkgVersion)
		packages = append(packages, pkg)
	}
	return packages
}

// generateCPE23URI produces a CPE 2.3 URI for the given package name and version.
//
// Resolution order:
//  1. Look up the package name in the NVD vendor/product mapping (vendor_map.go).
//     If found → use the proper vendor and product: cpe:2.3:a:{vendor}:{product}:{version}
//  2. If not mapped, try a heuristic: assume the package's own ecosystem name
//     is both vendor and product (works for many standalone projects).
//  3. Fall back to wildcard vendor: cpe:2.3:a:*:{pkg}:{version}
func generateCPE23URI(pkgName, pkgVersion string) string {
	// Strip Debian multi-arch suffixes like :amd64, :i386, :all
	cleanName := pkgName
	if idx := strings.Index(cleanName, ":"); idx > 0 {
		cleanName = cleanName[:idx]
	}

	// Step 1: Check the vendor map.
	if entry := LookupVendorProduct(cleanName); entry != nil {
		return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
			entry.Vendor, entry.Product, pkgVersion)
	}

	// Step 2: Heuristic — use package name as both vendor and product.
	// This works well for standalone projects like "nginx", "redis", "memcached".
	// We don't use this blindly — only when the name looks like a well-known
	// standalone product (no hyphens/underscores makes it look like a brand).
	// For names with separators, the vendor map is the only reliable source.
	isSimpleName := !strings.ContainsAny(cleanName, "-_+")
	if isSimpleName && len(cleanName) <= 20 {
		return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
			cleanName, cleanName, pkgVersion)
	}

	// Step 3: Fall back to wildcard vendor — lowest match probability
	// but keeps backward compatibility with product-only search fallbacks.
	return fmt.Sprintf("cpe:2.3:a:*:%s:%s:*:*:*:*:*:*:*", cleanName, pkgVersion)
}

// collectSecurityFindings runs lightweight security checks on Linux.
func (c *LinuxCollector) collectSecurityFindings(ctx context.Context) []models.SecurityFinding {
	var findings []models.SecurityFinding

	// 1. PermitRootLogin
	rootLogin, _ := c.run(ctx, "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null || echo 'not found'")
	if strings.Contains(strings.ToLower(rootLogin), "yes") && !strings.HasPrefix(strings.ToLower(rootLogin), "#") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "linux-root-login", Name: "SSH PermitRootLogin Enabled",
			Severity: "HIGH", Status: "fail", Evidence: strings.TrimSpace(rootLogin),
		})
	}

	// 2. PasswordAuthentication
	passAuth, _ := c.run(ctx, "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null || echo 'not found'")
	if strings.Contains(strings.ToLower(passAuth), "yes") && !strings.HasPrefix(strings.ToLower(passAuth), "#") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "linux-password-auth", Name: "SSH PasswordAuthentication Enabled",
			Severity: "MEDIUM", Status: "warn", Evidence: strings.TrimSpace(passAuth),
		})
	}

	// 3. Firewall status.
	fw, _ := c.run(ctx, "ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || echo 'inactive'")
	if strings.Contains(strings.ToLower(fw), "inactive") || strings.Contains(strings.ToLower(fw), "not running") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "linux-firewall", Name: "Firewall Disabled",
			Severity: "HIGH", Status: "fail", Evidence: strings.TrimSpace(fw),
		})
	}

	// 4. SELinux status.
	selinux, _ := c.run(ctx, "getenforce 2>/dev/null || echo 'not found'")
	if strings.Contains(strings.ToLower(selinux), "disabled") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "linux-selinux", Name: "SELinux Disabled",
			Severity: "MEDIUM", Status: "warn", Evidence: strings.TrimSpace(selinux),
		})
	}

	// 5. SSH service running.
	sshRunning, _ := c.run(ctx,
		"systemctl is-active ssh 2>/dev/null | grep -q active && echo 'active' || "+
			"service ssh status 2>/dev/null | grep -q running && echo 'active' || "+
			"pgrep -x sshd >/dev/null 2>&1 && echo 'active' || "+
			"echo 'inactive'")
	if !strings.Contains(sshRunning, "active") {
		findings = append(findings, models.SecurityFinding{
			CheckID: "linux-ssh-service", Name: "SSH Service Not Running",
			Severity: "HIGH", Status: "fail", Evidence: "SSH service is inactive",
		})
	}

	return findings
}

// run executes a command via the SSH session.
func (c *LinuxCollector) run(ctx context.Context, cmd string) (string, error) {
	return c.session.RunCommand(ctx, cmd)
}

func parseOSFromRelease(release string) string {
	re := regexp.MustCompile(`^ID\s*=\s*["']?([^"'\n]+)["']?`)
	matches := re.FindStringSubmatch(release)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return "linux"
}

func parseDistroFromRelease(release string) string {
	re := regexp.MustCompile(`^PRETTY_NAME\s*=\s*["']?([^"'\n]+)["']?`)
	matches := re.FindStringSubmatch(release)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	// Fallback to VERSION_ID.
	re = regexp.MustCompile(`^VERSION_ID\s*=\s*["']?([^"'\n]+)["']?`)
	matches = re.FindStringSubmatch(release)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
