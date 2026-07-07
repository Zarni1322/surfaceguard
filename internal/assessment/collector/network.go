package collector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// NetworkCollector gathers data from network devices via SNMP.
type NetworkCollector struct {
	session auth.Session
}

// NewNetworkCollector creates a collector for the given SNMP session.
func NewNetworkCollector(session auth.Session) *NetworkCollector {
	return &NetworkCollector{session: session}
}

// CollectAll runs all SNMP data collection and returns asset info.
func (c *NetworkCollector) CollectAll(ctx context.Context) (*models.AssetInfo, []models.SecurityFinding, error) {
	// sysDescr .1.3.6.1.2.1.1.1.0
	sysDescr, _ := c.get(ctx, "sysDescr")
	// sysName .1.3.6.1.2.1.1.5.0
	hostname, _ := c.get(ctx, ".1.3.6.1.2.1.1.5.0")
	// sysObjectID .1.3.6.1.2.1.1.2.0
	_ = "" // sysObjectID available via sysDescr

	vendor, model := parseSNMPDeviceInfo(sysDescr)

	asset := &models.AssetInfo{
		Hostname:  strings.TrimSpace(hostname),
		OS:        vendor,
		Distro:    model,
		AssetType: "network_device",
	}

	findings := c.collectFindings(ctx)
	return asset, findings, nil
}

// CollectInterfaces gathers interface information from the device.
func (c *NetworkCollector) CollectInterfaces(ctx context.Context) (string, error) {
	// ifDescr table .1.3.6.1.2.1.2.2.1.2
	return c.walk(ctx, ".1.3.6.1.2.1.2.2.1.2")
}

// collectFindings runs lightweight security checks on the network device.
func (c *NetworkCollector) collectFindings(ctx context.Context) []models.SecurityFinding {
	var findings []models.SecurityFinding

	// Check system uptime to determine if the device was recently rebooted.
	uptimeStr, err := c.get(ctx, ".1.3.6.1.2.1.1.3.0")
	if err == nil {
		uptimeParts := strings.Fields(uptimeStr)
		if len(uptimeParts) > 0 {
			if ticks, err := strconv.ParseInt(uptimeParts[0], 10, 64); err == nil {
				uptime := time.Duration(ticks) * time.Millisecond
				if uptime < 24*time.Hour {
					findings = append(findings, models.SecurityFinding{
						CheckID:  "net-uptime",
						Name:     "Device Recently Rebooted",
						Severity: "LOW",
						Status:   "warn",
						Evidence: fmt.Sprintf("Uptime: %s", uptime.Round(time.Second).String()),
					})
				}
			}
		}
	}

	return findings
}

func (c *NetworkCollector) get(ctx context.Context, oid string) (string, error) {
	return c.session.RunCommand(ctx, oid)
}

func (c *NetworkCollector) walk(ctx context.Context, oid string) (string, error) {
	return c.session.RunCommand(ctx, "walk "+oid)
}

func parseSNMPDeviceInfo(sysDescr string) (vendor, model string) {
	descr := strings.TrimSpace(sysDescr)
	if descr == "" {
		return "", ""
	}

	// Try common patterns: "Vendor Model ..."
	parts := strings.Fields(descr)
	if len(parts) >= 2 {
		vendor = parts[0]
		model = strings.Join(parts[1:], " ")
	}
	return vendor, model
}

var _ = fmt.Sprintf
var _ = strconv.Itoa
