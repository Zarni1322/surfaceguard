package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

type Format string

const (
	FormatConsole Format = "console"
	FormatJSON    Format = "json"
	FormatHTML    Format = "html"
)

func Generate(w io.Writer, result *models.ScanResult, format Format) error {
	switch format {
	case FormatConsole:
		return consoleReport(w, result)
	case FormatJSON:
		return jsonReport(w, result)
	case FormatHTML:
		return htmlReport(w, result)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}
}

func consoleReport(w io.Writer, result *models.ScanResult) error {
	fmt.Fprintf(w, "\n%s\n%s\n\n", centerText("SurfaceGuard Report", 60), repeatChar("=", 60))
	fmt.Fprintf(w, "  Target:     %s\n", result.Target.Raw)
	if len(result.Target.Hosts) > 0 { fmt.Fprintf(w, "  IP Address: %s\n", result.Target.Hosts[0]) }
	fmt.Fprintf(w, "  Started:    %s\n", result.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "  Duration:   %s\n", result.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, "  Open Ports: %d\n", len(result.OpenPorts))
	fmt.Fprintf(w, "  Findings:   %d\n", len(result.Findings))
	if result.RiskScore > 0 {
		fmt.Fprintf(w, "  Risk Score: %.0f/100 (%s)\n", result.RiskScore, models.RiskLabel(result.RiskScore))
	}
	fmt.Fprint(w, "\n")

	if len(result.OpenPorts) > 0 {
		fmt.Fprintf(w, "%-6s %-15s %-20s %-15s %s\n%s\n", "PORT", "STATE", "SERVICE", "VERSION", "PRODUCT", repeatChar("-", 80))
		for _, p := range result.OpenPorts {
			v, pr := p.Version, p.Product
			if v == "" { v = "-" }
			if pr == "" { pr = "-" }
			fmt.Fprintf(w, "%-6d %-15s %-20s %-15s %s\n", p.Port, p.State, p.Service, v, pr)
		}
		fmt.Fprintln(w)
	}

	if len(result.Findings) > 0 {
		sorted := make([]models.Finding, len(result.Findings))
		copy(sorted, result.Findings)
		matcher.SortFindings(sorted)
		fmt.Fprintf(w, "%s\n%s\n", centerText("Vulnerabilities Found", 60), repeatChar("-", 80))
		cp := 0
		for _, f := range sorted {
			if f.Port.Port != cp {
				cp = f.Port.Port
				fmt.Fprintf(w, "\n  Port %d/%s (%s)\n  %s\n", f.Port.Port, f.Port.Protocol, f.Port.Service, repeatChar("-", 60))
			}
			fmt.Fprintf(w, "  [%s] %s\n", colorSeverity(f.CVE.Severity), f.CVE.ID)
			fmt.Fprintf(w, "  CVSS: %s | Severity: %s", cvssString(f.CVE), colorSeverity(f.CVE.Severity))
			if f.CVE.IsInKEV { fmt.Fprintf(w, " | ⚠ KEV") }
			if f.CVE.EPSSScore != nil { fmt.Fprintf(w, " | EPSS: %.4f", *f.CVE.EPSSScore) }
			fmt.Fprintln(w)
			if f.CVE.Description != "" { fmt.Fprintf(w, "  %s\n", truncateString(f.CVE.Description, 120)) }
			if len(f.CVE.References) > 0 {
				fmt.Fprintf(w, "  References:\n")
				for _, ref := range f.CVE.References { fmt.Fprintf(w, "    - %s\n", ref) }
			}
			fmt.Fprintln(w)
		}
	}

	sc := countBySeverity(result.Findings)
	fmt.Fprintf(w, "%s\n  Summary:\n    Total Vulnerabilities: %d\n", repeatChar("=", 60), len(result.Findings))
	if result.RiskScore > 0 {
		fmt.Fprintf(w, "    Risk Score: %.0f/100 (%s)\n", result.RiskScore, models.RiskLabel(result.RiskScore))
	}
	if sc["CRITICAL"] > 0 { fmt.Fprintf(w, "    %s%d CRITICAL%s\n", colorRed, sc["CRITICAL"], colorReset) }
	if sc["HIGH"] > 0 { fmt.Fprintf(w, "    %s%d HIGH%s\n", colorYellow, sc["HIGH"], colorReset) }
	if sc["MEDIUM"] > 0 { fmt.Fprintf(w, "    %d MEDIUM\n", sc["MEDIUM"]) }
	if sc["LOW"] > 0 { fmt.Fprintf(w, "    %d LOW\n", sc["LOW"]) }

	if result.TLSInfo != nil {
		fmt.Fprintf(w, "\n  TLS: %s\n", result.TLSInfo.Version)
		if result.TLSInfo.DeprecatedProto {
			fmt.Fprintf(w, "    ⚠ Deprecated protocol\n")
		}
		if result.TLSInfo.WeakCipher {
			fmt.Fprintf(w, "    ⚠ Weak cipher suite\n")
		}
		if result.TLSInfo.CertificateCN != "" {
			fmt.Fprintf(w, "    Certificate: %s (expires %d days)\n", result.TLSInfo.CertificateCN, result.TLSInfo.DaysUntilExpiry)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func jsonReport(w io.Writer, result *models.ScanResult) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func htmlReport(w io.Writer, result *models.ScanResult) error {
	sc := countBySeverity(result.Findings)
	pr := ""
	for _, p := range result.OpenPorts {
		v, prd := p.Version, p.Product
		if v == "" { v = "-" }
		if prd == "" { prd = "-" }
		pr += fmt.Sprintf("<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>", p.Port, p.State, p.Service, html.EscapeString(v), html.EscapeString(prd))
	}
	sorted := make([]models.Finding, len(result.Findings))
	copy(sorted, result.Findings)
	matcher.SortFindings(sorted)
	fr := ""
	for _, f := range sorted {
		kb := ""
		if f.CVE.IsInKEV { kb = `<span class="kev-badge">KEV</span>` }
		es := ""
		if f.CVE.EPSSScore != nil { es = fmt.Sprintf("EPSS: %.4f", *f.CVE.EPSSScore) }
		rf := ""
		for _, r := range f.CVE.References { rf += fmt.Sprintf(`<li><a href="%s" target="_blank" rel="noopener">%s</a></li>`, html.EscapeString(r), html.EscapeString(truncateString(r, 80))) }
		if rf == "" { rf = `<li class="no-refs">No references</li>` }
		cs := cvssString(f.CVE)
		sv := severityCSSClass(f.CVE.Severity)
		fr += fmt.Sprintf(`<tr class="%s"><td><a href="https://nvd.nist.gov/vuln/detail/%s" target="_blank" rel="noopener">%s</a>%s</td><td>%d/%s</td><td>%s <span class="sev-badge %s">%s</span></td><td>%s</td><td>%s</td><td><ul>%s</ul></td></tr>`,
			sv, html.EscapeString(f.CVE.ID), html.EscapeString(f.CVE.ID), kb, f.Port.Port, f.Port.Protocol, cs, sv, f.CVE.Severity, es, html.EscapeString(truncateString(f.CVE.Description, 150)), rf)
	}
	tip := ""
	if len(result.Target.Hosts) > 0 { tip = result.Target.Hosts[0] }
	ss := ""
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if sc[s] > 0 { ss += fmt.Sprintf(`<span class="sev-count %s">%s: %d</span> `, severityCSSClass(s), s, sc[s]) }
	}

	h := fmt.Sprintf(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>SurfaceGuard Report - %s</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6;padding:20px}
.container{max-width:1200px;margin:0 auto}
h1{color:#58a6ff;font-size:1.8em;margin-bottom:10px}
h2{color:#58a6ff;font-size:1.3em;margin:25px 0 10px}
.header{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:20px}
.header-grid{display:grid;grid-template-columns:auto 1fr;gap:5px 15px}
.header-label{color:#8b949e}.header-value{color:#c9d1d9}
.summary-bar{display:flex;gap:10px;margin:10px 0;flex-wrap:wrap}
.sev-count{padding:4px 12px;border-radius:4px;font-weight:bold;font-size:0.9em}
.sev-badge{padding:2px 8px;border-radius:3px;font-size:0.85em;font-weight:bold;display:inline-block}
table{width:100%%;border-collapse:collapse;margin:10px 0 20px}
th{background:#161b22;color:#8b949e;text-align:left;padding:10px 12px;border-bottom:2px solid #30363d;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em}
td{padding:10px 12px;border-bottom:1px solid #21262d}
tr:hover{background:#1c2128}
a{color:#58a6ff;text-decoration:none}
a:hover{text-decoration:underline}
.kev-badge{background:#da3633;color:#fff;padding:1px 6px;border-radius:3px;font-size:0.75em;font-weight:bold;margin-left:5px}
.sev-CRITICAL td,.sev-HIGH td{border-left:3px solid}
.sev-CRITICAL td:first-child{border-left-color:#da3633}
.sev-HIGH td:first-child{border-left-color:#d29922}
.sev-MEDIUM td:first-child{border-left-color:#58a6ff}
.sev-LOW td:first-child{border-left-color:#8b949e}
.sev-CRITICAL .sev-badge{background:#da3633;color:#fff}
.sev-HIGH .sev-badge{background:#d29922;color:#fff}
.sev-MEDIUM .sev-badge{background:#1f6feb;color:#fff}
.sev-LOW .sev-badge{background:#21262d;color:#8b949e}
.footer{text-align:center;color:#8b949e;font-size:0.8em;margin-top:30px;padding-top:20px;border-top:1px solid #21262d}
</style></head><body><div class="container">
<h1>Vulnerability Scan Report</h1>
<div class="header"><div class="header-grid">
<span class="header-label">Target</span><span class="header-value">%s</span>
<span class="header-label">IP Address</span><span class="header-value">%s</span>
<span class="header-label">Scan Date</span><span class="header-value">%s</span>
<span class="header-label">Duration</span><span class="header-value">%s</span>
<span class="header-label">Open Ports</span><span class="header-value">%d</span>
<span class="header-label">Vulnerabilities</span><span class="header-value">%d</span>
</div><div class="summary-bar">%s</div></div>
<h2>Open Ports</h2>
<table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>Product</th></tr></thead><tbody>%s</tbody></table>
<h2>Vulnerabilities</h2>
<table><thead><tr><th>CVE ID</th><th>Port</th><th>CVSS / Severity</th><th>EPSS</th><th>Description</th><th>References</th></tr></thead><tbody>%s</tbody></table>
<div class="footer">Generated by SurfaceGuard &mdash; %s</div>
</div></body></html>`,
		html.EscapeString(result.Target.Raw), html.EscapeString(result.Target.Raw), html.EscapeString(tip),
		result.StartedAt.Format("2006-01-02 15:04:05 MST"), result.Duration.Round(time.Millisecond).String(),
		len(result.OpenPorts), len(result.Findings), ss, pr, fr, time.Now().Format(time.RFC3339))
	_, err := io.WriteString(w, h)
	return err
}

func centerText(text string, width int) string {
	if len(text) >= width { return text }
	return strings.Repeat(" ", (width-len(text))/2) + text
}

func repeatChar(char string, count int) string { return strings.Repeat(char, count) }

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen { return s }
	return s[:maxLen-3] + "..."
}

func cvssString(cve models.CVE) string {
	if cve.CVSSv3 != nil { return fmt.Sprintf("%.1f", *cve.CVSSv3) }
	if cve.CVSSv2 != nil { return fmt.Sprintf("%.1f (v2)", *cve.CVSSv2) }
	return "N/A"
}

func severityCSSClass(severity string) string {
	switch severity {
	case "CRITICAL": return "sev-CRITICAL"
	case "HIGH": return "sev-HIGH"
	case "MEDIUM": return "sev-MEDIUM"
	case "LOW": return "sev-LOW"
	default: return "sev-NONE"
	}
}

func countBySeverity(findings []models.Finding) map[string]int {
	c := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
	for _, f := range findings { c[f.CVE.Severity]++ }
	return c
}

const (
	colorReset = "\033[0m"
	colorRed   = "\033[31m"
	colorGreen = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue  = "\033[34m"
)

func colorSeverity(severity string) string {
	switch severity {
	case "CRITICAL": return colorRed + severity + colorReset
	case "HIGH": return colorYellow + severity + colorReset
	case "MEDIUM": return colorBlue + severity + colorReset
	default: return severity
	}
}
