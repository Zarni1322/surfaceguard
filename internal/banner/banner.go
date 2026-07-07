package banner

import (
	"fmt"
	"strings"
	"time"
)

// Info holds all dynamic values displayed in the banner.
type Info struct {
	Version        string
	BuildDate      string
	DBVersion      string
	LastFeedUpdate string
	FeedStatus     string
	CVEcount       int
	KEVcount       int
	EPSScount      int
}

// Display prints the banner with dynamic values to stdout.
func Display(info Info, noBanner bool) {
	if noBanner {
		return
	}
	fmt.Print(render(info))
}

// render constructs the full banner string.
func render(info Info) string {
	var b strings.Builder

	// ASCII logo.
	b.WriteString(logo)
	b.WriteString("\n")

	// Separator.
	sep := "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	b.WriteString("  ")
	b.WriteString(sep)
	b.WriteString("\n")

	// Organization.
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Organization", "Cyber Ops Academy"))
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Product", "Enterprise Infrastructure Vulnerability Scanner"))
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Author", "Han Niux"))

	// Separator.
	b.WriteString("  ")
	b.WriteString(strings.Repeat("─", 50))
	b.WriteString("\n")

	// Runtime info.
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Version", info.Version))
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Build Date", info.BuildDate))
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "DB Version", info.DBVersion))
	b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Feed Status", info.FeedStatus))

	// Feed update if available.
	if info.LastFeedUpdate != "" && info.LastFeedUpdate != "0001-01-01 00:00:00 UTC" {
		b.WriteString(fmt.Sprintf("  %-20s  %s\n", "Last Update", info.LastFeedUpdate))
	}

	// DB record counts (only if non-zero).
	if info.CVEcount > 0 || info.KEVcount > 0 || info.EPSScount > 0 {
		b.WriteString("  ")
		b.WriteString(strings.Repeat("─", 50))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %-20s  %d\n", "CVEs", info.CVEcount))
		b.WriteString(fmt.Sprintf("  %-20s  %d\n", "KEV", info.KEVcount))
		b.WriteString(fmt.Sprintf("  %-20s  %d\n", "EPSS", info.EPSScount))
	}

	// Trailing separator.
	b.WriteString("  ")
	b.WriteString(sep)
	b.WriteString("\n\n")

	return b.String()
}

// DefaultBuildDate returns a formatted build date string.
func DefaultBuildDate() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
}

// FeedStatusLabel returns a human-readable feed status.
func FeedStatusLabel(lastUpdate time.Time) string {
	if lastUpdate.IsZero() || lastUpdate.Year() <= 1 {
		return "Unknown"
	}
	if time.Since(lastUpdate) > 7*24*time.Hour {
		return "Update Available"
	}
	return "Up-to-date"
}
var logo = `  ███████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ███████╗██║   ██║██████╔╝█████╗  ███████║██║     █████╗  ██║   ██║███████║██████╔╝██║  ██║
  ╚════██║██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝  ██║   ██║██╔══██║██╔══██╗██║  ██║
  ███████║╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝`
