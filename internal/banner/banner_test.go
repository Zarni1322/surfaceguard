package banner

import (
	"strings"
	"testing"
	"time"
)

func TestDisplayNoBanner(t *testing.T) {
	info := Info{Version: "1.0.0"}
	// Should not panic or produce output when suppressed.
	Display(info, true)
}

func TestRenderContainsProduct(t *testing.T) {
	info := Info{
		Version:    "1.0.0-test",
		BuildDate:  "2024-01-01",
		DBVersion:  "3",
		FeedStatus: "Up-to-date",
		CVEcount:   100,
		KEVcount:   10,
		EPSScount:  5000,
	}
	output := render(info)

	checks := []string{
		"Enterprise Infrastructure Vulnerability Scanner",
		"Cyber Ops Academy",
		"Han Niux",
		"1.0.0-test",
		"2024-01-01",
		"Up-to-date",
		"100",
		"10",
		"5000",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected banner to contain %q", check)
		}
	}
}

func TestRenderEmptyInfo(t *testing.T) {
	info := Info{}
	output := render(info)
	if len(output) == 0 {
		t.Fatal("expected non-empty banner")
	}
	if !strings.Contains(output, "Enterprise") {
		t.Error("expected product name in banner")
	}
}

func TestFeedStatusLabel(t *testing.T) {
	tests := []struct {
		t    time.Time
		want string
	}{
		{time.Time{}, "Unknown"},
		{time.Now(), "Up-to-date"},
		{time.Now().Add(-10 * 24 * time.Hour), "Update Available"},
	}
	for _, tc := range tests {
		got := FeedStatusLabel(tc.t)
		if got != tc.want {
			t.Errorf("FeedStatusLabel(%v) = %q, want %q", tc.t, got, tc.want)
		}
	}
}

func TestDefaultBuildDate(t *testing.T) {
	date := DefaultBuildDate()
	if len(date) < 10 {
		t.Errorf("expected valid date string, got %q", date)
	}
}

func TestLogoLoaded(t *testing.T) {
	if len(logo) == 0 {
		t.Fatal("expected logo to be embedded")
	}
	if len(logo) < 100 {
		t.Error("expected logo to contain block characters")
	}
}

func TestRenderVersion(t *testing.T) {
	info := Info{Version: "2.0.0"}
	output := render(info)
	if !strings.Contains(output, "2.0.0") {
		t.Errorf("expected version 2.0.0 in banner")
	}
}

func TestRenderDBVersion(t *testing.T) {
	info := Info{DBVersion: "3"}
	output := render(info)
	if !strings.Contains(output, "DB Version") {
		t.Error("expected DB Version label")
	}
}

func TestRenderNoCounts(t *testing.T) {
	info := Info{CVEcount: 0, KEVcount: 0, EPSScount: 0}
	output := render(info)
	if strings.Contains(output, "CVEs") {
		t.Error("expected no CVE count when zero")
	}
}

func TestRenderWithLastUpdate(t *testing.T) {
	info := Info{
		LastFeedUpdate: "2024-06-15 12:00:00 UTC",
		CVEcount:      50,
	}
	output := render(info)
	if !strings.Contains(output, "Last Update") {
		t.Error("expected Last Update line")
	}
	if !strings.Contains(output, "50") {
		t.Error("expected CVE count 50")
	}
}
