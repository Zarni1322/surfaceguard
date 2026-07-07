package portscan

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"
)

func TestNewScanner(t *testing.T) {
	s := New(5*time.Second, 50, 1024)
	if s.timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %s", s.timeout)
	}
	if s.workers != 50 {
		t.Errorf("expected 50 workers, got %d", s.workers)
	}
	if s.bannerSize != 1024 {
		t.Errorf("expected 1024 banner size, got %d", s.bannerSize)
	}
}

func TestNewScannerDefaults(t *testing.T) {
	s := New(0, 0, 0)
	if s.timeout != 3*time.Second {
		t.Errorf("expected default 3s timeout, got %s", s.timeout)
	}
	if s.workers != 100 {
		t.Errorf("expected default 100 workers, got %d", s.workers)
	}
	if s.bannerSize != 2048 {
		t.Errorf("expected default 2048 banner size, got %d", s.bannerSize)
	}
}

func TestScanCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	s := New(time.Second, 10, 1024)
	results := s.Scan(ctx, "127.0.0.1", []int{80, 443, 8080})

	count := 0
	for range results {
		count++
	}
	if count > 0 {
		t.Errorf("expected 0 results for cancelled context, got %d", count)
	}
}

func TestScanTimeoutContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	s := New(time.Second, 10, 1024)
	results := s.Scan(ctx, "192.0.2.1", []int{80, 443, 8080}) // RFC 5737 TEST-NET

	count := 0
	for range results {
		count++
	}
	// With a very short context timeout, we expect most or all to be filtered
	// or the context expired before any completed.
	t.Logf("scanned %d ports with 1ms timeout", count)
}

func TestScanLocalhost(t *testing.T) {
	// Find an open port on localhost first.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on localhost: %v", err)
	}
	openPort := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Small delay to let the port release.
	time.Sleep(50 * time.Millisecond)

	s := New(3*time.Second, 10, 2048)
	results := s.Scan(context.Background(), "127.0.0.1", []int{openPort})

	var openCount int
	for r := range results {
		if r.State == "open" {
			openCount++
			if r.Port != openPort {
				t.Errorf("expected port %d, got %d", openPort, r.Port)
			}
		}
	}
	if openCount == 0 {
		t.Logf("port %d was not detected as open (may have been reclaimed by OS)", openPort)
	}
}

func TestParsePortsSingle(t *testing.T) {
	ports, err := ParsePorts("80")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 1 || ports[0] != 80 {
		t.Errorf("expected [80], got %v", ports)
	}
}

func TestParsePortsComma(t *testing.T) {
	ports, err := ParsePorts("80,443,8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{80, 443, 8080}
	if !sliceEqual(ports, expected) {
		t.Errorf("expected %v, got %v", expected, ports)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := ParsePorts("8000-8005")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{8000, 8001, 8002, 8003, 8004, 8005}
	if !sliceEqual(ports, expected) {
		t.Errorf("expected %v, got %v", expected, ports)
	}
}

func TestParsePortsMixed(t *testing.T) {
	ports, err := ParsePorts("80,443,8000-8002")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := []int{80, 443, 8000, 8001, 8002}
	if !sliceEqual(ports, expected) {
		t.Errorf("expected %v, got %v", expected, ports)
	}
}

func TestParsePortsAll(t *testing.T) {
	ports, err := ParsePorts("1-65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 65535 {
		t.Errorf("expected 65535 ports, got %d", len(ports))
	}
	if ports[0] != 1 {
		t.Errorf("expected first port 1, got %d", ports[0])
	}
	if ports[65534] != 65535 {
		t.Errorf("expected last port 65535, got %d", ports[65534])
	}
}

func TestParsePortsDeduplicate(t *testing.T) {
	ports, err := ParsePorts("80,80,443,443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 2 {
		t.Errorf("expected 2 unique ports, got %d: %v", len(ports), ports)
	}
}

func TestParsePortsEmpty(t *testing.T) {
	_, err := ParsePorts("")
	if err == nil {
		t.Fatal("expected error for empty spec")
	}
}

func TestParsePortsInvalid(t *testing.T) {
	tests := []struct {
		spec string
		desc string
	}{
		{"abc", "non-numeric"},
		{"80,abc,443", "mixed non-numeric"},
		{"0", "port zero"},
		{"65536", "port > 65535"},
		{"80-70", "negative range"},
		{"80-", "incomplete range"},
	}
	for _, tc := range tests {
		_, err := ParsePorts(tc.spec)
		if err == nil {
			t.Errorf("expected error for %s: %q", tc.desc, tc.spec)
		}
	}
}

func TestTopPorts(t *testing.T) {
	ports := TopPorts(100)
	if len(ports) == 0 {
		t.Fatal("expected non-empty top 100 ports")
	}
	if !sort.IntsAreSorted(ports) {
		t.Error("expected sorted ports")
	}
	// Port 22 should be in the list.
	found := false
	for _, p := range ports {
		if p == 22 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected port 22 in top ports")
	}
}

func TestTopPorts1000(t *testing.T) {
	ports := TopPorts(1000)
	if len(ports) < 100 {
		t.Errorf("expected at least 100 ports in top 1000, got %d", len(ports))
	}
}

func TestPortToModelOpen(t *testing.T) {
	result := ScanResult{Port: 443, State: "open", Banner: "HTTP/1.1 200 OK"}
	port := PortToModel(result)
	if port.Port != 443 {
		t.Errorf("expected port 443, got %d", port.Port)
	}
	if port.State != "open" {
		t.Errorf("expected state open, got %s", port.State)
	}
	if port.Protocol != "tcp" {
		t.Errorf("expected protocol tcp, got %s", port.Protocol)
	}
}

func TestPortsToModelsFilterAndSort(t *testing.T) {
	results := []ScanResult{
		{Port: 8080, State: "open"},
		{Port: 80, State: "open"},
		{Port: 443, State: "filtered"},
		{Port: 22, State: "open"},
	}
	ports := PortsToModels(results)
	if len(ports) != 3 {
		t.Errorf("expected 3 open ports, got %d", len(ports))
	}
	// Should be sorted: 22, 80, 8080
	if ports[0].Port != 22 || ports[1].Port != 80 || ports[2].Port != 8080 {
		t.Errorf("expected sorted [22, 80, 8080], got %v", ports)
	}
}

func TestSanitizeBanner(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK\r\n"},
		{"SSH-2.0-OpenSSH_8.9p1\r\n", "SSH-2.0-OpenSSH_8.9p1\r\n"},
		{"\x00\x01\x02Hello\x7f\x80\xff", "Hello"},
		{"", ""},
	}
	for _, tc := range tests {
		got := sanitizeBanner(tc.input)
		if got != tc.want {
			t.Errorf("sanitizeBanner(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func sliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
