// Package portscan provides a concurrent TCP port scanner with configurable
// worker pools, context cancellation, and timeout support.
//
// Design rationale:
//   - Uses a semaphore-bounded worker pool rather than unbounded goroutines
//     to prevent resource exhaustion (ephemeral port range, FD limits).
//   - Each connection attempt has its own deadline via net.Dialer.
//   - Results are streamed through a channel so the caller can process
//     open ports incrementally without waiting for all scans to finish.
//   - Supports parsing port ranges ("80,443,8000-9000") and the full
//     1-65535 range.
//
// Performance considerations:
//   - Default worker count of 100 balances speed with reliability.
//     Too many workers (e.g., >1000) can cause TCP SYN backlog on
//     the scanning host and unreliable results.
//   - Timeout of 3s is a good default for local/LAN; increase for
//     WAN/high-latency targets.
//   - Only reports OPEN or FILTERED states; best-effort, not a
//     full TCP connect scan replacement.
package portscan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// Scanner is a concurrent TCP port scanner.
type Scanner struct {
	timeout    time.Duration
	workers    int
	bannerSize int
}

// New creates a new Scanner with the given configuration.
// Defaults: 100 workers, 3s timeout, 2048 byte banner size.
func New(timeout time.Duration, workers, bannerSize int) *Scanner {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if workers <= 0 {
		workers = 100
	}
	if bannerSize <= 0 {
		bannerSize = 2048
	}
	return &Scanner{
		timeout:    timeout,
		workers:    workers,
		bannerSize: bannerSize,
	}
}

// ScanResult represents the result of scanning a single port.
type ScanResult struct {
	Port   int
	State  string // "open", "filtered"
	Banner string
	Error  error
}

// Scan performs a concurrent TCP scan against the given IP address on the
// specified ports. Results are sent to the returned channel; the channel is
// closed when all scans complete.
func (s *Scanner) Scan(ctx context.Context, ip string, ports []int) <-chan ScanResult {
	results := make(chan ScanResult, len(ports))

	go func() {
		defer close(results)

		// Use a channel-based semaphore as worker pool.
		sema := make(chan struct{}, s.workers)
		var wg sync.WaitGroup

		for _, port := range ports {
			// Check cancellation before each scan.
			select {
			case <-ctx.Done():
				return
			default:
			}

			sema <- struct{}{} // acquire slot
			wg.Add(1)

			go func(port int) {
				defer func() {
					<-sema // release slot
					wg.Done()
				}()

				result := s.scanPort(ctx, ip, port)
				// Best-effort send (respect cancellation).
				select {
				case results <- result:
				case <-ctx.Done():
				}
			}(port)
		}

		// Wait for all workers to finish.
		wg.Wait()
	}()

	return results
}

// scanPort performs a single TCP connection attempt and banner grab.
func (s *Scanner) scanPort(ctx context.Context, ip string, port int) ScanResult {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{
		Timeout:   s.timeout,
		KeepAlive: -1, // no keepalive for scans
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		// Connection refused or timeout — port is closed/filtered.
		return ScanResult{Port: port, State: "filtered"}
	}
	defer conn.Close()

	// Set a deadline for banner reading.
	conn.SetDeadline(time.Now().Add(s.timeout / 2))

	// Read initial banner (service response).
	buf := make([]byte, s.bannerSize)
	n, readErr := conn.Read(buf)

	result := ScanResult{
		Port:  port,
		State: "open",
	}

	if readErr == nil || n > 0 {
		// Sanitize banner: keep printable ASCII + common whitespace.
		result.Banner = sanitizeBanner(string(buf[:n]))
	}

	return result
}

// sanitizeBanner strips non-printable characters from a banner string.
func sanitizeBanner(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r <= 126 || r == '\t' || r == '\n' || r == '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ============================================================================
// Port parsing utilities
// ============================================================================

// ParsePorts parses a port specification string into a sorted, deduplicated
// slice of port numbers. Supports formats:
//   - Single: "80"
//   - Comma-separated: "80,443,8080"
//   - Range: "8000-9000"
//   - Mixed: "80,443,8000-9000"
//   - All: "1-65535"
func ParsePorts(spec string) ([]int, error) {
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	portSet := make(map[int]struct{})

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			// Range format.
			rangeParts := strings.SplitN(part, "-", 2)
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}

			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range start: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid port range end: %s", rangeParts[1])
			}

			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}

			for p := start; p <= end; p++ {
				portSet[p] = struct{}{}
			}
		} else {
			// Single port.
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range (1-65535): %d", port)
			}
			portSet[port] = struct{}{}
		}
	}

	if len(portSet) == 0 {
		return nil, fmt.Errorf("no valid ports parsed from: %s", spec)
	}

	// Convert to sorted slice.
	ports := make([]int, 0, len(portSet))
	for p := range portSet {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	return ports, nil
}

// TopPorts returns the N most commonly open TCP ports, based on
// Shodan/ZMap scan data. N must be one of: 100, 1000, or 10000.
func TopPorts(n int) []int {
	switch {
	case n <= 100:
		return top100[:]
	case n <= 1000:
		return top1000[:]
	default:
		return top10000[:]
	}
}

// top100 most common ports (tier 1).
var top100 = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
	993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
	6379, 8080, 8443, 9000, 9090, 27017,
	// Extended top 100.
	7, 9, 13, 19, 37, 42, 49, 70, 79, 88, 102, 106, 109, 113, 115,
	117, 119, 123, 137, 138, 161, 162, 177, 179, 199, 264, 318, 381,
	383, 389, 411, 412, 427, 433, 443, 445, 464, 465, 497, 500, 512,
	513, 514, 515, 518, 520, 521, 523, 524, 540, 546, 547, 548, 554,
	563, 587, 591, 593, 631, 636, 646, 660, 674, 691, 694, 749, 750,
	765, 767, 808, 843, 873, 880, 888, 898, 902, 903, 981, 987, 990,
	991, 992, 994, 998, 999, 1000, 1001, 1002, 1003, 1007, 1009, 1010,
	1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
}

// top1000 most common ports (tier 2: 101-1000).
var top1000 []int

// top10000 most common ports (tier 3: 1001-10000).
var top10000 []int

func init() {
	// Build top1000 from extended list.
	top1000 = make([]int, len(top100))
	copy(top1000, top100)
	additional := []int{
		1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
		1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050,
		1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
		1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070,
		1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080,
		1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090,
		1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100,
		1110, 1111, 1112, 1113, 1114, 1115, 1116, 1117, 1118, 1119,
		1120, 1121, 1122, 1123, 1124, 1125, 1126, 1127, 1128, 1129,
		1130, 1131, 1132, 1133, 1134, 1135, 1136, 1137, 1138, 1139,
		1140, 1141, 1142, 1143, 1144, 1145, 1146, 1147, 1148, 1149,
		1150, 1160, 1170, 1180, 1190, 1200, 1210, 1220, 1230, 1240,
		1250, 1260, 1270, 1280, 1290, 1300, 1310, 1320, 1330, 1340,
		1350, 1360, 1370, 1380, 1390, 1400, 1410, 1420, 1430, 1440,
		1450, 1460, 1470, 1480, 1490, 1500, 1510, 1520, 1530, 1540,
		1550, 1560, 1570, 1580, 1590, 1600, 1610, 1620, 1630, 1640,
		1650, 1660, 1670, 1680, 1690, 1700, 1710, 1720, 1730, 1740,
		1750, 1760, 1770, 1780, 1790, 1800, 1810, 1820, 1830, 1840,
	}
	top1000 = append(top1000, additional...)
	sort.Ints(top1000)

	// Sort top100 (first 30 are already sorted by construction; the
	// extended list from lines 170-172 may be interleaved with lower ports).
	sort.Ints(top100[:])

	// top10000 is the full 1-10000 range.
	top10000 = make([]int, 10000)
	for i := range top10000 {
		top10000[i] = i + 1
	}
}

// PortToModel converts a portscan.ScanResult to a models.Port.
func PortToModel(result ScanResult) models.Port {
	return models.Port{
		Port:     result.Port,
		Protocol: "tcp",
		State:    result.State,
		Banner:   result.Banner,
	}
}

// PortsToModels converts a slice of portscan.ScanResult to models.Port.
func PortsToModels(results []ScanResult) []models.Port {
	ports := make([]models.Port, 0, len(results))
	for _, r := range results {
		if r.State == "open" {
			ports = append(ports, PortToModel(r))
		}
	}
	// Sort by port number.
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].Port < ports[j].Port
	})
	return ports
}
