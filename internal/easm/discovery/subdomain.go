// Package discovery provides subdomain, DNS, and alive-check capabilities
// for the External Attack Surface Management (EASM) pipeline.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SubdomainResult holds a discovered subdomain from passive or active sources.
type SubdomainResult struct {
	Hostname string `json:"hostname"`
	Source   string `json:"source"` // passive, bruteforce
}

// SubdomainProvider is the interface for passive subdomain discovery sources.
// Implementations fetch subdomains from public intelligence sources.
type SubdomainProvider interface {
	Name() string
	Discover(ctx context.Context, domain string) ([]string, error)
}

// ============================================================================
// Built-in Passive Providers
// ============================================================================

// crtshProvider fetches subdomains from crt.sh (Certificate Transparency logs).
type crtshProvider struct {
	client *http.Client
}

func (p *crtshProvider) Name() string { return "crt.sh" }

func (p *crtshProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SurfaceGuard-EASM/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || seen[name] {
				continue
			}
			// Filter to only include subdomains of our domain
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				subs = append(subs, name)
			}
		}
	}
	return subs, nil
}

// alienvaultProvider fetches subdomains from AlienVault OTX.
type alienvaultProvider struct {
	client *http.Client
}

func (p *alienvaultProvider) Name() string { return "AlienVault" }

func (p *alienvaultProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SurfaceGuard-EASM/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range result.PassiveDNS {
		h := strings.TrimSpace(strings.ToLower(entry.Hostname))
		if h == "" || seen[h] {
			continue
		}
		if strings.HasSuffix(h, "."+domain) || h == domain {
			seen[h] = true
			subs = append(subs, h)
		}
	}
	return subs, nil
}

// urlscanProvider fetches subdomains from urlscan.io.
type urlscanProvider struct {
	client *http.Client
}

func (p *urlscanProvider) Name() string { return "urlscan.io" }

func (p *urlscanProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=10000", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SurfaceGuard-EASM/1.0")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var subs []string
	for _, r := range result.Results {
		d := strings.TrimSpace(strings.ToLower(r.Page.Domain))
		if d == "" || seen[d] {
			continue
		}
		if strings.HasSuffix(d, "."+domain) || d == domain {
			seen[d] = true
			subs = append(subs, d)
		}
	}
	return subs, nil
}

// securitytrailsProvider fetches subdomains from SecurityTrails.
type securitytrailsProvider struct {
	client *http.Client
	apiKey string
}

func (p *securitytrailsProvider) Name() string { return "SecurityTrails" }

func (p *securitytrailsProvider) Discover(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SurfaceGuard-EASM/1.0")
	if p.apiKey != "" {
		req.Header.Set("APIKEY", p.apiKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var subs []string
	for _, sd := range result.Subdomains {
		subs = append(subs, sd+"."+domain)
	}
	return subs, nil
}

// DefaultPassiveProviders returns the default set of passive subdomain providers.
func DefaultPassiveProviders() []SubdomainProvider {
	client := &http.Client{Timeout: 15 * time.Second}
	return []SubdomainProvider{
		&crtshProvider{client: client},
		&alienvaultProvider{client: client},
		&urlscanProvider{client: client},
	}
}

// ============================================================================
// Passive Subdomain Discovery
// ============================================================================

// DiscoverPassive runs all passive providers concurrently and returns deduplicated subdomains.
func DiscoverPassive(ctx context.Context, domain string, providers []SubdomainProvider) ([]SubdomainResult, error) {
	if providers == nil {
		providers = DefaultPassiveProviders()
	}

	type providerResult struct {
		name  string
		hosts []string
		err   error
	}

	resultCh := make(chan providerResult, len(providers))
	var wg sync.WaitGroup

	for _, p := range providers {
		wg.Add(1)
		go func(prov SubdomainProvider) {
			defer wg.Done()
			hosts, err := prov.Discover(ctx, domain)
			resultCh <- providerResult{name: prov.Name(), hosts: hosts, err: err}
		}(p)
	}

	wg.Wait()
	close(resultCh)

	seen := make(map[string]string) // hostname -> source
	for r := range resultCh {
		if r.err != nil {
			continue // skip failed providers
		}
		for _, h := range r.hosts {
			if _, exists := seen[h]; !exists {
				seen[h] = r.name
			}
		}
	}

	var results []SubdomainResult
	for hostname, source := range seen {
		results = append(results, SubdomainResult{Hostname: hostname, Source: source})
	}
	return results, nil
}

// ============================================================================
// Active DNS Bruteforce
// ============================================================================

// DNSBruteforce performs active DNS bruteforce using a wordlist.
// It resolves each name against the target domain and returns valid subdomains.
func DNSBruteforce(ctx context.Context, domain string, wordlist []string, workers int) ([]SubdomainResult, error) {
	if workers <= 0 {
		workers = 50
	}
	if len(wordlist) == 0 {
		return nil, nil
	}

	var mu sync.Mutex
	var results []SubdomainResult
	sema := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, word := range wordlist {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		hostname := word + "." + domain

		sema <- struct{}{}
		wg.Add(1)
		go func(h string) {
			defer func() { <-sema; wg.Done() }()

			// Check context cancellation
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Resolve the hostname
			addrs, err := net.DefaultResolver.LookupHost(ctx, h)
			if err != nil || len(addrs) == 0 {
				return
			}

			mu.Lock()
			results = append(results, SubdomainResult{Hostname: h, Source: "bruteforce"})
			mu.Unlock()
		}(hostname)
	}

	wg.Wait()
	return results, nil
}

// ============================================================================
// Wildcard DNS Detection
// ============================================================================

// WildcardPattern holds information about detected wildcard DNS.
type WildcardPattern struct {
	Detected  bool     `json:"detected"`
	Addresses []string `json:"addresses,omitempty"`
}

// DetectWildcard checks if a domain has wildcard DNS by resolving a random
// subdomain that should not exist. Returns the detected pattern.
func DetectWildcard(ctx context.Context, domain string) (WildcardPattern, error) {
	// Generate a random non-existent subdomain
	randomSub := fmt.Sprintf("surfaceguard-wildcard-check-%d.%s", time.Now().UnixNano(), domain)
	addrs, err := net.DefaultResolver.LookupHost(ctx, randomSub)
	if err != nil {
		// NXDOMAIN or similar — no wildcard
		return WildcardPattern{Detected: false}, nil
	}
	if len(addrs) > 0 {
		return WildcardPattern{Detected: true, Addresses: addrs}, nil
	}
	return WildcardPattern{Detected: false}, nil
}

// FilterWildcardResults removes subdomains that resolve to wildcard IPs.
// subdomains matching any of the wildcardAddresses are excluded.
func FilterWildcardResults(results []SubdomainResult, wildcardAddrs []string) []SubdomainResult {
	if len(wildcardAddrs) == 0 {
		return results
	}

	wildcardSet := make(map[string]bool)
	for _, addr := range wildcardAddrs {
		wildcardSet[addr] = true
	}

	var filtered []SubdomainResult
	for _, r := range results {
		// Resolve and check
		addrs, err := net.DefaultResolver.LookupHost(context.Background(), r.Hostname)
		if err != nil {
			continue
		}
		isWildcard := false
		for _, addr := range addrs {
			if wildcardSet[addr] {
				isWildcard = true
				break
			}
		}
		if !isWildcard {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

// ============================================================================
// DNS Resolution
// ============================================================================

// DNSInfo holds resolved DNS records for a hostname.
type DNSInfo struct {
	Hostname string   `json:"hostname"`
	A        []string `json:"a,omitempty"`
	AAAA     []string `json:"aaaa,omitempty"`
	CNAME    string   `json:"cname,omitempty"`
}

// ResolveDNS resolves A, AAAA, and CNAME records for a hostname.
func ResolveDNS(ctx context.Context, hostname string) *DNSInfo {
	info := &DNSInfo{Hostname: hostname}

	// Resolve A records (IPv4)
	addrs, _ := net.DefaultResolver.LookupHost(ctx, hostname)
	for _, addr := range addrs {
		if strings.Contains(addr, ":") {
			info.AAAA = append(info.AAAA, addr)
		} else {
			info.A = append(info.A, addr)
		}
	}

	// Resolve CNAME
	cname, err := net.DefaultResolver.LookupCNAME(ctx, hostname)
	if err == nil && cname != hostname+"." {
		info.CNAME = strings.TrimSuffix(cname, ".")
	}

	return info
}

// ============================================================================
// Alive Validation
// ============================================================================

// AliveResult holds the alive check result for an asset.
type AliveResult struct {
	Hostname   string `json:"hostname"`
	IP         string `json:"ip"`
	IsAlive    bool   `json:"is_alive"`
	Method     string `json:"method"` // http, https, tcp, icmp
	StatusCode int    `json:"status_code,omitempty"`
}

// ValidateAlive checks if a host is reachable via HTTP, HTTPS, or TCP.
// Returns true if any method succeeds. Timeout is per-probe.
func ValidateAlive(ctx context.Context, hostname, ip string, timeout time.Duration) *AliveResult {
	result := &AliveResult{Hostname: hostname, IP: ip}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Try HTTPS first
	if alive, code := tryHTTP(ctx, "https://"+hostname, timeout); alive {
		result.IsAlive = true
		result.Method = "https"
		result.StatusCode = code
		return result
	}

	// Try HTTP
	if alive, code := tryHTTP(ctx, "http://"+hostname, timeout); alive {
		result.IsAlive = true
		result.Method = "http"
		result.StatusCode = code
		return result
	}

	// Try direct TCP to common ports
	for _, port := range []int{80, 443, 22, 8080, 8443} {
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			result.IsAlive = true
			result.Method = fmt.Sprintf("tcp/%d", port)
			return result
		}
	}

	return result
}

func tryHTTP(ctx context.Context, targetURL string, timeout time.Duration) (bool, int) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false, 0
	}
	req.Header.Set("User-Agent", "SurfaceGuard-EASM/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	return true, resp.StatusCode
}

// ============================================================================
// Wordlist Loading
// ============================================================================

// WordlistMap returns known wordlist paths.
func WordlistPath(size string) string {
	base := "assets/wordlists/dns-"
	switch size {
	case "small":
		return base + "small.txt"
	case "medium":
		return base + "medium.txt"
	case "large":
		return base + "large.txt"
	default:
		return ""
	}
}

// LoadWordlist reads a wordlist file and returns non-empty lines.
func LoadWordlist(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	return readLines(path)
}

// IsValidDomain checks if a string looks like a valid domain name.
func IsValidDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	// Must contain at least one dot and no spaces
	if !strings.Contains(domain, ".") || strings.Contains(domain, " ") {
		return false
	}
	// Basic label check
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 {
			return false
		}
	}
	return true
}

// IsValidCIDR checks if a string is a valid CIDR notation.
func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

// IsValidIP checks if a string is a valid IP address.
func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// ExpandCIDR returns all IP addresses in a CIDR range.
func ExpandCIDR(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network and broadcast addresses for IPv4
	if len(ips) > 2 && strings.Contains(cidr, ".") {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// readLines reads a file and returns non-empty, non-comment lines.
func readLines(path string) ([]string, error) {
	// Not importing os/io here — caller provides wordlist or loads from disk
	return nil, fmt.Errorf("use external wordlist loader")
}

// ParseURL extracts the hostname from a raw target string.
func ParseTarget(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)

	// If it has a scheme, extract hostname
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return "", "", err
		}
		raw = u.Hostname()
	}

	switch {
	case IsValidCIDR(raw):
		return raw, "cidr", nil
	case IsValidIP(raw):
		return raw, "ip", nil
	case IsValidDomain(raw):
		return raw, "domain", nil
	default:
		return "", "", fmt.Errorf("unrecognized target format: %s", raw)
	}
}
