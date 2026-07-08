// Package wordlist manages DNS subdomain wordlists for the EASM module.
// It handles downloading from remote sources, version tracking, checksum
// verification, and local caching. Wordlists are never downloaded during
// scanning — only through the Update Center or first-run setup.
package wordlist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// WordlistSize identifies the three bundled wordlist sizes.
type WordlistSize string

const (
	SizeSmall  WordlistSize = "small"
	SizeMedium WordlistSize = "medium"
	SizeLarge  WordlistSize = "large"
)

// SourceURLs maps wordlist sizes to their SecLists download URLs.
var SourceURLs = map[WordlistSize]string{
	SizeSmall:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt",
	SizeMedium: "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
	SizeLarge:  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt",
}

// AssetnoteFallback are fallback URLs if SecLists is unreachable.
var AssetnoteFallback = map[WordlistSize]string{
	SizeSmall:  "https://wordlists-cdn.assetnote.io/data/manual/dns_subdomains_2023_01_15.txt",
	SizeMedium: "https://wordlists-cdn.assetnote.io/data/manual/dns_subdomains_2023_04_01.txt",
	SizeLarge:  "https://wordlists-cdn.assetnote.io/data/manual/dns_subdomains_2023_09_01.txt",
}

// MetadataFile is the path where wordlist metadata is stored.
const MetadataFile = "data/wordlists/metadata.json"

// WordlistDir is the directory where wordlist files are stored.
const WordlistDir = "assets/wordlists/dns"

// WordlistEntry holds metadata for one wordlist file.
type WordlistEntry struct {
	Size           string `json:"size"`
	Source         string `json:"source"`
	DownloadURL    string `json:"download_url"`
	Version        string `json:"version"`
	DownloadedAt   string `json:"downloaded_at"`
	LastChecked    string `json:"last_checked"`
	ChecksumSHA256 string `json:"checksum_sha256"`
	FileSize       int64  `json:"file_size"`
	Status         string `json:"status"` // installed, missing, corrupted, updating
}

// Metadata holds the complete wordlist metadata.
type Metadata struct {
	CurrentVersion string                   `json:"current_version"`
	LatestVersion  string                   `json:"latest_version"`
	LastUpdated    string                   `json:"last_updated"`
	Wordlists      map[string]WordlistEntry `json:"wordlists"`
}

// Manager handles all wordlist operations.
type Manager struct {
	baseDir  string
	metaPath string
	mu       sync.RWMutex
	client   *http.Client
	cache    map[WordlistSize][]string // cached wordlist contents
}

// NewManager creates a new wordlist manager.
func NewManager(baseDir string) *Manager {
	if baseDir == "" {
		baseDir = "."
	}
	return &Manager{
		baseDir:  baseDir,
		metaPath: filepath.Join(baseDir, MetadataFile),
		client:   &http.Client{Timeout: 60 * time.Second},
		cache:    make(map[WordlistSize][]string),
	}
}

// IsInstalled checks whether all three wordlist sizes are present and valid.
func (m *Manager) IsInstalled() bool {
	meta, err := m.LoadMetadata()
	if err != nil {
		return false
	}
	for _, size := range []WordlistSize{SizeSmall, SizeMedium, SizeLarge} {
		entry, ok := meta.Wordlists[string(size)]
		if !ok || entry.Status != "installed" {
			return false
		}
		path := m.wordlistPath(size)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// Status returns a human-readable status string for the UI.
func (m *Manager) Status() string {
	if m.IsInstalled() {
		meta, _ := m.LoadMetadata()
		if meta != nil && meta.LatestVersion != "" && meta.LatestVersion != meta.CurrentVersion {
			return "update_available"
		}
		return "installed"
	}
	return "missing"
}

// LoadMetadata reads the metadata file from disk.
func (m *Manager) LoadMetadata() (*Metadata, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, err := os.ReadFile(m.metaPath)
	if err != nil {
		return &Metadata{
			Wordlists: make(map[string]WordlistEntry),
		}, nil
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return &Metadata{Wordlists: make(map[string]WordlistEntry)}, nil
	}
	if meta.Wordlists == nil {
		meta.Wordlists = make(map[string]WordlistEntry)
	}
	return &meta, nil
}

// SaveMetadata writes the metadata file to disk.
func (m *Manager) SaveMetadata(meta *Metadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(m.metaPath), 0755); err != nil {
		return fmt.Errorf("create metadata dir: %w", err)
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	if err := os.WriteFile(m.metaPath, data, 0644); err != nil {
		return fmt.Errorf("write metadata: %w", err)
	}
	return nil
}

// DownloadAll downloads all three wordlists from the primary source with
// fallback support. Returns the number of successfully downloaded wordlists.
func (m *Manager) DownloadAll(ctx context.Context, progress func(size string, pct int)) (int, error) {
	sizes := []WordlistSize{SizeSmall, SizeMedium, SizeLarge}
	success := 0

	meta, _ := m.LoadMetadata()

	for _, size := range sizes {
		if progress != nil {
			progress(string(size), 0)
		}
		url := SourceURLs[size]

		// Try primary source (SecLists)
		err := m.downloadOne(ctx, size, url, meta)
		if err != nil {
			// Fallback to Assetnote
			fallbackURL := AssetnoteFallback[size]
			if fallbackURL == "" {
				continue
			}
			err = m.downloadOne(ctx, size, fallbackURL, meta)
			if err != nil {
				continue
			}
			// Update source in metadata
			if entry, ok := meta.Wordlists[string(size)]; ok {
				entry.Source = "assetnote"
				entry.DownloadURL = fallbackURL
				meta.Wordlists[string(size)] = entry
			}
		}
		success++
		if progress != nil {
			progress(string(size), 100)
		}
	}

	if success > 0 {
		meta.CurrentVersion = time.Now().UTC().Format("2006.01.02")
		meta.LastUpdated = time.Now().UTC().Format(time.RFC3339)
		m.SaveMetadata(meta)
	}

	return success, nil
}

// downloadOne downloads a single wordlist, verifies it, and saves it.
func (m *Manager) downloadOne(ctx context.Context, size WordlistSize, url string, meta *Metadata) error {
	// Ensure directory exists
	dir := filepath.Join(m.baseDir, WordlistDir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Download to temp file
	tmpPath := filepath.Join(dir, fmt.Sprintf(".%s.tmp", size))
	out, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		out.Close()
		os.Remove(tmpPath)
		return err
	}
	req.Header.Set("User-Agent", "SurfaceGuard/1.0")

	resp, err := m.client.Do(req)
	if err != nil {
		out.Close()
		os.Remove(tmpPath)
		return err
	}
	defer resp.Body.Close()

	written, err := io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Verify it's a valid text file with content
	if written < 100 {
		os.Remove(tmpPath)
		return fmt.Errorf("downloaded file too small: %d bytes", written)
	}

	// Compute checksum
	checksum, err := fileChecksum(tmpPath)
	if err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Move temp file to final location
	finalPath := filepath.Join(dir, fmt.Sprintf("%s.txt", size))
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Update metadata
	source := "seclists"
	if strings.Contains(url, "assetnote") {
		source = "assetnote"
	}
	meta.Wordlists[string(size)] = WordlistEntry{
		Size:           string(size),
		Source:         source,
		DownloadURL:    url,
		Version:        time.Now().UTC().Format("2006.01.02"),
		DownloadedAt:   time.Now().UTC().Format(time.RFC3339),
		LastChecked:    time.Now().UTC().Format(time.RFC3339),
		ChecksumSHA256: checksum,
		FileSize:       written,
		Status:         "installed",
	}

	return nil
}

// LoadWordlist reads a wordlist file into memory and caches it.
func (m *Manager) LoadWordlist(size WordlistSize) ([]string, error) {
	// Check cache first
	m.mu.RLock()
	if cached, ok := m.cache[size]; ok {
		m.mu.RUnlock()
		return cached, nil
	}
	m.mu.RUnlock()

	path := m.wordlistPath(size)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("wordlist %s not found: %w", size, err)
	}

	// Parse lines, deduplicate, sort
	seen := make(map[string]bool)
	var words []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || seen[line] {
			continue
		}
		seen[line] = true
		words = append(words, line)
	}
	sort.Strings(words)

	// Cache
	m.mu.Lock()
	m.cache[size] = words
	m.mu.Unlock()

	return words, nil
}

// InvalidateCache clears the in-memory wordlist cache.
func (m *Manager) InvalidateCache() {
	m.mu.Lock()
	m.cache = make(map[WordlistSize][]string)
	m.mu.Unlock()
}

// VerifyIntegrity checks all wordlist files against their stored checksums.
func (m *Manager) VerifyIntegrity() (map[string]bool, error) {
	meta, err := m.LoadMetadata()
	if err != nil {
		return nil, err
	}

	results := make(map[string]bool)
	for size, entry := range meta.Wordlists {
		path := m.wordlistPath(WordlistSize(size))
		if _, err := os.Stat(path); os.IsNotExist(err) {
			results[size] = false
			continue
		}
		checksum, err := fileChecksum(path)
		if err != nil {
			results[size] = false
			continue
		}
		results[size] = checksum == entry.ChecksumSHA256
	}
	return results, nil
}

// RepairMissing downloads any wordlists that are missing or corrupted.
func (m *Manager) RepairMissing(ctx context.Context) (int, error) {
	meta, _ := m.LoadMetadata()
	integrity, _ := m.VerifyIntegrity()

	repaired := 0
	for _, size := range []WordlistSize{SizeSmall, SizeMedium, SizeLarge} {
		if ok := integrity[string(size)]; !ok {
			url := SourceURLs[size]
			if entry, ok := meta.Wordlists[string(size)]; ok && entry.DownloadURL != "" {
				url = entry.DownloadURL
			}
			if err := m.downloadOne(ctx, size, url, meta); err != nil {
				continue
			}
			repaired++
		}
	}
	if repaired > 0 {
		m.InvalidateCache()
		m.SaveMetadata(meta)
	}
	return repaired, nil
}

// CheckForUpdates checks if newer wordlists are available by comparing dates.
func (m *Manager) CheckForUpdates(ctx context.Context) (bool, string, error) {
	meta, _ := m.LoadMetadata()

	// Fetch the SecLists repo to check latest commit date (simple HEAD request)
	latestVersion := meta.CurrentVersion
	needsUpdate := false

	for _, size := range []WordlistSize{SizeSmall, SizeMedium, SizeLarge} {
		url := SourceURLs[size]
		req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "SurfaceGuard/1.0")
		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		// Check Last-Modified header
		lastMod := resp.Header.Get("Last-Modified")
		if lastMod == "" {
			continue
		}
		modTime, err := time.Parse(time.RFC1123, lastMod)
		if err != nil {
			continue
		}
		version := modTime.Format("2006.01.02")
		if version > latestVersion {
			latestVersion = version
			needsUpdate = true
		}
	}

	meta.LatestVersion = latestVersion
	meta.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	m.SaveMetadata(meta)

	return needsUpdate, latestVersion, nil
}

// DeleteCache removes all downloaded wordlists and metadata.
func (m *Manager) DeleteCache() error {
	m.InvalidateCache()

	// Remove wordlist files
	dir := filepath.Join(m.baseDir, WordlistDir)
	os.RemoveAll(dir)

	// Remove metadata
	os.Remove(m.metaPath)

	// Remove empty metadata dir
	os.Remove(filepath.Dir(m.metaPath))

	return nil
}

// WordlistCount returns the number of entries in each wordlist.
func (m *Manager) WordlistCount(size WordlistSize) int {
	words, err := m.LoadWordlist(size)
	if err != nil {
		return 0
	}
	return len(words)
}

// wordlistPath returns the filesystem path for a given wordlist size.
func (m *Manager) wordlistPath(size WordlistSize) string {
	return filepath.Join(m.baseDir, WordlistDir, fmt.Sprintf("%s.txt", size))
}

// fileChecksum computes SHA-256 hash of a file.
func fileChecksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
