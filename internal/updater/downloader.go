package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/evilhunter/surfaceguard/internal/config"
)

// Downloader handles resumable downloads with temp file staging.
type Downloader struct {
	cfg    *config.UpdateConfig
	client *http.Client
}

func newDownloader(cfg *config.UpdateConfig, client *http.Client) *Downloader {
	return &Downloader{cfg: cfg, client: client}
}

// DownloadResult holds the outcome of a download.
type DownloadResult struct {
	FilePath    string // final (staged) file path
	TempPath    string // .tmp path
	BytesOffset int64  // bytes already on disk (0 for fresh, >0 for resume)
	FileHash    string // SHA-256 hex
	Resumed     bool   // true if the download was resumed from a partial file
}

// DownloadFile downloads a URL to a .tmp file in the downloads directory.
// If dstPath already exists and the server supports Range requests, it resumes.
// On success returns the DownloadResult with the path to the .tmp file.
// The caller must rename it to its final name after verification.
func (d *Downloader) DownloadFile(ctx context.Context, url, dstPath string, prevOffset int64) (*DownloadResult, error) {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir downloads: %w", err)
	}

	tmpPath := dstPath + ".tmp"
	res := &DownloadResult{
		FilePath: dstPath,
		TempPath: tmpPath,
	}

	// Determine offset: prefer prevOffset from checkpoint, else check existing file.
	offset := prevOffset
	if offset <= 0 {
		if fi, err := os.Stat(tmpPath); err == nil {
			offset = fi.Size()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	req.Header.Set("User-Agent", "SurfaceGuard/1.0")
	req.Header.Set("Accept", "application/json")

	var file *os.File
	if offset > 0 {
		// Attempt resume — open existing file for appending.
		file, err = os.OpenFile(tmpPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err == nil {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
			res.BytesOffset = offset
			res.Resumed = true
		} else {
			// Can't open existing — start fresh.
			file, err = os.Create(tmpPath)
			if err != nil {
				return nil, fmt.Errorf("create tmp: %w", err)
			}
			offset = 0
		}
	} else {
		file, err = os.Create(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("create tmp: %w", err)
		}
	}

	resp, err := d.client.Do(req)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		// Server says the range is invalid — file is already complete.
		file.Close()
		res.FileHash = sha256HashFile(tmpPath)
		return res, nil
	}

	if offset > 0 && resp.StatusCode != http.StatusPartialContent {
		// Server doesn't support Range — restart from scratch.
		file.Close()
		os.Remove(tmpPath)
		file, err = os.Create(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("create tmp (fallback): %w", err)
		}
		res.Resumed = false
		res.BytesOffset = 0
		// Retry without Range header.
		req.Header.Del("Range")
		resp.Body.Close()
		resp, err = d.client.Do(req)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("http (fallback): %w", err)
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		file.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}

	written, err := io.Copy(file, resp.Body)
	file.Close()
	if err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	res.BytesOffset = offset + written
	res.FileHash = sha256HashFile(tmpPath)
	return res, nil
}

// FinalizeFile renames a .tmp file to its final name.
func (d *Downloader) FinalizeFile(tmpPath, finalPath string) error {
	return os.Rename(tmpPath, finalPath)
}

// RemoveTemp deletes a .tmp file.
func (d *Downloader) RemoveTemp(tmpPath string) {
	os.Remove(tmpPath)
}

// VerifyChecksum checks a file's SHA-256 hash against the expected hex string.
// If expectedHash is empty, the check is skipped.
func VerifyChecksum(filePath, expectedHash string) (bool, error) {
	if expectedHash == "" {
		return true, nil
	}
	actual := sha256HashFile(filePath)
	return actual == expectedHash, nil
}

// sha256HashFile computes SHA-256 hex digest of a file.
func sha256HashFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}
