package updater

import (
	"context"
	"fmt"
	"strings"

	"github.com/evilhunter/surfaceguard/internal/database"
)

// FeedState represents the lifecycle state of a feed update.
type FeedState string

const (
	StateNotStarted   FeedState = "NOT_STARTED"
	StateDownloading  FeedState = "DOWNLOADING"
	StateDownloaded   FeedState = "DOWNLOADED"
	StateVerifying    FeedState = "VERIFYING"
	StateParsing      FeedState = "PARSING"
	StateNormalizing  FeedState = "NORMALIZING"
	StateImporting    FeedState = "IMPORTING"
	StateCompleted    FeedState = "COMPLETED"
	StateFailed       FeedState = "FAILED"
)

// FeedStep describes the current granular step for display/logging.
type FeedStep string

const (
	StepNone           FeedStep = ""
	StepFetchMetadata  FeedStep = "fetch_metadata"
	StepDownloading    FeedStep = "downloading"
	StepDownloadResume FeedStep = "download_resume"
	StepVerifyChecksum FeedStep = "verify_checksum"
	StepDecompress     FeedStep = "decompress"
	StepParseCSV       FeedStep = "parse_csv"
	StepParseJSON      FeedStep = "parse_json"
	StepNormalize      FeedStep = "normalize"
	StepImport         FeedStep = "import"
)

// FeedNames for checkpoint tracking.
const (
	FeedNVD  = "NVD"
	FeedKEV  = "KEV"
	FeedEPSS = "EPSS"
)

// allFeeds lists every feed the updater processes.
var allFeeds = []string{FeedNVD, FeedKEV, FeedEPSS}

// activeStates are states indicating a feed update is in progress (not completed/failed/not_started).
func isActiveState(state FeedState) bool {
	switch state {
	case StateDownloading, StateDownloaded, StateVerifying,
		StateParsing, StateNormalizing, StateImporting:
		return true
	}
	return false
}

// isTerminalState returns true if the feed reached a terminal state.
func isTerminalState(state FeedState) bool {
	return state == StateCompleted || state == StateFailed
}

// CheckpointManager saves/loads/resumes update progress.
type CheckpointManager struct {
	repo database.CheckpointRepository
}

func newCheckpointManager(repo database.CheckpointRepository) *CheckpointManager {
	return &CheckpointManager{repo: repo}
}

// Save persists a checkpoint for the given feed.
func (cm *CheckpointManager) Save(ctx context.Context, feedName string, state FeedState, step FeedStep, bytesOffset int64, filePath, fileHash, message string) error {
	return cm.repo.Save(ctx, &database.DBCheckpoint{
		FeedName:    feedName,
		State:       string(state),
		Step:        string(step),
		BytesOffset: bytesOffset,
		FilePath:    filePath,
		FileHash:    fileHash,
		Message:     message,
	})
}

// Get returns the checkpoint for a feed, or nil if none exists.
func (cm *CheckpointManager) Get(ctx context.Context, feedName string) (*database.DBCheckpoint, error) {
	cp, err := cm.repo.Get(ctx, feedName)
	if err != nil {
		return nil, err
	}
	return cp, nil
}

// HasUnfinished returns the set of feeds with an active (in-progress) checkpoint.
func (cm *CheckpointManager) HasUnfinished(ctx context.Context) ([]string, error) {
	cps, err := cm.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	var unfinished []string
	for _, cp := range cps {
		if isActiveState(FeedState(cp.State)) {
			unfinished = append(unfinished, cp.FeedName)
		}
	}
	return unfinished, nil
}

// ClearAll removes all checkpoints.
func (cm *CheckpointManager) ClearAll(ctx context.Context) error {
	return cm.repo.DeleteAll(ctx)
}

// ClearFeed removes a checkpoint for one feed.
func (cm *CheckpointManager) ClearFeed(ctx context.Context, feedName string) error {
	return cm.repo.Delete(ctx, feedName)
}

// MarkCompleted saves a COMPLETED checkpoint.
func (cm *CheckpointManager) MarkCompleted(ctx context.Context, feedName string) error {
	return cm.Save(ctx, feedName, StateCompleted, StepNone, 0, "", "", "completed")
}

// MarkFailed saves a FAILED checkpoint with the given error.
func (cm *CheckpointManager) MarkFailed(ctx context.Context, feedName string, err error) error {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return cm.Save(ctx, feedName, StateFailed, StepNone, 0, "", "", msg)
}

// ResumePrompt returns a human-readable summary of unfinished feeds for the CLI prompt.
func ResumePrompt(unfinished []string) string {
	var b strings.Builder
	b.WriteString("An interrupted update was detected.\n\n")
	for _, feed := range unfinished {
		b.WriteString(fmt.Sprintf("  • %s\n", feed))
	}
	b.WriteString("\nResume previous update?\n[Y/n] ")
	return b.String()
}
