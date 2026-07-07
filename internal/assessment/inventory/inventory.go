// Package inventory manages asset inventory with change detection between scans.
// It tracks new, removed, and changed packages and software across assessments.
package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// Manager handles asset inventory operations.
type Manager struct {
	db database.Database
}

// NewManager creates a new inventory manager.
func NewManager(db database.Database) *Manager {
	return &Manager{db: db}
}

// UpsertAsset creates or updates an asset in the inventory.
func (m *Manager) UpsertAsset(ctx context.Context, asset *models.AssetInfo) (int64, error) {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	now := time.Now().UTC()
	if asset.LastSeen.IsZero() {
		asset.LastSeen = now
	}
	if asset.LastScan.IsZero() {
		asset.LastScan = now
	}

	dbAsset := &database.DBAssetInventory{
		Hostname:      asset.Hostname,
		IP:            asset.IP,
		OS:            asset.OS,
		Distro:        asset.Distro,
		KernelVersion: asset.KernelVersion,
		Architecture:  asset.Architecture,
		AssetType:     asset.AssetType,
		RiskScore:     asset.RiskScore,
		LastSeen:      nowStr,
		LastScan:      nowStr,
	}

	return m.db.AssetInventory().Upsert(ctx, dbAsset)
}

// GetAsset returns an asset by ID.
func (m *Manager) GetAsset(ctx context.Context, id int64) (*models.AssetInfo, error) {
	dbAsset, err := m.db.AssetInventory().Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return dbToAsset(dbAsset), nil
}

// ListAssets returns all assets in inventory.
func (m *Manager) ListAssets(ctx context.Context) ([]models.AssetInfo, error) {
	dbAssets, err := m.db.AssetInventory().List(ctx)
	if err != nil {
		return nil, err
	}
	assets := make([]models.AssetInfo, len(dbAssets))
	for i, a := range dbAssets {
		assets[i] = *dbToAsset(&a)
	}
	return assets, nil
}

// SyncPackages synchronizes the package list for an asset.
// Returns counts of new, removed, and changed packages.
func (m *Manager) SyncPackages(ctx context.Context, assetID int64, packages []models.InstalledPackage) (newPkgs, removedPkgs, changedPkgs int, err error) {
	// Get existing packages.
	existing, err := m.db.InstalledPackage().ListByAsset(ctx, assetID)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("list packages: %w", err)
	}

	// Build a set of current package names.
	currentNames := make(map[string]bool)
	existingMap := make(map[string]*database.DBInstalledPackage)

	for _, p := range existing {
		key := p.Name
		existingMap[key] = &p
	}

	for _, pkg := range packages {
		dbPkg := &database.DBInstalledPackage{
			AssetID:  assetID,
			Name:     pkg.Name,
			Version:  pkg.Version,
			Arch:     pkg.Arch,
			CPE23URI: pkg.CPE23URI,
		}

		existingPkg, exists := existingMap[pkg.Name]
		if !exists {
			newPkgs++
		} else if existingPkg.Version != pkg.Version {
			changedPkgs++
		}

		if _, err := m.db.InstalledPackage().Upsert(ctx, dbPkg); err != nil {
			return 0, 0, 0, fmt.Errorf("upsert package %s: %w", pkg.Name, err)
		}
		currentNames[pkg.Name] = true
	}

	// Mark removed packages.
	var keptNames []string
	for name := range currentNames {
		keptNames = append(keptNames, name)
	}
	if err := m.db.InstalledPackage().MarkRemoved(ctx, assetID, keptNames); err != nil {
		return 0, 0, 0, fmt.Errorf("mark removed: %w", err)
	}

	// Count removals.
	for _, p := range existing {
		if !currentNames[p.Name] && p.Status == "installed" {
			removedPkgs++
		}
	}

	return newPkgs, removedPkgs, changedPkgs, nil
}

// SyncSoftware synchronizes the software list for a Windows asset.
func (m *Manager) SyncSoftware(ctx context.Context, assetID int64, software []models.InstalledSoftware) (int, error) {
	// Get existing software.
	existing, err := m.db.InstalledSoftware().ListByAsset(ctx, assetID)
	if err != nil {
		return 0, err
	}

	// Delete and re-insert for simplicity (unique constraint on name+version).
	m.db.InstalledSoftware().DeleteByAsset(ctx, assetID)

	for _, sw := range software {
		dbSw := &database.DBInstalledSoftware{
			AssetID:     assetID,
			Name:        sw.Name,
			Version:     sw.Version,
			Vendor:      sw.Vendor,
			InstallDate: sw.InstallDate,
			CPE23URI:    sw.CPE23URI,
		}
		if _, err := m.db.InstalledSoftware().Upsert(ctx, dbSw); err != nil {
			return 0, fmt.Errorf("upsert software %s: %w", sw.Name, err)
		}
	}

	removed := len(existing) - len(software)
	if removed < 0 {
		removed = 0
	}
	return removed, nil
}

// PackageDiff computes the difference between two package scans for display.
type PackageDiff struct {
	New     []models.InstalledPackage `json:"new"`
	Removed []models.InstalledPackage `json:"removed"`
	Changed []models.InstalledPackage `json:"changed"`
}

// DiffPackages compares two package lists and returns the difference.
func DiffPackages(previous, current []models.InstalledPackage) PackageDiff {
	prevMap := make(map[string]models.InstalledPackage)
	for _, p := range previous {
		prevMap[p.Name] = p
	}
	curMap := make(map[string]models.InstalledPackage)
	for _, p := range current {
		curMap[p.Name] = p
	}

	var diff PackageDiff
	for name, p := range curMap {
		if _, exists := prevMap[name]; !exists {
			diff.New = append(diff.New, p)
		} else if prevMap[name].Version != p.Version {
			diff.Changed = append(diff.Changed, p)
		}
	}
	for name, p := range prevMap {
		if _, exists := curMap[name]; !exists {
			p.Status = "removed"
			diff.Removed = append(diff.Removed, p)
		}
	}
	return diff
}

func dbToAsset(a *database.DBAssetInventory) *models.AssetInfo {
	asset := &models.AssetInfo{
		ID:            a.ID,
		Hostname:      a.Hostname,
		IP:            a.IP,
		OS:            a.OS,
		Distro:        a.Distro,
		KernelVersion: a.KernelVersion,
		Architecture:  a.Architecture,
		AssetType:     a.AssetType,
		RiskScore:     a.RiskScore,
	}
	if t, err := time.Parse(time.RFC3339, a.LastSeen); err == nil {
		asset.LastSeen = t
	}
	if t, err := time.Parse(time.RFC3339, a.LastScan); err == nil {
		asset.LastScan = t
	}
	return asset
}
