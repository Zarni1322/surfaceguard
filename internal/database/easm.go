package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// sqliteEASMScanRepo implements EASMScanRepository.
type sqliteEASMScanRepo struct{ db *sql.DB }

func (r *sqliteEASMScanRepo) Create(ctx context.Context, s *DBEASMScan) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_scans (target, scan_type, wordlist, ports, started_at, status, worker_count, scanshots)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.Target, s.ScanType, s.Wordlist, s.Ports, s.StartedAt, s.Status, s.WorkerCount, s.Screenshots)
	if err != nil {
		return 0, fmt.Errorf("create easm scan: %w", err)
	}
	return res.LastInsertId()
}

func (r *sqliteEASMScanRepo) Get(ctx context.Context, id int64) (*DBEASMScan, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, target, scan_type, wordlist, ports, started_at, completed_at, duration_ms,
			status, total_assets, alive_assets, total_services, total_cves,
			critical_cves, high_cves, medium_cves, low_cves, kev_cves, avg_epss,
			worker_count, scanshots, error_message, report_json
		FROM easm_scans WHERE id = ?`, id)
	s := &DBEASMScan{}
	err := row.Scan(&s.ID, &s.Target, &s.ScanType, &s.Wordlist, &s.Ports, &s.StartedAt, &s.CompletedAt,
		&s.DurationMs, &s.Status, &s.TotalAssets, &s.AliveAssets, &s.TotalServices, &s.TotalCVEs,
		&s.CriticalCVEs, &s.HighCVEs, &s.MediumCVEs, &s.LowCVEs, &s.KEVCVEs, &s.AvgEPSS,
		&s.WorkerCount, &s.Screenshots, &s.ErrorMessage, &s.ReportJSON)
	if err != nil {
		return nil, fmt.Errorf("get easm scan %d: %w", id, err)
	}
	return s, nil
}

func (r *sqliteEASMScanRepo) UpdateStatus(ctx context.Context, id int64, status, completedAt string, durationMs int64, errMsg string) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE easm_scans SET status = ?, completed_at = ?, duration_ms = ?, error_message = ?
		WHERE id = ?`, status, completedAt, durationMs, errMsg, id)
	return err
}

func (r *sqliteEASMScanRepo) UpdateStats(ctx context.Context, id int64, totalAssets, aliveAssets, totalServices, totalCVEs int,
	criticalCVEs, highCVEs, mediumCVEs, lowCVEs, kevCVEs int, avgEPSS float64) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE easm_scans SET total_assets=?, alive_assets=?, total_services=?, total_cves=?,
			critical_cves=?, high_cves=?, medium_cves=?, low_cves=?, kev_cves=?, avg_epss=?
		WHERE id=?`, totalAssets, aliveAssets, totalServices, totalCVEs,
		criticalCVEs, highCVEs, mediumCVEs, lowCVEs, kevCVEs, avgEPSS, id)
	return err
}

func (r *sqliteEASMScanRepo) List(ctx context.Context, limit int) ([]DBEASMScan, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, target, scan_type, wordlist, ports, started_at, completed_at, duration_ms,
			status, total_assets, alive_assets, total_services, total_cves,
			critical_cves, high_cves, medium_cves, low_cves, kev_cves, avg_epss,
			worker_count, scanshots, error_message, report_json
		FROM easm_scans ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("list easm scans: %w", err)
	}
	defer rows.Close()
	var scans []DBEASMScan
	for rows.Next() {
		var s DBEASMScan
		if err := rows.Scan(&s.ID, &s.Target, &s.ScanType, &s.Wordlist, &s.Ports, &s.StartedAt, &s.CompletedAt,
			&s.DurationMs, &s.Status, &s.TotalAssets, &s.AliveAssets, &s.TotalServices, &s.TotalCVEs,
			&s.CriticalCVEs, &s.HighCVEs, &s.MediumCVEs, &s.LowCVEs, &s.KEVCVEs, &s.AvgEPSS,
			&s.WorkerCount, &s.Screenshots, &s.ErrorMessage, &s.ReportJSON); err != nil {
			return nil, fmt.Errorf("scan easm row: %w", err)
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

func (r *sqliteEASMScanRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM easm_findings WHERE scan_id = ?", id)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `DELETE FROM easm_services WHERE asset_id IN (SELECT id FROM easm_assets WHERE scan_id = ?)`, id)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "DELETE FROM easm_assets WHERE scan_id = ?", id)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, "DELETE FROM easm_scans WHERE id = ?", id)
	return err
}

// sqliteEASMAssetRepo implements EASMAssetRepository.
type sqliteEASMAssetRepo struct{ db *sql.DB }

func (r *sqliteEASMAssetRepo) Insert(ctx context.Context, a *DBEASMAsset) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_assets (scan_id, hostname, ip_address, ipv6_address, cname, is_alive, is_wildcard, source, asset_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ScanID, a.Hostname, a.IPAddress, a.IPv6Address, a.CNAME, a.IsAlive, a.IsWildcard, a.Source, a.AssetType)
	if err != nil {
		return 0, fmt.Errorf("insert easm asset: %w", err)
	}
	return res.LastInsertId()
}

func (r *sqliteEASMAssetRepo) BulkInsert(ctx context.Context, assets []DBEASMAsset) error {
	if len(assets) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO easm_assets (scan_id, hostname, ip_address, ipv6_address, cname, is_alive, is_wildcard, source, asset_type)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, a := range assets {
		_, err := stmt.ExecContext(ctx, a.ScanID, a.Hostname, a.IPAddress, a.IPv6Address, a.CNAME, a.IsAlive, a.IsWildcard, a.Source, a.AssetType)
		if err != nil {
			return fmt.Errorf("insert asset %s: %w", a.Hostname, err)
		}
	}
	return tx.Commit()
}

func (r *sqliteEASMAssetRepo) ListByScan(ctx context.Context, scanID int64) ([]DBEASMAsset, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, scan_id, hostname, ip_address, ipv6_address, cname, is_alive, is_wildcard, source, asset_type, discovered_at
		FROM easm_assets WHERE scan_id = ? ORDER BY hostname`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []DBEASMAsset
	for rows.Next() {
		var a DBEASMAsset
		if err := rows.Scan(&a.ID, &a.ScanID, &a.Hostname, &a.IPAddress, &a.IPv6Address, &a.CNAME, &a.IsAlive, &a.IsWildcard, &a.Source, &a.AssetType, &a.DiscoveredAt); err != nil {
			return nil, err
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func (r *sqliteEASMAssetRepo) CountByScan(ctx context.Context, scanID int64) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM easm_assets WHERE scan_id = ?", scanID).Scan(&count)
	return count, err
}

func (r *sqliteEASMAssetRepo) GetByScanAndHost(ctx context.Context, scanID int64, hostname string) (*DBEASMAsset, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT id, scan_id, hostname, ip_address, ipv6_address, cname, is_alive, is_wildcard, source, asset_type, discovered_at
		FROM easm_assets WHERE scan_id = ? AND hostname = ?`, scanID, hostname)
	var a DBEASMAsset
	err := row.Scan(&a.ID, &a.ScanID, &a.Hostname, &a.IPAddress, &a.IPv6Address, &a.CNAME, &a.IsAlive, &a.IsWildcard, &a.Source, &a.AssetType, &a.DiscoveredAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// sqliteEASMServiceRepo implements EASMServiceRepository.
type sqliteEASMServiceRepo struct{ db *sql.DB }

func (r *sqliteEASMServiceRepo) Insert(ctx context.Context, s *DBEASMService) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO easm_services (asset_id, port, protocol, service, product, version, banner, confidence, technology, cpe_2_3_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.AssetID, s.Port, s.Protocol, s.Service, s.Product, s.Version, s.Banner, s.Confidence, s.Technology, s.CPE23URI)
	if err != nil {
		return 0, fmt.Errorf("insert easm service: %w", err)
	}
	return res.LastInsertId()
}

func (r *sqliteEASMServiceRepo) BulkInsert(ctx context.Context, services []DBEASMService) error {
	if len(services) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO easm_services (asset_id, port, protocol, service, product, version, banner, confidence, technology, cpe_2_3_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, s := range services {
		_, err := stmt.ExecContext(ctx, s.AssetID, s.Port, s.Protocol, s.Service, s.Product, s.Version, s.Banner, s.Confidence, s.Technology, s.CPE23URI)
		if err != nil {
			return fmt.Errorf("insert service %d/%s: %w", s.Port, s.Service, err)
		}
	}
	return tx.Commit()
}

func (r *sqliteEASMServiceRepo) ListByAsset(ctx context.Context, assetID int64) ([]DBEASMService, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, asset_id, port, protocol, service, product, version, banner, confidence, technology, cpe_2_3_uri
		FROM easm_services WHERE asset_id = ? ORDER BY port`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var services []DBEASMService
	for rows.Next() {
		var s DBEASMService
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Port, &s.Protocol, &s.Service, &s.Product, &s.Version, &s.Banner, &s.Confidence, &s.Technology, &s.CPE23URI); err != nil {
			return nil, err
		}
		services = append(services, s)
	}
	return services, rows.Err()
}

func (r *sqliteEASMServiceRepo) ListByScan(ctx context.Context, scanID int64) ([]DBEASMService, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT sv.id, sv.asset_id, sv.port, sv.protocol, sv.service, sv.product, sv.version,
			sv.banner, sv.confidence, sv.technology, sv.cpe_2_3_uri
		FROM easm_services sv
		JOIN easm_assets a ON a.id = sv.asset_id
		WHERE a.scan_id = ? ORDER BY sv.port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var services []DBEASMService
	for rows.Next() {
		var s DBEASMService
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Port, &s.Protocol, &s.Service, &s.Product, &s.Version, &s.Banner, &s.Confidence, &s.Technology, &s.CPE23URI); err != nil {
			return nil, err
		}
		services = append(services, s)
	}
	return services, rows.Err()
}

func (r *sqliteEASMServiceRepo) CountByScan(ctx context.Context, scanID int64) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM easm_services sv
		JOIN easm_assets a ON a.id = sv.asset_id
		WHERE a.scan_id = ?`, scanID).Scan(&count)
	return count, err
}

// sqliteEASMFindingRepo implements EASMFindingRepository.
type sqliteEASMFindingRepo struct{ db *sql.DB }

func (r *sqliteEASMFindingRepo) Insert(ctx context.Context, f *DBEASMFinding) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO easm_findings (service_id, scan_id, cve_id, cvss_v3, cvss_v2, severity, description, is_kev, epss_score, epss_percentile, matched_cpe, matched_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ServiceID, f.ScanID, f.CVEID, f.CVSSv3, f.CVSSv2, f.Severity, f.Description, f.IsKEV, f.EPSSScore, f.EPSSPercentile, f.MatchedCPE, f.MatchedVersion)
	if err != nil {
		return 0, fmt.Errorf("insert easm finding: %w", err)
	}
	return res.LastInsertId()
}

func (r *sqliteEASMFindingRepo) BulkInsert(ctx context.Context, findings []DBEASMFinding) error {
	if len(findings) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO easm_findings (service_id, scan_id, cve_id, cvss_v3, cvss_v2, severity, description, is_kev, epss_score, epss_percentile, matched_cpe, matched_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, f := range findings {
		_, err := stmt.ExecContext(ctx, f.ServiceID, f.ScanID, f.CVEID, f.CVSSv3, f.CVSSv2, f.Severity, f.Description, f.IsKEV, f.EPSSScore, f.EPSSPercentile, f.MatchedCPE, f.MatchedVersion)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", f.CVEID, err)
		}
	}
	return tx.Commit()
}

func (r *sqliteEASMFindingRepo) ListByScan(ctx context.Context, scanID int64) ([]DBEASMFinding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, service_id, scan_id, cve_id, cvss_v3, cvss_v2, severity, description, is_kev, epss_score, epss_percentile, matched_cpe, matched_version
		FROM easm_findings WHERE scan_id = ? ORDER BY cvss_v3 DESC NULLS LAST`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []DBEASMFinding
	for rows.Next() {
		var f DBEASMFinding
		if err := rows.Scan(&f.ID, &f.ServiceID, &f.ScanID, &f.CVEID, &f.CVSSv3, &f.CVSSv2, &f.Severity, &f.Description, &f.IsKEV, &f.EPSSScore, &f.EPSSPercentile, &f.MatchedCPE, &f.MatchedVersion); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (r *sqliteEASMFindingRepo) ListByService(ctx context.Context, serviceID int64) ([]DBEASMFinding, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, service_id, scan_id, cve_id, cvss_v3, cvss_v2, severity, description, is_kev, epss_score, epss_percentile, matched_cpe, matched_version
		FROM easm_findings WHERE service_id = ? ORDER BY cvss_v3 DESC NULLS LAST`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var findings []DBEASMFinding
	for rows.Next() {
		var f DBEASMFinding
		if err := rows.Scan(&f.ID, &f.ServiceID, &f.ScanID, &f.CVEID, &f.CVSSv3, &f.CVSSv2, &f.Severity, &f.Description, &f.IsKEV, &f.EPSSScore, &f.EPSSPercentile, &f.MatchedCPE, &f.MatchedVersion); err != nil {
			return nil, err
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

func (r *sqliteEASMFindingRepo) CountByScan(ctx context.Context, scanID int64) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM easm_findings WHERE scan_id = ?", scanID).Scan(&count)
	return count, err
}

func (r *sqliteEASMFindingRepo) CountBySeverity(ctx context.Context, scanID int64) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT severity, COUNT(*) FROM easm_findings WHERE scan_id = ? GROUP BY severity", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err == nil {
			counts[strings.ToUpper(sev)] = cnt
		}
	}
	return counts, rows.Err()
}
