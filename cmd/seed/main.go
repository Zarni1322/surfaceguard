package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/evilhunter/surfaceguard/internal/database"
)

func main() {
	db, err := database.NewSQLiteDatabase(context.Background(), "data/cve.db")
	if err != nil {
		log.Fatalf("db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	type cveDef struct {
		cve string
		cvss float64
		sev string
		desc string
	}

	products := []struct {
		vendor  string
		product string
		version string
		uri     string
		cves    []cveDef
	}{
		{vendor: "openbsd", product: "openssh", version: "8.7", uri: "cpe:2.3:a:openbsd:openssh:8.7:*:*:*:*:*:*",
			cves: []cveDef{
				{"CVE-2023-38408", 9.8, "CRITICAL", "OpenSSH 8.7 remote code execution via SSH agent forwarding"},
				{"CVE-2023-48795", 5.9, "MEDIUM", "OpenSSH 8.7 Terrapin SSH protocol vulnerability"},
			}},
		{vendor: "mysql", product: "mysql", version: "8.0", uri: "cpe:2.3:a:mysql:mysql:8.0:*:*:*:*:*:*",
			cves: []cveDef{
				{"CVE-2023-21971", 9.8, "CRITICAL", "MySQL 8.0 Connector/J remote code execution"},
				{"CVE-2023-22053", 6.5, "MEDIUM", "MySQL 8.0 denial of service"},
			}},
		{vendor: "postgresql", product: "postgresql", version: "15", uri: "cpe:2.3:a:postgresql:postgresql:15:*:*:*:*:*:*",
			cves: []cveDef{
				{"CVE-2023-2454", 8.8, "HIGH", "PostgreSQL 15 shutdown of a supervised process"},
			}},
		{vendor: "redis", product: "redis", version: "7.0", uri: "cpe:2.3:a:redis:redis:7.0:*:*:*:*:*:*",
			cves: []cveDef{
				{"CVE-2023-41056", 7.5, "HIGH", "Redis 7.0 integer overflow"},
			}},
		{vendor: "apache", product: "http_server", version: "2.4.57", uri: "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*",
			cves: []cveDef{
				{"CVE-2023-25690", 9.8, "CRITICAL", "Apache httpd 2.4.57 HTTP request smuggling"},
			}},
	}

	for _, p := range products {
		vendorID, err := db.Vendor().GetOrCreate(ctx, p.vendor)
		if err != nil {
			log.Fatalf("vendor: %v", err)
		}
		productID, err := db.Product().GetOrCreate(ctx, vendorID, p.product)
		if err != nil {
			log.Fatalf("product: %v", err)
		}
		_, _ = db.CPE().Insert(ctx, &database.DBCPE{
			VendorID: vendorID, ProductID: productID, Part: "a",
			Version: p.version, CPE23URI: p.uri,
		})
		cpes, _ := db.CPE().FindByCPE23URI(ctx, p.uri)
		if len(cpes) == 0 { continue }
		cpeID := cpes[0].ID

		for _, cve := range p.cves {
			now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
			_, _, err := db.CVE().Upsert(ctx, &database.DBCVE{
				CVEID: cve.cve, CPEID: cpeID, Description: cve.desc,
				CVSSv3: &cve.cvss, Severity: cve.sev,
				PublishedDate: now, LastModifiedDate: now,
				ReferencesJSON: fmt.Sprintf(`["https://nvd.nist.gov/vuln/detail/%s"]`, cve.cve),
			})
			if err != nil {
				log.Printf("CVE %s: %v", cve.cve, err)
			} else {
				fmt.Printf("  ✓ %s\n", cve.cve)
			}
		}
	}
	db.Metadata().Set(ctx, "last_update", time.Now().UTC().Format(time.RFC3339))
	fmt.Println("\nDone!")
}
