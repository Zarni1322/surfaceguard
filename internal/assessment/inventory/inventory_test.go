package inventory

import (
	"testing"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

func TestDiffPackages(t *testing.T) {
	prev := []models.InstalledPackage{
		{Name: "openssh", Version: "8.0", Status: "installed"},
		{Name: "nginx", Version: "1.20", Status: "installed"},
	}
	curr := []models.InstalledPackage{
		{Name: "openssh", Version: "8.1", Status: "installed"},
		{Name: "curl", Version: "7.0", Status: "installed"},
	}

	diff := DiffPackages(prev, curr)
	if len(diff.New) != 1 || diff.New[0].Name != "curl" {
		t.Errorf("expected 1 new package (curl), got %d", len(diff.New))
	}
	if len(diff.Changed) != 1 || diff.Changed[0].Name != "openssh" {
		t.Errorf("expected 1 changed package (openssh), got %d", len(diff.Changed))
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Name != "nginx" {
		t.Errorf("expected 1 removed package (nginx), got %d", len(diff.Removed))
	}
}

func TestDiffPackagesEmpty(t *testing.T) {
	diff := DiffPackages(nil, nil)
	if len(diff.New) != 0 || len(diff.Changed) != 0 || len(diff.Removed) != 0 {
		t.Errorf("expected empty diff, got new=%d changed=%d removed=%d", len(diff.New), len(diff.Changed), len(diff.Removed))
	}
}

func TestDiffPackagesIdentical(t *testing.T) {
	pkgs := []models.InstalledPackage{
		{Name: "a", Version: "1.0"},
		{Name: "b", Version: "2.0"},
	}
	diff := DiffPackages(pkgs, pkgs)
	if len(diff.New) != 0 || len(diff.Changed) != 0 || len(diff.Removed) != 0 {
		t.Errorf("expected empty diff for identical lists")
	}
}
