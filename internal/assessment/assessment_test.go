package assessment

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

func setupTestEngine(t *testing.T) (*Engine, database.Database) {
	t.Helper()
	ctx := context.Background()

	db, err := database.NewSQLiteDatabase(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}

	cfg := config.DefaultConfig()
	m := matcher.New(db)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	eng := NewEngine(&cfg.Assessment, db, m, logger)

	// Use a dev encryption key for testing.
	cfg.Assessment.EncryptKey = "test-key-for-unit-tests-12345"

	return eng, db
}

func TestNewEngine(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	if eng == nil {
		t.Fatal("expected non-nil engine")
	}
}

func TestCreateAndListProfiles(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	ctx := context.Background()

	// Create a profile.
	profile := &auth.Profile{
		Name:       "test-profile",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Port:       22,
		Username:   "admin",
		AuthMethod: "password",
		Password:   "secret123",
	}

	id, err := eng.CreateProfile(ctx, profile)
	if err != nil {
		t.Fatalf("CreateProfile: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive ID, got %d", id)
	}

	// List profiles.
	profiles, err := eng.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}
	if profiles[0].Name != "test-profile" {
		t.Errorf("expected name 'test-profile', got %q", profiles[0].Name)
	}
	if profiles[0].Username != "admin" {
		t.Errorf("expected username 'admin', got %q", profiles[0].Username)
	}
}

func TestCreateAndDeleteProfile(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	ctx := context.Background()

	profile := &auth.Profile{
		Name:       "delete-me",
		Protocol:   models.ProtocolSSH,
		Host:       "10.0.0.1",
		Username:   "root",
		AuthMethod: "password",
		Password:   "pass",
	}

	id, _ := eng.CreateProfile(ctx, profile)
	if err := eng.DeleteProfile(ctx, id); err != nil {
		t.Fatalf("DeleteProfile: %v", err)
	}

	profiles, _ := eng.ListProfiles(ctx)
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles after delete, got %d", len(profiles))
	}
}

func TestCreateProfileValidationFailure(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	ctx := context.Background()

	// Missing name.
	_, err := eng.CreateProfile(ctx, &auth.Profile{
		Protocol: models.ProtocolSSH,
	})
	if err == nil {
		t.Fatal("expected validation error for missing name")
	}
}

func TestGetDecryptedProfile(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	ctx := context.Background()

	profile := &auth.Profile{
		Name:       "encrypted-test",
		Protocol:   models.ProtocolSSH,
		Host:       "10.0.0.1",
		Username:   "admin",
		AuthMethod: "password",
		Password:   "my-secret-password",
	}

	id, _ := eng.CreateProfile(ctx, profile)

	// Get the decrypted profile.
	dec, err := eng.GetProfile(ctx, id)
	if err != nil {
		t.Fatalf("GetProfile: %v", err)
	}
	if dec.Password != "my-secret-password" {
		t.Errorf("expected password 'my-secret-password', got %q", dec.Password)
	}
	if dec.Username != "admin" {
		t.Errorf("expected username 'admin', got %q", dec.Username)
	}
}

func TestValidateCredentialsProfileNotFound(t *testing.T) {
	eng, db := setupTestEngine(t)
	defer db.Close()

	ctx := context.Background()
	_, err := eng.ValidateCredentials(ctx, 999)
	if err == nil {
		t.Fatal("expected error for non-existent profile")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := "unit-test-encryption-key-32b"
	plaintext := "very-secret-password!!"

	cipher, err := auth.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	dec, err := auth.Decrypt(cipher, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if dec != plaintext {
		t.Errorf("round trip failed: %q != %q", dec, plaintext)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	cipher, _ := auth.Encrypt("secret", "correct-key")
	_, err := auth.Decrypt(cipher, "wrong-key")
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

