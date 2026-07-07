package auth

import (
	"testing"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

func TestProfileValidateSSHPassword(t *testing.T) {
	p := &Profile{
		Name:       "test-ssh",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Port:       22,
		Username:   "admin",
		AuthMethod: "password",
		Password:   "secret",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid SSH password profile: %v", err)
	}
}

func TestProfileValidateSSHKey(t *testing.T) {
	p := &Profile{
		Name:       "test-ssh-key",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Username:   "admin",
		AuthMethod: "key",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid SSH key profile: %v", err)
	}
}

func TestProfileValidateSSHKeyPassphrase(t *testing.T) {
	p := &Profile{
		Name:       "test-ssh-keypass",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Username:   "admin",
		AuthMethod: "key+passphrase",
		PrivateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
		Password:   "passphrase",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid SSH key+passphrase profile: %v", err)
	}
}

func TestProfileValidateWinRM(t *testing.T) {
	p := &Profile{
		Name:       "test-winrm",
		Protocol:   models.ProtocolWinRM,
		Host:       "192.168.1.100",
		Username:   "admin",
		AuthMethod: "password",
		Password:   "secret",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid WinRM profile: %v", err)
	}
	if p.Port != 5986 {
		t.Errorf("expected default WinRM port 5986, got %d", p.Port)
	}
}

func TestProfileValidateSNMP(t *testing.T) {
	p := &Profile{
		Name:       "test-snmp",
		Protocol:   models.ProtocolSNMP,
		Host:       "192.168.1.1",
		AuthMethod: "community",
		Community:  "public",
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid SNMP profile: %v", err)
	}
	if p.Port != 161 {
		t.Errorf("expected default SNMP port 161, got %d", p.Port)
	}
}

func TestProfileValidateMissingName(t *testing.T) {
	p := &Profile{
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Username:   "admin",
		AuthMethod: "password",
		Password:   "secret",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestProfileValidateMissingHost(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Protocol:   models.ProtocolSSH,
		Username:   "admin",
		AuthMethod: "password",
		Password:   "secret",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestProfileValidateMissingPassword(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Username:   "admin",
		AuthMethod: "password",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestProfileValidateMissingPrivateKey(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Protocol:   models.ProtocolSSH,
		Host:       "192.168.1.1",
		Username:   "admin",
		AuthMethod: "key",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for missing private key")
	}
}

func TestProfileInvalidProtocol(t *testing.T) {
	p := &Profile{
		Name:       "test",
		Protocol:   models.Protocol("invalid"),
		Host:       "192.168.1.1",
		AuthMethod: "password",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := "test-encryption-key-32bytes!"
	plaintext := "super-secret-password"

	cipherHex, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if cipherHex == "" {
		t.Fatal("expected non-empty cipher text")
	}

	decrypted, err := Decrypt(cipherHex, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}

func TestEncryptEmptyKey(t *testing.T) {
	_, err := Encrypt("test", "")
	if err == nil {
		t.Fatal("expected error for empty encrypt key")
	}
}

func TestDecryptInvalidHex(t *testing.T) {
	_, err := Decrypt("invalid-hex", "some-key")
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestEncryptDifferentKeys(t *testing.T) {
	c1, _ := Encrypt("password", "key1")
	c2, _ := Encrypt("password", "key2")
	if c1 == c2 {
		t.Fatal("encryption with different keys should produce different ciphertext")
	}
}

func TestValidationResult(t *testing.T) {
	vr := ValidationResult{Status: "SUCCESS"}
	vr.AddCheck("Connection", "fail", "timeout")
	if vr.Status != "FAILED" {
		t.Errorf("expected FAILED after fail check, got %s", vr.Status)
	}
	if len(vr.Checks) != 1 {
		t.Errorf("expected 1 check, got %d", len(vr.Checks))
	}
}

func TestValidationResultWarning(t *testing.T) {
	vr := ValidationResult{Status: "SUCCESS"}
	vr.AddCheck("Privileges", "warn", "limited")
	if vr.Status != "WARNING" {
		t.Errorf("expected WARNING after warn check, got %s", vr.Status)
	}
}

func TestRedactPassword(t *testing.T) {
	redacted := RedactPassword("secret123")
	if redacted != "********" {
		t.Errorf("expected 8 asterisks, got %q", redacted)
	}
	if RedactPassword("") != "" {
		t.Errorf("expected empty string for empty password")
	}
}
