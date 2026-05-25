package common

import (
	"strings"
	"testing"
)

func TestSecretEncryptionRoundTripAndLegacyPlaintext(t *testing.T) {
	previous := CryptoSecret
	CryptoSecret = strings.Repeat("a", 32)
	defer func() { CryptoSecret = previous }()

	plain := "sk-abcdefghijklmnopqrstuvwxyz"
	encrypted, err := EncryptSecretIfNeeded(plain)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if !IsEncryptedSecret(encrypted) {
		t.Fatalf("expected encrypted prefix, got %q", encrypted)
	}
	if strings.Contains(encrypted, plain) {
		t.Fatalf("encrypted value leaked plaintext")
	}
	decrypted, err := DecryptSecretIfNeeded(encrypted)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if decrypted != plain {
		t.Fatalf("expected %q, got %q", plain, decrypted)
	}
	legacy, err := DecryptSecretIfNeeded(plain)
	if err != nil {
		t.Fatalf("legacy plaintext should be accepted: %v", err)
	}
	if legacy != plain {
		t.Fatalf("expected legacy plaintext %q, got %q", plain, legacy)
	}
}

func TestMaskSecret(t *testing.T) {
	if got := MaskSecret("sk-abcdefghijklmnopqrstuvwxyz"); got != "sk-a*********************wxyz" {
		t.Fatalf("unexpected mask: %s", got)
	}
	if got := MaskSecret("short"); got != "*****" {
		t.Fatalf("unexpected short mask: %s", got)
	}
}
