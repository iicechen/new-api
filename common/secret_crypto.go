package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const encryptedSecretPrefix = "enc:v1:"

func IsEncryptedSecret(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), encryptedSecretPrefix)
}

func secretCipher() (cipher.AEAD, error) {
	if strings.TrimSpace(CryptoSecret) == "" {
		return nil, fmt.Errorf("CRYPTO_SECRET is not configured")
	}
	sum := sha256.Sum256([]byte(CryptoSecret))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func EncryptSecret(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	aead, err := secretCipher()
	if err != nil {
		return "", err
	}
	iv := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	sealed := aead.Seal(nil, iv, []byte(value), nil)
	tagSize := aead.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]
	enc := base64.RawURLEncoding
	return encryptedSecretPrefix + enc.EncodeToString(iv) + ":" + enc.EncodeToString(ciphertext) + ":" + enc.EncodeToString(authTag), nil
}

func EncryptSecretIfNeeded(value string) (string, error) {
	if value == "" || IsEncryptedSecret(value) {
		return value, nil
	}
	return EncryptSecret(value)
}

func DecryptSecretIfNeeded(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !IsEncryptedSecret(value) {
		return value, nil
	}
	parts := strings.Split(value, ":")
	if len(parts) != 5 || parts[0] != "enc" || parts[1] != "v1" {
		return "", fmt.Errorf("invalid encrypted secret format")
	}
	enc := base64.RawURLEncoding
	iv, err := enc.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted secret iv")
	}
	ciphertext, err := enc.DecodeString(parts[3])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted secret ciphertext")
	}
	authTag, err := enc.DecodeString(parts[4])
	if err != nil {
		return "", fmt.Errorf("invalid encrypted secret auth tag")
	}
	aead, err := secretCipher()
	if err != nil {
		return "", err
	}
	sealed := append(ciphertext, authTag...)
	plaintext, err := aead.Open(nil, iv, sealed, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt secret")
	}
	return string(plaintext), nil
}
