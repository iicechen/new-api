package common

import (
	"regexp"
	"strings"
)

var (
	bearerTokenPattern = regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9._~+\-/=]+)`)
	kvSecretPattern    = regexp.MustCompile(`(?i)\b(API[_-]?KEY|AUTHORIZATION|SQL_DSN|CRYPTO_SECRET|JWT_SECRET|SESSION_SECRET|TOKEN|SECRET)\b\s*[:=]\s*([^\s,;]+)`)
	jsonSecretPattern  = regexp.MustCompile(`(?i)("(?:api[_-]?key|authorization|sql_dsn|crypto_secret|jwt_secret|session_secret|token|secret)"\s*:\s*")([^"]+)(")`)
)

// MaskSecret keeps a small prefix/suffix for identification without exposing a full secret.
func MaskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

// SanitizeLogMessage removes common secret shapes before they reach stdout or log files.
func SanitizeLogMessage(message string) string {
	if message == "" {
		return ""
	}
	message = bearerTokenPattern.ReplaceAllStringFunc(message, func(match string) string {
		parts := strings.Fields(match)
		if len(parts) != 2 {
			return "Bearer " + MaskSecret(match)
		}
		return parts[0] + " " + MaskSecret(parts[1])
	})
	message = kvSecretPattern.ReplaceAllStringFunc(message, func(match string) string {
		parts := kvSecretPattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		return parts[1] + "=" + MaskSecret(parts[2])
	})
	message = jsonSecretPattern.ReplaceAllStringFunc(message, func(match string) string {
		parts := jsonSecretPattern.FindStringSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		return parts[1] + MaskSecret(parts[2]) + parts[3]
	})
	return message
}
