package main

import (
	"regexp"
	"strings"
)

// Mask, metin içerisindeki tüm hassas verileri (API key, PII, şifre, token, IP vb.) güvenli bir şekilde maskeler.
func Mask(input string) string {
	result := input

	// 1. Şifreler ve Parolalar (password=..., passwd: ..., şifre, veya doğrudan password123 gibi kelimeler)
	passwordRegex := regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret)\b\s*[:=]?\s*("[^"]+"|\S+)?|\bpassword\d+\b`)
	result = passwordRegex.ReplaceAllString(result, "[REDACTED]")

	// 2. API Key ve Özel Secret Kalıpları (api_key=..., sk_live_... vb.)
	apiKeyRegex := regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*([a-zA-Z0-9_\-]+)`)
	result = apiKeyRegex.ReplaceAllString(result, `$1=[REDACTED]`)

	// 3. AWS Secret Access Key
	awsSecretRegex := regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([a-zA-Z0-9/+=]+)`)
	result = awsSecretRegex.ReplaceAllString(result, `$1=[REDACTED]`)

	// 4. GitHub ve AWS Key ID Kalıpları
	ghTokenRegex := regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	result = ghTokenRegex.ReplaceAllString(result, "[REDACTED_GITHUB_TOKEN]")

	awsKeyRegex := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	result = awsKeyRegex.ReplaceAllString(result, "[REDACTED_AWS_KEY_ID]")

	// 5. JWT Token'lar
	jwtRegex := regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)
	result = jwtRegex.ReplaceAllString(result, "[REDACTED_JWT]")

	// 6. Bearer Token'lar
	bearerRegex := regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9_\-\.]+`)
	result = bearerRegex.ReplaceAllString(result, "Bearer [REDACTED_TOKEN]")

	// 7. Kredi Kartı Numaraları (16 haneli boşluklu veya bitişik)
	ccRegex := regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	result = ccRegex.ReplaceAllString(result, "****-****-****-****")

	// 8. T.C. Kimlik Numarası (TCKN - 11 hane)
	tcknRegex := regexp.MustCompile(`\b[1-9]\d{10}\b`)
	result = tcknRegex.ReplaceAllString(result, "[REDACTED_TCKN]")

	// 9. IPv4 ve IPv6 Adresleri
	ipv4Regex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	result = ipv4Regex.ReplaceAllString(result, "[REDACTED_IP]")

	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
	result = ipv6Regex.ReplaceAllString(result, "[REDACTED_IP]")

	// 10. E-posta Adresleri (Kullanıcı adının başını gizleyerek maskeleme)
	emailRegex := regexp.MustCompile(`([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)`)
	result = emailRegex.ReplaceAllStringFunc(result, func(email string) string {
		parts := strings.Split(email, "@")
		if len(parts[0]) <= 1 {
			return "***@" + parts[1]
		}
		return string(parts[0][0]) + "***@" + parts[1]
	})

	return result
}
