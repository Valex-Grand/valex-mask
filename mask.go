package main

import (
	"net"
	"regexp"
	"strings"
)

var (
	emailRE = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	bearerRE = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-]+\b`)
	jwtRE = regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	githubRE = regexp.MustCompile(`(?i)\bgh[pousr]_[A-Za-z0-9_]{10,}\b`)
	awsKeyRE = regexp.MustCompile(`(?i)\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	awsSecretRE = regexp.MustCompile(`(?i)\baws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{16,}["']?`)
	apiKeyRE = regexp.MustCompile(`(?i)\b((?:api[_-]?key|token|secret))\s*[:=]\s*["']?([A-Za-z0-9_\-]+)["']?`)
	jsonPasswordRE = regexp.MustCompile(`(?i)("password"\s*:\s*")([^"]*)(")`)
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6RE = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){1,7}[0-9A-Fa-f]{1,4}\b`)
	cardRE = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	tcknRE = regexp.MustCompile(`\b\d{11}\b`)
)

func Mask(s string) string {
	if s == "" {
		return s
	}

	out := s
	out = jsonPasswordRE.ReplaceAllString(out, `$1[REDACTED]$3`)
	out = bearerRE.ReplaceAllString(out, "Bearer [REDACTED_TOKEN]")
	out = jwtRE.ReplaceAllString(out, "[REDACTED_JWT]")
	out = githubRE.ReplaceAllString(out, "[REDACTED_GITHUB_TOKEN]")
	out = awsKeyRE.ReplaceAllString(out, "[REDACTED_AWS_KEY_ID]")
	out = awsSecretRE.ReplaceAllString(out, "aws_secret_access_key=[REDACTED]")
	out = apiKeyRE.ReplaceAllString(out, "$1=[REDACTED]")
	out = emailRE.ReplaceAllStringFunc(out, redactEmail)
	out = maskIPs(out)
	out = maskCards(out)
	out = maskTCKN(out)
	return out
}

func AppendMask(dst []byte, src string) []byte {
	if !hasSensitiveData(src) {
		return append(dst, src...)
	}
	return append(dst, Mask(src)...)
}

func hasSensitiveData(s string) bool {
	return emailRE.MatchString(s) ||
		bearerRE.MatchString(s) ||
		jwtRE.MatchString(s) ||
		githubRE.MatchString(s) ||
		awsKeyRE.MatchString(s) ||
		awsSecretRE.MatchString(s) ||
		apiKeyRE.MatchString(s) ||
		jsonPasswordRE.MatchString(s) ||
		ipv4RE.MatchString(s) ||
		ipv6RE.MatchString(s) ||
		cardRE.MatchString(s) ||
		tcknRE.MatchString(s)
}

func redactEmail(s string) string {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return s
	}
	local := parts[0]
	domain := parts[1]

	if len(local) <= 1 {
		return "*@" + domain
	}
	if len(local) == 2 {
		return local[:1] + "*@" + domain
	}
	return local[:1] + strings.Repeat("*", len(local)-1) + "@" + domain
}

func maskIPs(s string) string {
	out := ipv4RE.ReplaceAllStringFunc(s, func(v string) string {
		if net.ParseIP(v) != nil {
			return "[REDACTED_IP]"
		}
		return v
	})
	out = ipv6RE.ReplaceAllStringFunc(out, func(v string) string {
		if net.ParseIP(v) != nil {
			return "[REDACTED_IP]"
		}
		return v
	})
	return out
}

func maskCards(s string) string {
	matches := cardRE.FindAllString(s, -1)
	if len(matches) == 0 {
		return s
	}
	for _, m := range matches {
		candidate := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, m)
		if len(candidate) >= 13 && len(candidate) <= 19 && isLuhn(candidate) {
			s = strings.Replace(s, m, "****-****-****-****", 1)
		}
	}
	return s
}

func maskTCKN(s string) string {
	matches := tcknRE.FindAllString(s, -1)
	if len(matches) == 0 {
		return s
	}
	for _, m := range matches {
		if isValidTCKN(m) {
			s = strings.Replace(s, m, "[REDACTED_TCKN]", 1)
		}
	}
	return s
}

func isLuhn(s string) bool {
	if s == "" {
		return false
	}
	sum := 0
	alt := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func isValidTCKN(s string) bool {
	if len(s) != 11 {
		return false
	}
	digits := make([]int, 11)
	for i := 0; i < 11; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		digits[i] = int(s[i] - '0')
	}
	if digits[0] == 0 {
		return false
	}
	first9 := 0
	for i := 0; i < 9; i++ {
		first9 += digits[i]
	}
	if digits[9] != ((first9*7)-sum(digits[:9]))%10 {
		return false
	}
	if digits[10] != (first9+digits[9])%10 {
		return false
	}
	return true
}

func sum(nums []int) int {
	out := 0
	for _, n := range nums {
		out += n
	}
	return out
}
