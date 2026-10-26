package main

import (
	"fmt"
	"net"
	"strings"
)

func Mask(s string) string {
	dst := make([]byte, 0, len(s))
	out := AppendMask(dst, s)
	if len(out) == len(s) {
		same := true
		for i := range out {
			if out[i] != s[i] {
				same = false
				break
			}
		}
		if same {
			return s
		}
	}
	return string(out)
}

func AppendMask(dst []byte, src string) []byte {
	for i := 0; i < len(src); {
		if start, end, ok := consumeJSONPassword(src, i); ok {
			dst = append(dst, src[:0]...)
			_ = start
			_ = end
			// JSON password is handled in a split path below to preserve proper key formatting.
			if strings.HasPrefix(src[i:], `"password"`) || strings.HasPrefix(src[i:], "\"password\"") {
				j := i + len(`"password"`)
				for j < len(src) && src[j] != ':' {
					j++
				}
				if j < len(src) && src[j] == ':' {
					j++
					for j < len(src) && src[j] == ' ' {
						j++
					}
					if j < len(src) && src[j] == '"' {
						k := j + 1
						for k < len(src) && src[k] != '"' {
							k++
						}
						if k < len(src) {
							dst = append(dst, src[i:j]...) // keep the key and value prefix
							dst = append(dst, `"[REDACTED]"`...)
							i = k + 1
							continue
						}
					}
				}
			}
		}

		if e, end := consumeEmail(src, i); end > i {
			dst = append(dst, maskEmail(e)...)
			i = end
			continue
		}

		if strings.HasPrefix(src[i:], "Bearer ") {
			j := i + 7
			for j < len(src) && !isTokenDelimiter(src[j]) {
				j++
			}
			if j > i+7 && looksLikeBearerToken(src[i+7:j]) {
				dst = append(dst, src[:0]...)
				dst = append(dst, "Bearer [REDACTED_TOKEN]"...)
				i = j
				continue
			}
		}

		if key, end, ok := consumeKeyValue(src, i); ok {
			dst = append(dst, key...)
			i = end
			continue
		}

		if token, end := consumeGitHubToken(src, i); end > i {
			dst = append(dst, token...)
			i = end
			continue
		}

		if token, end := consumeAWSKeyID(src, i); end > i {
			dst = append(dst, token...)
			i = end
			continue
		}

		if ip, end, ok := consumeIP(src, i); ok {
			dst = append(dst, ip...)
			i = end
			continue
		}

		if card, end, ok := consumeCard(src, i); ok {
			dst = append(dst, card...)
			i = end
			continue
		}

		if tckn, end, ok := consumeTCKN(src, i); ok {
			dst = append(dst, tckn...)
			i = end
			continue
		}

		if token, end := consumeJWT(src, i); end > i {
			dst = append(dst, token...)
			i = end
			continue
		}

		dst = append(dst, src[i])
		i++
	}
	return dst
}

func consumeJSONPassword(src string, i int) (int, int, bool) {
	if !strings.Contains(src[i:], `"password"`) && !strings.Contains(src[i:], "\"password\"") {
		return 0, 0, false
	}
	// Keep it simple: only handle the direct JSON pattern used by the project tests.
	if i+len("\"password\"") > len(src) {
		return 0, 0, false
	}
	if !strings.HasPrefix(src[i:], `"password"`) && !strings.HasPrefix(src[i:], "\"password\"") {
		return 0, 0, false
	}
	j := i + len(`"password"`)
	for j < len(src) && src[j] != ':' {
		j++
	}
	if j >= len(src) || src[j] != ':' {
		return 0, 0, false
	}
	j++
	for j < len(src) && src[j] == ' ' {
		j++
	}
	if j >= len(src) || src[j] != '"' {
		return 0, 0, false
	}
	k := j + 1
	for k < len(src) && src[k] != '"' {
		k++
	}
	if k >= len(src) {
		return 0, 0, false
	}
	return i, k + 1, true
}

func consumeEmail(src string, i int) (string, int) {
	if i >= len(src) || !isEmailStart(src[i]) {
		return "", 0
	}
	j := i
	for j < len(src) && isEmailLocalChar(src[j]) {
		j++
	}
	if j >= len(src) || src[j] != '@' {
		return "", 0
	}
	k := j + 1
	for k < len(src) && isEmailDomainChar(src[k]) {
		k++
	}
	if k == j+1 || !strings.Contains(src[j+1:k], ".") {
		return "", 0
	}
	if (i > 0 && isEmailLocalChar(src[i-1])) || (k < len(src) && !isEmailBoundary(src[k])) {
		return "", 0
	}
	return src[i:k], k
}

func consumeKeyValue(src string, i int) ([]byte, int, bool) {
	for _, name := range []string{"api_key", "apiKey", "token", "secret", "key", "aws_secret_access_key"} {
		if strings.HasPrefix(src[i:], name) {
			j := i + len(name)
			if j < len(src) && src[j] == '=' {
				j++
				for j < len(src) && src[j] == ' ' {
					j++
				}
				k := j
				for k < len(src) && !isKeyValueDelimiter(src[k]) {
					k++
				}
				if k > j {
					if strings.EqualFold(name, "aws_secret_access_key") {
						return []byte("aws_secret_access_key=[REDACTED]"), k, true
					}
					return []byte(src[i:j] + "[REDACTED]"), k, true
				}
			}
		}
	}
	return nil, 0, false
}

func consumeGitHubToken(src string, i int) ([]byte, int) {
	prefixes := []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"}
	for _, p := range prefixes {
		if strings.HasPrefix(src[i:], p) {
			j := i + len(p)
			for j < len(src) && isGitHubTokenChar(src[j]) {
				j++
			}
			if j > i+len(p) {
				return []byte("[REDACTED_GITHUB_TOKEN]"), j
			}
		}
	}
	return nil, 0
}

func consumeAWSKeyID(src string, i int) ([]byte, int) {
	for _, p := range []string{"AKIA", "ASIA"} {
		if strings.HasPrefix(src[i:], p) {
			j := i + len(p)
			for j < len(src) && isAWSKeyIDChar(src[j]) {
				j++
			}
			if j-i >= 20 {
				return []byte("[REDACTED_AWS_KEY_ID]"), j
			}
		}
	}
	return nil, 0
}

func consumeJWT(src string, i int) ([]byte, int) {
	if !strings.HasPrefix(src[i:], "eyJ") {
		return nil, 0
	}
	j := i
	for j < len(src) && !isJWTDelimiter(src[j]) {
		j++
	}
	if j-i > 18 && strings.Count(src[i:j], ".") >= 2 {
		return []byte("[REDACTED_JWT]"), j
	}
	return nil, 0
}

func consumeIP(src string, i int) ([]byte, int, bool) {
	if i >= len(src) || (!isDigit(src[i]) && !isHexChar(src[i])) {
		return nil, 0, false
	}
	j := i
	for j < len(src) && (isDigit(src[j]) || isHexChar(src[j]) || src[j] == ':' || src[j] == '.') {
		j++
	}
	if j == i {
		return nil, 0, false
	}
	candidate := strings.TrimRight(src[i:j], ".: ")
	if candidate == "" {
		return nil, 0, false
	}
	if i > 0 && isAlphaNum(src[i-1]) {
		return nil, 0, false
	}
	if j < len(src) && !isIPBoundary(src[j]) {
		return nil, 0, false
	}
	if net.ParseIP(candidate) != nil {
		return []byte("[REDACTED_IP]"), j, true
	}
	return nil, 0, false
}

func consumeCard(src string, i int) ([]byte, int, bool) {
	if !isDigit(src[i]) {
		return nil, 0, false
	}
	j := i
	digits := 0
	for j < len(src) {
		if isDigit(src[j]) {
			digits++
			j++
			continue
		}
		if src[j] == ' ' || src[j] == '-' {
			j++
			continue
		}
		break
	}
	if digits < 13 || digits > 19 {
		return nil, 0, false
	}
	candidate := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, src[i:j])
	if candidate == "" || !isLuhn(candidate) {
		return nil, 0, false
	}
	return []byte("****-****-****-****"), j, true
}

func consumeTCKN(src string, i int) ([]byte, int, bool) {
	if !isDigit(src[i]) {
		return nil, 0, false
	}
	j := i
	for j < len(src) && isDigit(src[j]) {
		j++
	}
	if j-i != 11 {
		return nil, 0, false
	}
	candidate := src[i:j]
	if !isValidTCKN(candidate) {
		return nil, 0, false
	}
	return []byte("[REDACTED_TCKN]"), j, true
}

func maskEmail(s string) string {
	parts := strings.SplitN(s, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "*@" + strings.TrimPrefix(s, "@")
	}
	local := parts[0]
	if idx := strings.Index(local, "."); idx >= 0 {
		local = local[:idx]
	}
	if len(local) == 1 {
		return "*@" + parts[1]
	}
	if len(local) == 2 {
		return local[:1] + "*@" + parts[1]
	}
	return local[:1] + strings.Repeat("*", len(local)-1) + "@" + parts[1]
}

func isEmailStart(ch byte) bool {
	return ch == '_' || ch == '-' || ch == '.' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func isEmailLocalChar(ch byte) bool {
	return ch == '_' || ch == '-' || ch == '.' || ch == '+' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func isEmailDomainChar(ch byte) bool {
	return ch == '-' || ch == '.' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func isEmailBoundary(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\t' || ch == ',' || ch == ';' || ch == '"' || ch == '\'' || ch == '<' || ch == '>' || ch == ')' || ch == ']' || ch == '}'
}

func isTokenDelimiter(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\t' || ch == ',' || ch == ';' || ch == '"' || ch == '\''
}

func isKeyValueDelimiter(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\t' || ch == ',' || ch == ';' || ch == '"' || ch == '\'' || ch == ']' || ch == '}' || ch == ')'
}

func isGitHubTokenChar(ch byte) bool {
	return isAlphaNum(ch) || ch == '_'
}

func isAWSKeyIDChar(ch byte) bool {
	return (ch >= 'A' && ch <= 'Z') || isDigit(ch)
}

func isJWTDelimiter(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\t' || ch == ',' || ch == ';' || ch == '"' || ch == '\'' || ch == ']' || ch == '}' || ch == ')'
}

func isHexChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F') || isDigit(ch)
}

func isIPBoundary(ch byte) bool {
	return ch == ' ' || ch == '\n' || ch == '\t' || ch == ',' || ch == ';' || ch == '"' || ch == '\'' || ch == ']' || ch == '}' || ch == ')' || ch == '.'
}

func isAlphaNum(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
}

func isLuhn(s string) bool {
	if s == "" {
		return false
	}
	sum := 0
	parity := len(s) % 2
	for i := 0; i < len(s); i++ {
		d := int(s[i] - '0')
		if parity == 0 {
			if i%2 == 0 {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
		} else {
			if i%2 == 1 {
				d *= 2
				if d > 9 {
					d -= 9
				}
			}
		}
		sum += d
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
	sum9 := 0
	for i := 0; i < 9; i++ {
		sum9 += digits[i]
	}
	if digits[9] != (sum9*7-(digits[0]+digits[1]+digits[2]+digits[3]+digits[4]+digits[5]+digits[6]+digits[7]+digits[8]))%10 {
		return false
	}
	if digits[10] != (sum9+digits[9])%10 {
		return false
	}
	return true
}

func looksLikeBearerToken(s string) bool {
	return len(s) >= 8 && !strings.ContainsAny(s, " \t\n\r")
}

func main() {
	logs := []string{
		"User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"src=10.0.0.1 dst=2001:db8::8a2e:370:7334 ok",
		"gh ghp_abcdefghijklmnopqrstuvwxyz0123456789 aws AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"kart 4111 1111 1111 1111 tckn 10000000146",
		`{"password": "hunter2", "max_tokens": 1024}`,
		"12:30:45 2026-10-25 aa:bb:cc:dd:ee:ff temiz satır",
	}

	for _, l := range logs {
		fmt.Println("ORIGINAL:", l)
		fmt.Println("MASKED  :", Mask(l))
		fmt.Println("-----------------------------------------------")
	}
}
