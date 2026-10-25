package main

import (
	"strings"
	"sync"
)



var (
	clsAlnum      [256]bool
	clsAlnumUS    [256]bool 
	clsUpperDigit [256]bool
	clsB64URL     [256]bool 
	clsJWT        [256]bool 
	clsToken      [256]bool 
	clsIdent      [256]bool 
	clsEmailLocal [256]bool
	clsDomain     [256]bool
	clsHex        [256]bool
	clsKVStop     [256]bool 
)

func init() {
	for b := 0; b < 256; b++ {
		c := byte(b)
		lo := c >= 'a' && c <= 'z'
		up := c >= 'A' && c <= 'Z'
		dg := c >= '0' && c <= '9'
		al := lo || up || dg

		clsAlnum[b] = al
		clsAlnumUS[b] = al || c == '_'
		clsUpperDigit[b] = up || dg
		clsB64URL[b] = al || c == '_' || c == '-'
		clsJWT[b] = al || c == '_' || c == '-' || c == '.'
		clsToken[b] = al || c == '.' || c == '_' || c == '~' || c == '+' || c == '/' || c == '=' || c == '-'
		clsIdent[b] = al || c == '_' || c == '-'
		clsEmailLocal[b] = al || c == '.' || c == '_' || c == '%' || c == '+' || c == '-'
		clsDomain[b] = al || c == '.' || c == '-'
		clsHex[b] = dg || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		switch c {
		case ' ', '\t', '\n', '\r', ',', ';', '&', '"', '\'', '}', ')', ']':
			clsKVStop[b] = true
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 32
	}
	return c
}


func run(src string, i int, cls *[256]bool, max int) int {
	lim := i + max
	if lim > len(src) || lim < 0 {
		lim = len(src)
	}
	e := i
	for e < lim && cls[src[e]] {
		e++
	}
	return e
}

func containsFold(s, sub string) bool { 
	n := len(sub)
	for k := 0; k+n <= len(s); k++ {
		m := 0
		for m < n && lower(s[k+m]) == sub[m] {
			m++
		}
		if m == n {
			return true
		}
	}
	return false
}



type mode uint8

const (
	modeConst mode = iota 
	modeEmail             
	modeKV                
)

type match struct {
	end  int
	rep  string
	mode mode
	aux  int
}



type prefixRule struct {
	prefix  string
	minTail int
	cls     *[256]bool
	rep     string
}

var prefixRules = []prefixRule{
	{"github_pat_", 22, &clsAlnumUS, "[REDACTED_GITHUB_TOKEN]"},
	{"ghp_", 36, &clsAlnum, "[REDACTED_GITHUB_TOKEN]"},
	{"gho_", 36, &clsAlnum, "[REDACTED_GITHUB_TOKEN]"},
	{"ghu_", 36, &clsAlnum, "[REDACTED_GITHUB_TOKEN]"},
	{"ghs_", 36, &clsAlnum, "[REDACTED_GITHUB_TOKEN]"},
	{"ghr_", 36, &clsAlnum, "[REDACTED_GITHUB_TOKEN]"},
	{"AKIA", 16, &clsUpperDigit, "[REDACTED_AWS_KEY_ID]"},
	{"ASIA", 16, &clsUpperDigit, "[REDACTED_AWS_KEY_ID]"},
	{"sk_live_", 10, &clsAlnum, "[REDACTED_STRIPE_KEY]"},
	{"rk_live_", 10, &clsAlnum, "[REDACTED_STRIPE_KEY]"},
	{"xoxb-", 10, &clsB64URL, "[REDACTED_SLACK_TOKEN]"},
	{"xoxp-", 10, &clsB64URL, "[REDACTED_SLACK_TOKEN]"},
	{"AIza", 35, &clsB64URL, "[REDACTED_GOOGLE_KEY]"},
}

func matchPrefix(src string, i int) (match, bool) {
	rest := src[i:]
	for k := range prefixRules {
		r := &prefixRules[k]
		if strings.HasPrefix(rest, r.prefix) {
			ts := i + len(r.prefix)
			te := run(src, ts, r.cls, 256)
			if te-ts >= r.minTail {
				return match{end: te, rep: r.rep}, true
			}
		}
	}
	return match{}, false
}



func matchJWT(src string, i int) (match, bool) {
	if !strings.HasPrefix(src[i:], "eyJ") {
		return match{}, false
	}
	e := run(src, i, &clsJWT, 4096)
	for e > i && src[e-1] == '.' {
		e--
	}
	tok := src[i:e]
	d1 := strings.IndexByte(tok, '.')
	if d1 < 4 {
		return match{}, false
	}
	d2rel := strings.IndexByte(tok[d1+1:], '.')
	if d2rel < 4 {
		return match{}, false
	}
	d2 := d1 + 1 + d2rel
	if strings.IndexByte(tok[d2+1:], '.') >= 0 || len(tok)-d2-1 < 1 {
		return match{}, false
	}
	return match{end: e, rep: "[REDACTED_JWT]"}, true
}

func matchBearer(src string, i int) (match, bool) {
	if len(src)-i < 8 {
		return match{}, false
	}
	const w = "bearer"
	for k := 0; k < len(w); k++ {
		if lower(src[i+k]) != w[k] {
			return match{}, false
		}
	}
	k := i + len(w)
	if src[k] != ' ' && src[k] != '\t' {
		return match{}, false
	}
	for k < len(src) && (src[k] == ' ' || src[k] == '\t') {
		k++
	}
	te := run(src, k, &clsToken, 2048)
	if te-k < 8 { // 
		return match{}, false
	}
	return match{end: te, rep: "Bearer [REDACTED_TOKEN]"}, true
}

var sensitiveWords = [...]string{
	"secret", "token", "apikey", "api_key", "api-key",
	"access_key", "private_key", "credential",
}

func matchKV(src string, i int) (match, bool) {
	je := run(src, i, &clsIdent, 64)
	if je == i || je >= len(src) {
		return match{}, false
	}
	ident := src[i:je]
	pass := containsFold(ident, "passw") || containsFold(ident, "passphrase")
	if !pass {
		found := false
		for _, w := range sensitiveWords {
			if containsFold(ident, w) {
				found = true
				break
			}
		}
		if !found {
			return match{}, false
		}
	}
	k := je
	if k < len(src) && (src[k] == '"' || src[k] == '\'') { 
		k++
	}
	for k < len(src) && (src[k] == ' ' || src[k] == '\t') {
		k++
	}
	if k >= len(src) || (src[k] != ':' && src[k] != '=') {
		return match{}, false
	}
	k++
	for k < len(src) && (src[k] == ' ' || src[k] == '\t') {
		k++
	}
	if k < len(src) && (src[k] == '"' || src[k] == '\'') {
		k++
	}
	vs := k
	if strings.HasPrefix(src[vs:], "[REDACTED") { 
		return match{}, false
	}
	for k < len(src) && !clsKVStop[src[k]] {
		k++
	}
	minLen := 6 
	if pass {
		minLen = 1
	}
	if k-vs < minLen {
		return match{}, false
	}
	return match{end: k, rep: "[REDACTED]", mode: modeKV, aux: vs}, true
}



func matchEmail(src string, i int) (match, bool) {
	le := run(src, i, &clsEmailLocal, 64)
	if le >= len(src) || src[le] != '@' {
		return match{}, false
	}
	ds := le + 1
	de := run(src, ds, &clsDomain, 255)
	for de > ds && (src[de-1] == '.' || src[de-1] == '-') {
		de--
	}
	dom := src[ds:de]
	dot := strings.LastIndexByte(dom, '.')
	if dot <= 0 || len(dom)-dot-1 < 2 {
		return match{}, false
	}
	for k := dot + 1; k < len(dom); k++ {
		if !isAlpha(dom[k]) {
			return match{}, false
		}
	}
	return match{end: de, mode: modeEmail, aux: le}, true
}



func matchIPv4(src string, i int) (int, bool) {
	p := i
	for oct := 0; oct < 4; oct++ {
		if oct > 0 {
			if p >= len(src) || src[p] != '.' {
				return 0, false
			}
			p++
		}
		s, v := p, 0
		for p < len(src) && isDigit(src[p]) && p-s < 3 {
			v = v*10 + int(src[p]-'0')
			p++
		}
		if p == s || v > 255 {
			return 0, false
		}
	}
	if p < len(src) {
		if isDigit(src[p]) {
			return 0, false
		}
		if src[p] == '.' && p+1 < len(src) && isDigit(src[p+1]) { 
			return 0, false
		}
	}
	return p, true
}

func luhn(d []byte) bool {
	sum, alt := 0, false
	for k := len(d) - 1; k >= 0; k-- {
		v := int(d[k])
		if alt {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
		alt = !alt
	}
	return sum%10 == 0
}

func validTCKN(d []byte) bool {
	if len(d) != 11 || d[0] == 0 {
		return false
	}
	odd := int(d[0]) + int(d[2]) + int(d[4]) + int(d[6]) + int(d[8])
	even := int(d[1]) + int(d[3]) + int(d[5]) + int(d[7])
	d10 := ((odd*7-even)%10 + 10) % 10
	if int(d[9]) != d10 {
		return false
	}
	sum := 0
	for k := 0; k < 10; k++ {
		sum += int(d[k])
	}
	return int(d[10]) == sum%10
}

func matchCardTCKN(src string, i int) (match, bool) {
	var d [19]byte
	n, j, lastEnd := 0, i, i
	sepSeen := false
loop:
	for j < len(src) {
		c := src[j]
		switch {
		case isDigit(c):
			if n == 19 {
				return match{}, false
			}
			d[n] = c - '0'
			n++
			j++
			lastEnd = j
		case (c == ' ' || c == '-') && n > 0 && j+1 < len(src) && isDigit(src[j+1]):
			if !sepSeen && n != 4 { 
				break loop
			}
			sepSeen = true
			j++
		default:
			break loop
		}
	}
	if lastEnd < len(src) && (isAlpha(src[lastEnd]) || src[lastEnd] == '_') {
		return match{}, false
	}
	if n == 11 && lastEnd-i == 11 && validTCKN(d[:n]) {
		return match{end: lastEnd, rep: "[REDACTED_TCKN]"}, true
	}
	if n >= 13 && n <= 19 && luhn(d[:n]) {
		return match{end: lastEnd, rep: "****-****-****-****"}, true
	}
	return match{}, false
}



func validIPv6(s string) bool {
	dc := strings.Count(s, "::")
	if dc > 1 || strings.Contains(s, ":::") {
		return false
	}
	if dc == 0 && strings.Count(s, ":") != 7 { 
		return false
	}
	if s[0] == ':' && !strings.HasPrefix(s, "::") {
		return false
	}
	if s[len(s)-1] == ':' && !strings.HasSuffix(s, "::") {
		return false
	}
	groups := 0
	for start := 0; start <= len(s); {
		end := strings.IndexByte(s[start:], ':')
		if end < 0 {
			end = len(s)
		} else {
			end += start
		}
		l := end - start
		if l > 4 {
			return false
		}
		if l > 0 {
			groups++
		}
		start = end + 1
	}
	if dc == 0 {
		return groups == 8
	}
	return groups >= 1 && groups <= 7
}

func matchIPv6(src string, i int) (match, bool) {
	e := i
	for e < len(src) && e-i < 45 && (clsHex[src[e]] || src[e] == ':') {
		e++
	}
	if e < len(src) {
		if clsAlnum[src[e]] || src[e] == '_' {
			return match{}, false
		}
		if src[e] == '.' && e+1 < len(src) && isDigit(src[e+1]) { 
			return match{}, false
		}
	}
	if e-i >= 2 && src[e-1] == ':' && src[e-2] != ':' { 
		e--
	}
	if e-i < 2 || !validIPv6(src[i:e]) {
		return match{}, false
	}
	return match{end: e, rep: "[REDACTED_IP]"}, true
}




func isStart(src string, i int) bool {
	c := src[i]
	if c == ':' {
		if i == 0 {
			return true
		}
		p := src[i-1]
		return !(clsAlnum[p] || p == ':')
	}
	if !(clsAlnum[c] || c == '_') {
		return false
	}
	if i == 0 {
		return true
	}
	p := src[i-1]
	return !(clsAlnum[p] || p == '_')
}

func detect(src string, i int) (match, bool) {
	c := src[i]
	if c == ':' {
		return matchIPv6(src, i)
	}
	if m, ok := matchPrefix(src, i); ok {
		return m, true
	}
	if c == 'e' {
		if m, ok := matchJWT(src, i); ok {
			return m, true
		}
	}
	if c == 'B' || c == 'b' {
		if m, ok := matchBearer(src, i); ok {
			return m, true
		}
	}
	if isAlpha(c) || c == '_' {
		if m, ok := matchKV(src, i); ok {
			return m, true
		}
	}
	if m, ok := matchEmail(src, i); ok {
		return m, true
	}
	if isDigit(c) {
		dotted := i >= 2 && src[i-1] == '.' && isDigit(src[i-2]) 
		if !dotted {
			if end, ok := matchIPv4(src, i); ok {
				return match{end: end, rep: "[REDACTED_IP]"}, true
			}
			if m, ok := matchCardTCKN(src, i); ok {
				return m, true
			}
		}
	}
	if clsHex[c] {
		return matchIPv6(src, i)
	}
	return match{}, false
}

func appendMask(dst []byte, src string) ([]byte, bool) {
	last, changed := 0, false
	for i := 0; i < len(src); {
		if isStart(src, i) {
			if m, ok := detect(src, i); ok && m.end > i {
				dst = append(dst, src[last:i]...)
				switch m.mode {
				case modeEmail:
					if m.aux-i >= 2 {
						dst = append(dst, src[i])
						dst = append(dst, "***"...)
					} else {
						dst = append(dst, '*')
					}
					dst = append(dst, src[m.aux:m.end]...)
				case modeKV:
					dst = append(dst, src[i:m.aux]...)
					dst = append(dst, m.rep...)
				default:
					dst = append(dst, m.rep...)
				}
				i, last, changed = m.end, m.end, true
				continue
			}
		}
		i++
	}
	dst = append(dst, src[last:]...)
	return dst, changed
}


func AppendMask(dst []byte, src string) []byte {
	dst, _ = appendMask(dst, src)
	return dst
}

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }}


func Mask(s string) string {
	bp := bufPool.Get().(*[]byte)
	buf, changed := appendMask((*bp)[:0], s)
	out := s
	if changed {
		out = string(buf)
	}
	if cap(buf) <= 1<<16 {
		*bp = buf[:0]
	}
	bufPool.Put(bp)
	return out
}
