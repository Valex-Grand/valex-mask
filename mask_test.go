package main

import (
	"regexp"
	"testing"
)

func TestMask(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"orijinal örnek",
			"User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci...",
			"User v***@example.com tried login with api_key=[REDACTED] and Bearer [REDACTED_TOKEN]"},
		{"ipv4+ipv6", "src=10.0.0.1 dst=2001:db8::8a2e:370:7334 ok", "src=[REDACTED_IP] dst=[REDACTED_IP] ok"},
		{"ipv6 tam", "ip 2001:0db8:85a3:0000:0000:8a2e:0370:7334.", "ip [REDACTED_IP]."},
		{"jwt", "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U x", "t=[REDACTED_JWT] x"},
		{"github", "gh ghp_abcdefghijklmnopqrstuvwxyz0123456789 end", "gh [REDACTED_GITHUB_TOKEN] end"},
		{"aws id", "key AKIAIOSFODNN7EXAMPLE x", "key [REDACTED_AWS_KEY_ID] x"},
		{"aws secret", "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws_secret_access_key=[REDACTED]"},
		{"kart", "card 4111 1111 1111 1111 paid", "card ****-****-****-**** paid"},
		{"kart amex", "3782 822463 10005", "****-****-****-****"},
		{"tckn", "tckn 10000000146 ok", "tckn [REDACTED_TCKN] ok"},
		{"json password", `{"password": "hunter2"}`, `{"password": "[REDACTED]"}`},
		{"tek harf e-posta", "a@b.io", "*@b.io"},
		{"e-posta virgül", "john.doe@mail.example.com, hi", "j***@mail.example.com, hi"},
		
		{"saat/tarih/mac", "12:30:45 2026-10-25 aa:bb:cc:dd:ee:ff", "12:30:45 2026-10-25 aa:bb:cc:dd:ee:ff"},
		{"max_tokens", "max_tokens=1024", "max_tokens=1024"},
		{"luhn hatalı", "4111 1111 1111 1112", "4111 1111 1111 1112"},
		{"tckn hatalı", "10000000147", "10000000147"},
		{"versiyon", "v1.2.3 build 1.2.3.4.5", "v1.2.3 build 1.2.3.4.5"},
		{"bearer cümlesi", "bearer of bad news", "bearer of bad news"},
		{"sayı listesi", "1 2 3 4 5 6 7 8 9 10 11 12", "1 2 3 4 5 6 7 8 9 10 11 12"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Mask(c.in)
			if got != c.want {
				t.Fatalf("\n in : %q\n got: %q\nwant: %q", c.in, got, c.want)
			}
			if again := Mask(got); again != got {
				t.Fatalf("idempotent değil:\n 1: %q\n 2: %q", got, again)
			}
		})
	}
}

const sampleLog = "User valex@example.com tried login with api_key=sk_live_123456 from 10.0.0.1 and Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.sig12345 card 4111 1111 1111 1111"

func TestZeroAlloc(t *testing.T) {
	buf := make([]byte, 0, 4096)
	for _, in := range []string{sampleLog, "temiz satır, hassas veri yok 12:30:45"} {
		n := testing.AllocsPerRun(200, func() { buf = AppendMask(buf[:0], in) })
		if n != 0 {
			t.Fatalf("AppendMask %d alokasyon yaptı, 0 bekleniyordu: %q", int(n), in)
		}
	}
	clean := "temiz satır"
	Mask(clean) // pool ısınsın
	if n := testing.AllocsPerRun(200, func() { _ = Mask(clean) }); n != 0 {
		t.Fatalf("Mask(temiz) alokasyon yaptı: %v", n)
	}
}



var (
	benchEmailRegex  = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	benchBearerRegex = regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\._\-]+`)
	benchApiKeyRegex = regexp.MustCompile(`(?i)(api[_-]?key|secret|token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]+)['"]?`)
	benchCcRegex     = regexp.MustCompile(`\b(?:\d[ -]*?){13,16}\b`)
)

func maskRegex(s string) string {
	s = benchEmailRegex.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = benchBearerRegex.ReplaceAllString(s, "Bearer [REDACTED_TOKEN]")
	s = benchApiKeyRegex.ReplaceAllString(s, "$1=[REDACTED]")
	return benchCcRegex.ReplaceAllString(s, "****-****-****-****")
}

func BenchmarkRegex(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = maskRegex(sampleLog)
	}
}

func BenchmarkMask(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = Mask(sampleLog)
	}
}

func BenchmarkAppendMask(b *testing.B) {
	buf := make([]byte, 0, 4096)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf = AppendMask(buf[:0], sampleLog)
	}
}