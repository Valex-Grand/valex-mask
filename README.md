<div align="center">

# 🛡️ valex-mask

**Zero-allocation log sanitization for Go.**
Mask secrets, PII, card numbers and IP addresses before they ever reach your logs.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Allocations](https://img.shields.io/badge/allocs-0%20/op-brightgreen?style=for-the-badge)](#-benchmarks)
[![Dependencies](https://img.shields.io/badge/dependencies-0-blue?style=for-the-badge)](go.mod)

[Features](#-features) · [Install](#-installation) · [Quick Start](#-quick-start) · [What Gets Masked](#-what-gets-masked) · [Benchmarks](#-benchmarks) · [Limitations](#-limitations)

</div>

---

## ✨ Why valex-mask?

Regex-based redaction is easy to write and expensive to run: every pass allocates, and on a hot logging path that turns into GC pressure. `valex-mask` replaces the regex chain with a **single-pass, byte-level scanner** that writes into a buffer you own.

```
   Incoming log                valex-mask                    Clean log
┌───────────────────┐    ┌──────────────────────┐    ┌───────────────────────┐
│ api_key=sk_live_… │ ─▶ │  one pass over bytes │ ─▶ │ api_key=[REDACTED]    │
│ valex@example.com │    │  lookup tables       │    │ v***@example.com      │
│ 4111 1111 1111 …  │    │  sync.Pool buffers   │    │ ****-****-****-****   │
└───────────────────┘    └──────────────────────┘    └───────────────────────┘
```

## 🚀 Features

| | Feature | Details |
|---|---|---|
| ⚡ | **Zero allocation** | `AppendMask` into a reused buffer performs **0 allocs/op**. `Mask` allocates only the result string, and nothing at all for clean lines. |
| 🔍 | **Single pass** | One linear scan with 256-entry lookup tables. Scan windows are capped, so pathological input cannot blow up. |
| 🎯 | **Validated matches** | Card numbers must pass **Luhn**; Turkish ID numbers must pass the official **TCKN checksum**. Random digits are left alone. |
| 🔄 | **Idempotent** | Masking already-masked text changes nothing. Safe to run at multiple layers. |
| 📦 | **No dependencies** | Standard library only. |
| 🧪 | **Tested for false positives** | Timestamps, versions, MAC addresses and `max_tokens=1024` are explicitly covered by tests. |

## 📦 Installation

```bash
go get -u github.com/Valex-Grand/valex-mask
```

## 💡 Quick Start

### Standard usage: `Mask`

Simplest API. Returns the original string untouched (no allocation) when there is nothing to mask.

```go
package main

import (
	"fmt"

	valexmask "github.com/Valex-Grand/valex-mask"
)

func main() {
	raw := "User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci..."

	fmt.Println(valexmask.Mask(raw))
	// User v***@example.com tried login with api_key=[REDACTED] and Bearer [REDACTED_TOKEN]
}
```

### High-throughput usage: `AppendMask`

Reuse one buffer per goroutine (or per request) and the hot path allocates nothing.

```go
buf := make([]byte, 0, 4096)

for line := range lines {
	buf = valexmask.AppendMask(buf[:0], line)
	out.Write(buf)
}
```

> 💡 `AppendMask` appends to `dst`, so pass `buf[:0]` to overwrite or `buf` to accumulate.

## 🎯 What Gets Masked

| Category | Detected | Replaced with |
|---|---|---|
| 🔐 **Credentials** | `api_key=…`, `secret=…`, `token=…`, `password=…` (also JSON `"password": "…"`) | `…=[REDACTED]` |
| | `Bearer <token>` | `Bearer [REDACTED_TOKEN]` |
| | JSON Web Tokens (`eyJ….….…`) | `[REDACTED_JWT]` |
| | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`) | `[REDACTED_GITHUB_TOKEN]` |
| | AWS Access Key IDs (`AKIA…`, `ASIA…`) | `[REDACTED_AWS_KEY_ID]` |
| | AWS secret keys (via `aws_secret_access_key=…`) | `…=[REDACTED]` |
| | Stripe (`sk_live_`, `rk_live_`), Slack (`xoxb-`, `xoxp-`), Google (`AIza…`) | `[REDACTED_STRIPE_KEY]` etc. |
| 👤 **Identity** | Email addresses | `v***@example.com` |
| | Turkish national ID (TCKN, checksum-verified) | `[REDACTED_TCKN]` |
| 💳 **Financial** | Credit cards, 13 to 19 digits, Luhn-verified, spaces or dashes allowed | `****-****-****-****` |
| 🌐 **Network** | IPv4 | `[REDACTED_IP]` |
| | IPv6 (full and `::` compressed) | `[REDACTED_IP]` |

### Before / after

```text
src=10.0.0.1 dst=2001:db8::8a2e:370:7334 ok
src=[REDACTED_IP] dst=[REDACTED_IP] ok

jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
jwt=[REDACTED_JWT]

kart 4111 1111 1111 1111 tckn 10000000146
kart ****-****-****-**** tckn [REDACTED_TCKN]

{"password": "hunter2", "max_tokens": 1024}
{"password": "[REDACTED]", "max_tokens": 1024}
```

### ✅ Deliberately left alone

| Input | Why it is safe |
|---|---|
| `12:30:45` | Timestamp, not an IPv6 address (needs `::` or 8 groups) |
| `2026-10-25` | Date, fails card and ID validation |
| `aa:bb:cc:dd:ee:ff` | MAC address (6 groups, no `::`) |
| `max_tokens=1024` | Value too short to be a secret |
| `4111 1111 1111 1112` | Fails Luhn |
| `10000000147` | Fails TCKN checksum |
| `bearer of bad news` | Word after "bearer" is too short to be a token |

## 📊 Benchmarks

Measured on a 2-core Intel Xeon @ 2.8 GHz, Go 1.24, against a typical four-regex redaction chain, using a single log line containing an email, API key, IPv4, JWT bearer token and card number:

| Implementation | Time / op | Memory / op | Allocs / op |
|---|---:|---:|---:|
| Regex chain | 25,536 ns | 1,794 B | 19 |
| `Mask` | 2,035 ns | 144 B | **1** |
| `AppendMask` | 1,814 ns | 0 B | **0** |

That is roughly **12-14x faster**, with the allocation count dropping to zero on the buffer-reuse path. Your numbers will vary with hardware and input; run them yourself:

```bash
# Unit tests, race detector, zero-allocation assertions
go test -v -race ./...

# Benchmarks
go test -bench=. -benchmem
```

## 🧠 How it works

1. **Word-boundary gating.** Detectors only start at the beginning of a token, so most bytes cost a single table lookup.
2. **Ordered detectors.** Prefix secrets, JWT, Bearer, `key=value`, email, then numeric (IPv4, card, TCKN) and IPv6.
3. **Lazy copying.** Unchanged spans are copied in bulk only when a match is found, so clean lines never get copied at all in `Mask`.
4. **Pooled buffers.** `Mask` borrows scratch space from a `sync.Pool`; `AppendMask` lets you bring your own.

## ⚠️ Limitations

Being upfront about what this is and is not:

- **Heuristic, not a guarantee.** It catches well-known formats. Treat it as a safety net, not a substitute for not logging secrets in the first place.
- **Version strings that look like IPs.** `1.2.3.4` is indistinguishable from an IPv4 address and will be masked. (`v1.2.3` and `1.2.3.4.5` are left alone.)
- **Embedded IPv4 in IPv6** (`::ffff:1.2.3.4`) is not recognized as one address; the IPv4 part is masked on its own.
- **Standalone AWS secret keys** (40 random characters with no `secret=` label) are not detected, because doing so would produce too many false positives.
- **Long numeric IDs.** A 13 to 19 digit number that happens to pass Luhn (about 1 in 10) will be masked.
- Input is processed as `string`. If your logs arrive as `[]byte`, convert first.

## 🤝 Contributing

Issues and pull requests are welcome. For a new detector, please include:

- positive cases **and** false-positive cases in `mask_test.go`
- confirmation that `TestZeroAlloc` still passes
- idempotency (masking the output must not change it)

## 📄 License

MIT. See [LICENSE](LICENSE) for details.

<div align="center">

Made with ❤️ by **Valex**

</div>
