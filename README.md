# valex-mask

Zero-allocation log sanitization for Go.

`valex-mask` masks common secrets and sensitive values before they reach logs: email addresses, JWTs, bearer tokens, GitHub tokens, AWS keys, API keys, JSON passwords, IP addresses, credit cards, and Turkish TCKN IDs.

## Features

- Built for hot log pipelines
- `Mask(s string) string` returns a sanitized copy
- `AppendMask(dst []byte, src string) []byte` appends into a reusable buffer for lower allocation pressure
- Redacts common sensitive patterns without mutating unrelated text
- Validates card numbers with Luhn and TCKN with checksum rules
- Leaves timestamps, dates, and other non-sensitive values alone

## Installation

Install from source:

```bash
git clone https://github.com/Valex-Grand/valex-mask.git
cd valex-mask
go build -o valex-mark.exe .
```

Run the compiled binary:

```bash
valex-mark "User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci..."
```

Or install directly with Go:

```bash
go install github.com/Valex-Grand/valex-mask@latest
```

Example output:

```text
Orijinal : User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci...
Maskeli  : User v****@example.com tried login with api_key=[REDACTED] and Bearer [REDACTED_TOKEN]...
```

## Quick start

```go
package main

import (
    "fmt"

    valexmask "github.com/Valex-Grand/valex-mask"
)

func main() {
    raw := "User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci..."
    fmt.Println(valexmask.Mask(raw))
}
```

## What gets masked

- Email addresses
- Bearer tokens
- JWTs
- GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`)
- AWS Access Key IDs (`AKIA...`, `ASIA...`)
- `aws_secret_access_key=...`
- `api_key=...`, `token=...`, `secret=...`
- JSON password values
- IPv4 / IPv6 addresses
- Credit cards passing Luhn validation
- Turkish national IDs (TCKN) passing checksum validation

## Safe values intentionally left alone

These are left untouched because they are not sensitive or fail validation:

- `12:30:45`
- `2026-10-25`
- `aa:bb:cc:dd:ee:ff`
- `max_tokens=1024`
- invalid card numbers like `4111 1111 1111 1112`
- invalid TCKN values

## Notes

This library is designed as a practical log redaction tool, not a cryptographic sanitizer. It aims to catch common sensitive patterns reliably while avoiding noisy false positives on common log fields.

## License

MIT
