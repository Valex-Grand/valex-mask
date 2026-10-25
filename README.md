valex-mask 🛡️

valex-mask is a zero-allocation, high-performance Go library designed to sanitize logs and sensitive text by masking PII, secrets, API keys, tokens, and financial data in real-time.

🚀 Features

Zero-Allocation Design: Optimized with sync.Pool and lookup tables to minimize Garbage Collector (GC) pressure in high-throughput systems.

Comprehensive Masking:

PII & Credentials: Emails, Passwords, API Keys, JWT tokens, AWS Key IDs & Secrets, GitHub/Bearer tokens.

Network & System: IPv4, IPv6 addresses.

Financial & Identity: Credit Cards (with strict Luhn algorithm validation), Turkish TCKN (with checksum validation).

False-Positive Prevention: Ensures safe structural data (like timestamps, versions, MAC addresses, and non-sensitive fields like max_tokens=1024) remain untouched.

Idempotent: Safe to run multiple times on already masked text without corrupting data.

📦 Installation

To install valex-mask in your Go project, run:

go get github.com/Valex-Grand/valex-mask


💡 Usage

1. Standard Usage (Mask)

The simplest way to sanitize log strings:

package main

import (
	"fmt"
	"github.com/Valex-Grand/valex-mask"
)

func main() {
	rawLog := "User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci..."
	
	safeLog := valexmask.Mask(rawLog)
	
	fmt.Println(safeLog)
	// Output: User v***@example.com tried login with api_key=[REDACTED] and Bearer [REDACTED_TOKEN]
}


2. High-Performance / Zero-Allocation Usage (AppendMask)

For high-traffic microservices where memory allocations must be strictly avoided:

package main

import (
	"fmt"
	"github.com/Valex-Grand/valex-mask"
)

func main() {
	rawLog := "src=10.0.0.1 dst=2001:db8::8a2e:370:7334"
	
	buf := make([]byte, 0, 1024)
	buf = valexmask.AppendMask(buf[:0], rawLog)
	
	fmt.Println(string(buf))
	// Output: src=[REDACTED_IP] dst=[REDACTED_IP]
}


🛠️ Testing & Benchmarks

Run unit tests with race detection and zero-allocation checks:

go test -v -race ./...


Run performance benchmarks:

go test -bench=. -benchmem


📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
