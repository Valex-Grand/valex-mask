package main

import "fmt"

func main() {
	logs := []string{
		"User valex@example.com tried login with api_key=sk_live_123456 and Bearer eyJhbGci...",
		"src=10.0.0.1 dst=2001:db8::8a2e:370:7334 ok",
		"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
		"gh ghp_abcdefghijklmnopqrstuvwxyz0123456789 aws AKIAIOSFODNN7EXAMPLE",
		"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"kart 4111 1111 1111 1111 tckn 10000000146",
		`{"password": "hunter2", "max_tokens": 1024}`,
		"12:30:45 2026-10-25 aa:bb:cc:dd:ee:ff temiz satır",
	}
	for _, l := range logs {
		fmt.Println("Orijinal :", l)
		fmt.Println("Maskeli  :", Mask(l))
		fmt.Println("--------------------------------------------------")
	}
}
