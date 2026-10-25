package main

import (
	"regexp"
	"strings"
)


func Mask(input string) string {
	result := input


	passwordRegex := regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret)\b\s*[:=]?\s*("[^"]+"|\S+)?|\bpassword\d+\b`)
	result = passwordRegex.ReplaceAllString(result, "[REDACTED]")

	
	apiKeyRegex := regexp.MustCompile(`(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*([a-zA-Z0-9_\-]+)`)
	result = apiKeyRegex.ReplaceAllString(result, `$1=[REDACTED]`)

	
	awsSecretRegex := regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([a-zA-Z0-9/+=]+)`)
	result = awsSecretRegex.ReplaceAllString(result, `$1=[REDACTED]`)

	
	ghTokenRegex := regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	result = ghTokenRegex.ReplaceAllString(result, "[REDACTED_GITHUB_TOKEN]")

	awsKeyRegex := regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	result = awsKeyRegex.ReplaceAllString(result, "[REDACTED_AWS_KEY_ID]")

	
	jwtRegex := regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`)
	result = jwtRegex.ReplaceAllString(result, "[REDACTED_JWT]")

	
	bearerRegex := regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9_\-\.]+`)
	result = bearerRegex.ReplaceAllString(result, "Bearer [REDACTED_TOKEN]")

	
	ccRegex := regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	result = ccRegex.ReplaceAllString(result, "****-****-****-****")

	
	tcknRegex := regexp.MustCompile(`\b[1-9]\d{10}\b`)
	result = tcknRegex.ReplaceAllString(result, "[REDACTED_TCKN]")

	
	ipv4Regex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	result = ipv4Regex.ReplaceAllString(result, "[REDACTED_IP]")

	
	ipv6Regex := regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}:[0-9a-fA-F]{1,4}|\b(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,1}[0-9a-fA-F]{1,4}|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|\b[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|\b:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)\b`)
	result = ipv6Regex.ReplaceAllString(result, "[REDACTED_IP]")

	
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
