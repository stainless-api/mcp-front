package emailutil

import "strings"

// Normalize normalizes an email address for consistent comparison
// by converting to lowercase and trimming whitespace
func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ExtractDomain extracts domain from email address
func ExtractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
