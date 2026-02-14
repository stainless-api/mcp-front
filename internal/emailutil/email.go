package emailutil

import "strings"

// ExtractDomain extracts domain from email address
func ExtractDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}
