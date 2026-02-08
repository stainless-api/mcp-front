package hostmatch

import (
	"net"
	"strings"
)

func Match(host string, patterns []string) bool {
	host = stripPort(strings.ToLower(host))
	for _, p := range patterns {
		p = stripPort(strings.ToLower(p))
		if p == host {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			suffix := p[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && host != suffix[1:] {
				return true
			}
		}
	}
	return false
}

func stripPort(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}
