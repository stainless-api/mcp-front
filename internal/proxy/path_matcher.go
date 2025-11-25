package proxy

import (
	"path"
	"strings"
)

// PathMatcher validates request paths against allowed patterns
type PathMatcher struct {
	allowedPatterns []string
}

// NewPathMatcher creates a new path matcher with allowed patterns
func NewPathMatcher(allowedPatterns []string) *PathMatcher {
	return &PathMatcher{
		allowedPatterns: allowedPatterns,
	}
}

// IsAllowed checks if a path matches any of the allowed patterns
// Supports glob patterns with * wildcards:
//   - /api/v1/* matches /api/v1/metrics, /api/v1/logs, etc.
//   - /api/* matches /api/v1/metrics, /api/v2/logs, etc.
//   - /* matches everything
func (pm *PathMatcher) IsAllowed(requestPath string) bool {
	// If no patterns specified, deny everything (fail-closed)
	if len(pm.allowedPatterns) == 0 {
		return false
	}

	// Normalize path (remove trailing slash, ensure leading slash)
	requestPath = normalizePath(requestPath)

	for _, pattern := range pm.allowedPatterns {
		pattern = normalizePath(pattern)

		if matchGlobPattern(pattern, requestPath) {
			return true
		}
	}

	return false
}

// normalizePath ensures path has leading slash and no trailing slash
func normalizePath(p string) string {
	// Ensure leading slash
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// Remove trailing slash (except for root)
	if len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}

	return path.Clean(p)
}

// matchGlobPattern matches a path against a glob pattern
// Supports * wildcards:
//   - /api/* matches /api/foo but not /api/foo/bar
//   - /api/** matches /api/foo and /api/foo/bar (recursive)
//   - /api/*/metrics matches /api/v1/metrics, /api/v2/metrics
func matchGlobPattern(pattern, requestPath string) bool {
	// Exact match
	if pattern == requestPath {
		return true
	}

	// Handle /** (recursive wildcard)
	if strings.Contains(pattern, "/**") {
		// Special case: /** matches everything
		if pattern == "/**" {
			return true
		}

		prefix := strings.TrimSuffix(pattern, "/**")
		prefix = normalizePath(prefix)

		// /api/** matches /api and anything under /api/
		if requestPath == prefix || strings.HasPrefix(requestPath, prefix+"/") {
			return true
		}
	}

	// Handle single * wildcard
	if strings.Contains(pattern, "*") {
		// Split pattern into segments
		patternParts := strings.Split(pattern, "/")
		pathParts := strings.Split(requestPath, "/")

		// Must have same number of segments unless last is **
		if len(patternParts) != len(pathParts) {
			return false
		}

		// Match each segment
		for i, patternPart := range patternParts {
			if patternPart == "*" {
				// * matches any single non-empty segment
				if pathParts[i] == "" {
					return false
				}
				continue
			}

			if patternPart != pathParts[i] {
				return false
			}
		}

		return true
	}

	return false
}
