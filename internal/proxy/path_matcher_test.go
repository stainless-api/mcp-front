package proxy

import (
	"testing"
)

func TestPathMatcherExactMatch(t *testing.T) {
	pm := NewPathMatcher([]string{"/api/v1/metrics"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api/v1/metrics", true},
		{"/api/v1/logs", false},
		{"/api/v2/metrics", false},
		{"/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherSingleWildcard(t *testing.T) {
	pm := NewPathMatcher([]string{"/api/*/metrics"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api/v1/metrics", true},
		{"/api/v2/metrics", true},
		{"/api/foo/metrics", true},
		{"/api/v1/logs", false},
		{"/api/v1/metrics/query", false},
		{"/api/metrics", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherTrailingWildcard(t *testing.T) {
	pm := NewPathMatcher([]string{"/api/v1/*"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api/v1/metrics", true},
		{"/api/v1/logs", true},
		{"/api/v1/anything", true},
		{"/api/v1/metrics/query", false}, // * doesn't match nested paths
		{"/api/v1", false},
		{"/api/v2/metrics", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherRecursiveWildcard(t *testing.T) {
	pm := NewPathMatcher([]string{"/api/**"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api", true},
		{"/api/v1", true},
		{"/api/v1/metrics", true},
		{"/api/v1/metrics/query", true},
		{"/api/v2/logs/search", true},
		{"/other", false},
		{"/other/api/v1", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherMultiplePatterns(t *testing.T) {
	pm := NewPathMatcher([]string{
		"/api/v1/metrics",
		"/api/v2/logs",
		"/api/v3/*",
	})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api/v1/metrics", true},
		{"/api/v2/logs", true},
		{"/api/v3/anything", true},
		{"/api/v3/foo", true},
		{"/api/v1/logs", false},
		{"/api/v4/metrics", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherNoPatterns(t *testing.T) {
	pm := NewPathMatcher([]string{})

	// Empty patterns should allow everything
	tests := []string{
		"/api/v1/metrics",
		"/api/v2/logs",
		"/anything",
		"/",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			if !pm.IsAllowed(path) {
				t.Errorf("IsAllowed(%s) = false, want true (empty patterns should allow all)", path)
			}
		})
	}
}

func TestPathMatcherNormalization(t *testing.T) {
	pm := NewPathMatcher([]string{"/api/v1/metrics/"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api/v1/metrics", true},   // Trailing slash removed
		{"/api/v1/metrics/", true},  // Trailing slash removed
		{"api/v1/metrics", true},    // Leading slash added
		{"api/v1/metrics/", true},   // Both normalized
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherRootWildcard(t *testing.T) {
	pm := NewPathMatcher([]string{"/*"})

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/api", true},
		{"/metrics", true},
		{"/anything", true},
		{"/api/v1", false}, // /* doesn't match nested
		{"/", false},       // /* doesn't match root itself
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := pm.IsAllowed(tt.path)
			if result != tt.allowed {
				t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
			}
		})
	}
}

func TestPathMatcherRecursiveRootWildcard(t *testing.T) {
	pm := NewPathMatcher([]string{"/**"})

	// /** should match everything
	tests := []string{
		"/",
		"/api",
		"/api/v1",
		"/api/v1/metrics",
		"/anything/nested/deep",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			if !pm.IsAllowed(path) {
				t.Errorf("IsAllowed(%s) = false, want true (/** should match all)", path)
			}
		})
	}
}
