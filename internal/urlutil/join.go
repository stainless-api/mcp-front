package urlutil

import (
	"net/url"
	"path"
	"strings"
)

// JoinPath safely joins URL paths, handling trailing and leading slashes correctly
func JoinPath(base string, paths ...string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}

	// Join paths, ensuring proper slash handling
	allPaths := append([]string{u.Path}, paths...)
	u.Path = path.Join(allPaths...)

	// Preserve trailing slash if the last path component had one
	if len(paths) > 0 && strings.HasSuffix(paths[len(paths)-1], "/") {
		u.Path += "/"
	}

	return u.String(), nil
}

// MustJoinPath is like JoinPath but panics on error (for use with known-good URLs)
func MustJoinPath(base string, paths ...string) string {
	result, err := JoinPath(base, paths...)
	if err != nil {
		panic(err)
	}
	return result
}
