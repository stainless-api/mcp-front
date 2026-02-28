package ioutil

import (
	"fmt"
	"io"
)

// ReadLimited reads up to limit bytes from r and returns the content as a string.
// If reading fails, returns a string describing the read failure instead of silencing
// the error. This is intended for including response bodies in error messages and logs.
func ReadLimited(r io.Reader, limit int64) string {
	body, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return fmt.Sprintf("<unreadable: %v>", err)
	}
	return string(body)
}
