package ioutil

import (
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestReadLimited(t *testing.T) {
	t.Run("reads content up to limit", func(t *testing.T) {
		r := strings.NewReader("hello world")
		got := ReadLimited(r, 1024)
		if got != "hello world" {
			t.Errorf("got %q, want %q", got, "hello world")
		}
	})

	t.Run("truncates at limit", func(t *testing.T) {
		r := strings.NewReader("hello world")
		got := ReadLimited(r, 5)
		if got != "hello" {
			t.Errorf("got %q, want %q", got, "hello")
		}
	})

	t.Run("empty reader", func(t *testing.T) {
		r := strings.NewReader("")
		got := ReadLimited(r, 1024)
		if got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})

	t.Run("read error returns description", func(t *testing.T) {
		r := &failingReader{err: fmt.Errorf("connection reset")}
		got := ReadLimited(r, 1024)
		if got != "<unreadable: connection reset>" {
			t.Errorf("got %q, want error description", got)
		}
	})
}

type failingReader struct {
	err error
}

func (r *failingReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

// Verify failingReader implements io.Reader
var _ io.Reader = (*failingReader)(nil)
