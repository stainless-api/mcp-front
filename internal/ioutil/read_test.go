package ioutil

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadLimited(t *testing.T) {
	t.Run("reads content up to limit", func(t *testing.T) {
		r := strings.NewReader("hello world")
		assert.Equal(t, "hello world", ReadLimited(r, 1024))
	})

	t.Run("truncates at limit", func(t *testing.T) {
		r := strings.NewReader("hello world")
		assert.Equal(t, "hello", ReadLimited(r, 5))
	})

	t.Run("empty reader", func(t *testing.T) {
		r := strings.NewReader("")
		assert.Equal(t, "", ReadLimited(r, 1024))
	})

	t.Run("read error returns description", func(t *testing.T) {
		r := &failingReader{err: fmt.Errorf("connection reset")}
		assert.Equal(t, "<unreadable: connection reset>", ReadLimited(r, 1024))
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
