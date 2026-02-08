package proxy

import (
	"context"
	"time"
)

type RequestTrace struct {
	Start time.Time

	// Phase durations
	DenyListCheck  time.Duration
	JWEDecrypt     time.Duration
	PathParse      time.Duration
	HostMatch      time.Duration
	RequestBuild   time.Duration
	UpstreamRoundTrip time.Duration
	ResponseStream time.Duration

	// Total wall-clock time for the entire request
	Total time.Duration

	// Metadata
	Method         string
	TargetHost     string
	TargetPath     string
	StatusCode     int
	CredentialCount int
	RequestBodyBytes  int64
	ResponseBodyBytes int64
}

type TraceCallback func(RequestTrace)

type contextKey struct{}

func traceFromContext(ctx context.Context) *RequestTrace {
	t, _ := ctx.Value(contextKey{}).(*RequestTrace)
	return t
}

func contextWithTrace(ctx context.Context, t *RequestTrace) context.Context {
	return context.WithValue(ctx, contextKey{}, t)
}
