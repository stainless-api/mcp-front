package server

import (
	"context"
	"sync"
)

// streamableSessionStore manages Mcp-Session-Id values for streamable-http backends.
// It allows GET handlers to wait for a session ID established by a concurrent POST initialize.
type streamableSessionStore struct {
	mu      sync.Mutex
	ids     map[string]string
	waiters map[string][]chan string
}

func newStreamableSessionStore() *streamableSessionStore {
	return &streamableSessionStore{
		ids:     make(map[string]string),
		waiters: make(map[string][]chan string),
	}
}

func (s *streamableSessionStore) store(userEmail, sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ids[userEmail] = sessionID
	for _, ch := range s.waiters[userEmail] {
		select {
		case ch <- sessionID:
		default:
		}
	}
	delete(s.waiters, userEmail)
}

// get returns the stored session ID for a user, if any, without blocking.
func (s *streamableSessionStore) get(userEmail string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.ids[userEmail]
	return id, ok
}

// delete removes any stored session ID for a user.
func (s *streamableSessionStore) delete(userEmail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.ids, userEmail)
}

// waitFor returns the session ID for a user, waiting until one is stored or ctx is done.
func (s *streamableSessionStore) waitFor(ctx context.Context, userEmail string) (string, bool) {
	s.mu.Lock()
	if id, ok := s.ids[userEmail]; ok {
		s.mu.Unlock()
		return id, true
	}
	ch := make(chan string, 1)
	s.waiters[userEmail] = append(s.waiters[userEmail], ch)
	s.mu.Unlock()

	select {
	case id := <-ch:
		return id, true
	case <-ctx.Done():
		s.mu.Lock()
		waiters := s.waiters[userEmail]
		for i, w := range waiters {
			if w == ch {
				s.waiters[userEmail] = append(waiters[:i], waiters[i+1:]...)
				break
			}
		}
		if len(s.waiters[userEmail]) == 0 {
			delete(s.waiters, userEmail)
		}
		s.mu.Unlock()
		return "", false
	}
}
