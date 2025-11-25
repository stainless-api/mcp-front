package storage

import (
	"context"
	"time"

	"github.com/dgellow/mcp-front/internal/log"
)

// CleanupManager handles periodic cleanup of expired execution sessions
type CleanupManager struct {
	storage  Storage
	interval time.Duration
	stopChan chan struct{}
	doneChan chan struct{}
}

// NewCleanupManager creates a new cleanup manager
func NewCleanupManager(storage Storage, interval time.Duration) *CleanupManager {
	return &CleanupManager{
		storage:  storage,
		interval: interval,
		stopChan: make(chan struct{}),
		doneChan: make(chan struct{}),
	}
}

// Start begins the cleanup loop in a goroutine
func (cm *CleanupManager) Start(ctx context.Context) {
	log.LogInfoWithFields("cleanup", "Starting execution session cleanup manager", map[string]any{
		"interval": cm.interval.String(),
	})

	go cm.run(ctx)
}

// Stop gracefully stops the cleanup loop
func (cm *CleanupManager) Stop() {
	log.LogInfo("Stopping execution session cleanup manager...")
	close(cm.stopChan)
	<-cm.doneChan // Wait for cleanup loop to finish
	log.LogInfo("Execution session cleanup manager stopped")
}

// run is the main cleanup loop
func (cm *CleanupManager) run(ctx context.Context) {
	defer close(cm.doneChan)

	ticker := time.NewTicker(cm.interval)
	defer ticker.Stop()

	// Run cleanup immediately on start
	cm.cleanup(ctx)

	for {
		select {
		case <-ticker.C:
			cm.cleanup(ctx)
		case <-cm.stopChan:
			// Final cleanup on shutdown
			cm.cleanup(ctx)
			return
		case <-ctx.Done():
			// Context cancelled
			return
		}
	}
}

// cleanup performs the actual cleanup operation
func (cm *CleanupManager) cleanup(ctx context.Context) {
	count, err := cm.storage.CleanupExpiredSessions(ctx)
	if err != nil {
		log.LogErrorWithFields("cleanup", "Failed to cleanup expired sessions", map[string]any{
			"error": err.Error(),
		})
		return
	}

	if count > 0 {
		log.LogInfoWithFields("cleanup", "Cleaned up expired execution sessions", map[string]any{
			"count": count,
		})
	}
}
