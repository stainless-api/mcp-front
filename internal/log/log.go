package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	logger       *slog.Logger
	currentLevel atomic.Value // stores slog.Level
)

// LevelTrace is a custom trace level below debug
const LevelTrace = slog.Level(-8)

func init() {
	var level slog.Level

	switch strings.ToUpper(os.Getenv("LOG_LEVEL")) {
	case "ERROR":
		level = slog.LevelError
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "INFO", "":
		level = slog.LevelInfo
	case "DEBUG":
		level = slog.LevelDebug
	case "TRACE":
		level = LevelTrace
	default:
		level = slog.LevelInfo
	}

	// Store initial level
	currentLevel.Store(level)

	// Create handler
	updateHandler()
}

// updateHandler recreates the handler with the current log level
func updateHandler() {
	level := currentLevel.Load().(slog.Level)

	var handler slog.Handler
	if strings.ToUpper(os.Getenv("LOG_FORMAT")) == "JSON" {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{
						Key:   "timestamp",
						Value: slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano)),
					}
				}
				if a.Key == slog.LevelKey && a.Value.Any().(slog.Level) == LevelTrace {
					return slog.Attr{
						Key:   slog.LevelKey,
						Value: slog.StringValue("TRACE"),
					}
				}
				return a
			},
		})
	} else {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: level,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				if a.Key == slog.TimeKey {
					return slog.Attr{
						Key:   slog.TimeKey,
						Value: slog.StringValue(a.Value.Time().Format("2006-01-02 15:04:05.000-07:00")),
					}
				}
				if a.Key == slog.LevelKey && a.Value.Any().(slog.Level) == LevelTrace {
					return slog.Attr{
						Key:   slog.LevelKey,
						Value: slog.StringValue("TRACE"),
					}
				}
				return a
			},
		})
	}

	logger = slog.New(handler)
	slog.SetDefault(logger)
}

// SetLogLevel atomically updates the log level at runtime
func SetLogLevel(level string) error {
	var newLevel slog.Level

	switch strings.ToUpper(level) {
	case "ERROR":
		newLevel = slog.LevelError
	case "WARN", "WARNING":
		newLevel = slog.LevelWarn
	case "INFO":
		newLevel = slog.LevelInfo
	case "DEBUG":
		newLevel = slog.LevelDebug
	case "TRACE":
		newLevel = LevelTrace
	default:
		return fmt.Errorf("invalid log level: %s", level)
	}

	currentLevel.Store(newLevel)
	updateHandler()

	LogInfoWithFields("logging", "Log level changed", map[string]any{
		"new_level": level,
	})

	return nil
}

// GetLogLevel returns the current log level as a string
func GetLogLevel() string {
	level := currentLevel.Load().(slog.Level)

	switch level {
	case slog.LevelError:
		return "error"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelInfo:
		return "info"
	case slog.LevelDebug:
		return "debug"
	case LevelTrace:
		return "trace"
	default:
		return "unknown"
	}
}

// Convenience functions using standard slog with component context
func Logf(format string, args ...any) {
	logger.Info(fmt.Sprintf(format, args...))
}

func LogError(format string, args ...any) {
	logger.Error(fmt.Sprintf(format, args...))
}

func LogWarn(format string, args ...any) {
	logger.Warn(fmt.Sprintf(format, args...))
}

func LogDebug(format string, args ...any) {
	logger.Debug(fmt.Sprintf(format, args...))
}

func LogTrace(format string, args ...any) {
	if currentLevel.Load().(slog.Level) <= LevelTrace {
		logger.Log(context.Background(), LevelTrace, fmt.Sprintf(format, args...))
	}
}

// Structured logging functions with component and fields
func LogInfoWithFields(component, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Info(message, args...)
}

func LogDebugWithFields(component, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Debug(message, args...)
}

func LogErrorWithFields(component, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Error(message, args...)
}

func LogWarnWithFields(component, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	logger.Warn(message, args...)
}

func LogTraceWithFields(component, message string, fields map[string]any) {
	if currentLevel.Load().(slog.Level) <= LevelTrace {
		args := make([]any, 0, len(fields)*2+2)
		args = append(args, "component", component)
		for k, v := range fields {
			args = append(args, k, v)
		}
		logger.Log(context.Background(), LevelTrace, message, args...)
	}
}
