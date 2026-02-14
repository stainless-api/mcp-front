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

var currentLevel atomic.Value // stores slog.Level

// LevelTrace is a custom trace level below debug
const LevelTrace = slog.Level(-8)

func init() {
	level, err := parseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		level = slog.LevelInfo
	}

	currentLevel.Store(level)
	updateHandler()
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToUpper(s) {
	case "ERROR":
		return slog.LevelError, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "INFO", "":
		return slog.LevelInfo, nil
	case "DEBUG":
		return slog.LevelDebug, nil
	case "TRACE":
		return LevelTrace, nil
	default:
		return 0, fmt.Errorf("invalid log level: %s", s)
	}
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

	slog.SetDefault(slog.New(handler))
}

// SetLogLevel atomically updates the log level at runtime
func SetLogLevel(level string) error {
	newLevel, err := parseLevel(level)
	if err != nil {
		return err
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

func Logf(format string, args ...any) {
	slog.Default().Info(fmt.Sprintf(format, args...))
}

func LogError(format string, args ...any) {
	slog.Default().Error(fmt.Sprintf(format, args...))
}

func LogWarn(format string, args ...any) {
	slog.Default().Warn(fmt.Sprintf(format, args...))
}

func LogDebug(format string, args ...any) {
	slog.Default().Debug(fmt.Sprintf(format, args...))
}

func LogTrace(format string, args ...any) {
	if currentLevel.Load().(slog.Level) <= LevelTrace {
		slog.Default().Log(context.Background(), LevelTrace, fmt.Sprintf(format, args...))
	}
}

func buildArgs(component string, fields map[string]any) []any {
	args := make([]any, 0, len(fields)*2+2)
	args = append(args, "component", component)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return args
}

func LogInfoWithFields(component, message string, fields map[string]any) {
	slog.Default().Info(message, buildArgs(component, fields)...)
}

func LogDebugWithFields(component, message string, fields map[string]any) {
	slog.Default().Debug(message, buildArgs(component, fields)...)
}

func LogErrorWithFields(component, message string, fields map[string]any) {
	slog.Default().Error(message, buildArgs(component, fields)...)
}

func LogWarnWithFields(component, message string, fields map[string]any) {
	slog.Default().Warn(message, buildArgs(component, fields)...)
}

func LogTraceWithFields(component, message string, fields map[string]any) {
	if currentLevel.Load().(slog.Level) <= LevelTrace {
		slog.Default().Log(context.Background(), LevelTrace, message, buildArgs(component, fields)...)
	}
}
