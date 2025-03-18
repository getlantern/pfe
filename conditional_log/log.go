package conditional_log

import (
	"context"

	"github.com/getlantern/lantern-cloud/log"
)

type LogLevel int

const (
	LevelInfo LogLevel = iota
	LevelDebug
	LevelTrace
)

var (
	logLevel LogLevel
)

func SetLogLevel(lvl LogLevel) {
	logLevel = lvl
}

func Level() LogLevel {
	return logLevel
}

func Trace(ctx context.Context, name string, fields ...any) {
	Log(ctx, LevelTrace, name, fields...)
}

func Debug(ctx context.Context, name string, fields ...any) {
	Log(ctx, LevelDebug, name, fields...)
}

func Log(ctx context.Context, lvl LogLevel, name string, fields ...any) {
	switch lvl {
	case LevelTrace:
		if logLevel >= LevelTrace {
			log.Trace(ctx, name, fields...)
		}
	case LevelDebug:
		if logLevel >= LevelDebug {
			log.Debug(ctx, name, fields...)
		}
	case LevelInfo:
		log.Info(ctx, name, fields...)
	}
}
