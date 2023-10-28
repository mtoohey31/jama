package jama

import (
	"log/slog"
	"os"
)

var (
	level   = &slog.LevelVar{}
	options = &slog.HandlerOptions{Level: level}
	logger  = slog.New(slog.NewTextHandler(os.Stdout, options))
)
