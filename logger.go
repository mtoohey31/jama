package jama

import (
	"os"

	"golang.org/x/exp/slog"
)

var (
	level   = &slog.LevelVar{}
	options = &slog.HandlerOptions{Level: level}
	logger  = slog.New(slog.NewTextHandler(os.Stdout, options))
)
