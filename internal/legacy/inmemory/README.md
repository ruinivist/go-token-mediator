# Frozen in-memory store

This package preserves the original store and its tests for learning and comparison.
The canonical implementation lives in `internal/session`; it does not use this package
or preserve its API. Keep this archive independent and frozen.

Run its original tests with `go test ./internal/legacy/inmemory`.
