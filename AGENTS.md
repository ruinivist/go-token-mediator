# Project intent

This is a minimal Go learning implementation of a token-mediating backend. Prioritize correctness, readable code, and clear ownership over feature completeness. Keep the implementation small enough to understand end to end.

Intentional limits belong in [Decisions to skip](docs/Decisions%20to%20skip.md). Read that file before proposing additions; do not turn those decisions into an automatic feature backlog.

## Architecture

- `main.go` wires configuration, signal cancellation, session cleanup, and the HTTP server.
- `internal/mediator` owns configuration validation, HTTP routes, browser request protections, and outbound OAuth exchanges and refreshes.
- `internal/session` owns session state, pending authorization, provider connections, expiry, and synchronization. Keep its mutable state private and return copies.

The browser starts authorization and receives a provider URL and an opaque session cookie. The callback validates and consumes pending authorization, exchanges the code, saves the connection, rotates the session ID, and redirects to the configured frontend completion URL. The frontend requests access tokens and calls provider APIs directly. Refresh happens on the backend when needed.

## Correctness

- Keep client secrets, refresh tokens, and PKCE verifiers on the backend. Never log tokens, credentials, session cookies, authorization codes, or state.
- Validate the callback's session, provider, state, and pending-attempt expiry before exchanging a code. Consume valid pending authorization atomically so it cannot be replayed.
- Preserve cookie protections and the exact-origin, CSRF-header, and empty-JSON checks on browser POST requests.
- Save authorization results and rotate the session ID atomically. Preserve other provider connections and the absolute session deadline.
- Share concurrent refresh work per session/provider. Run provider HTTP calls outside the global store lock, and reject stale writes after logout, expiry, or connection replacement.
- Preserve request cancellation, timeouts, body limits, upstream response validation, and sanitized errors. Do not retry exchanges or refreshes blindly; codes are single-use and refresh tokens may rotate.

## Making changes

- Read the affected code and its callers first. Update affected tests, fixtures, and configuration together.
- Reuse existing helpers and package boundaries. Prefer the standard library and direct code; add dependencies or abstractions only for a concrete need.
- Keep changes scoped to the request. Preserve useful learning comments and explain non-obvious correctness choices briefly.
- Do not implement brittle, indirect, surprising, or workaround-based solutions. If no clean solution fits, explain the options and tradeoffs before implementing a workaround.
- Add a focused regression test for meaningful behavior changes. Use the existing `httptest` providers rather than real credentials or live services.

## Development

- `make run` runs with `config.example.json`; override with `make run CONFIG_PATH=/path/to/config.json`. Example credentials are placeholders.
- `make test` or `go test ./...` runs the tests.
- Run `go test -race ./...` when changing session synchronization or concurrent request behavior.
- Format changed Go files with `gofmt`. Documentation-only changes need a diff and link check rather than runtime tests.
