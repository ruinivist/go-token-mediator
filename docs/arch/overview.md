# Token mediator at a glance

The mediator runs in one Go process: `main` wires `mediator.Server` to the SQLite-backed `session.Store`. The component map summarizes their responsibilities; the sequence diagrams trace authorization and token retrieval.

![Logical component map of the token mediator](component-map.svg)

`main` loads configuration, opens the SQLite-backed `session.Store`, starts ten-minute cleanup, and runs `mediator.Server`. During shutdown, the server drains and waits for handlers; `main` then stops cleanup and closes the store. The server owns browser request protections and OAuth policy. The store owns session state, SQL transactions, and a refresh coordinator that holds no credentials. See [`main.go`](../../main.go#L26-L68), [`mediator.Server`](../../internal/mediator/server.go#L20-L62), and [`session.Open`](../../internal/session/store.go#L118-L171).

In the README's browser flow, the frontend receives an opaque session cookie and access tokens, then calls provider resource APIs directly ([README](../../README.md)). The mediator has no resource-proxy route ([registered routes](../../internal/mediator/server.go#L109-L120)). Client secrets, refresh tokens, and PKCE verifiers stay on the backend. Because the repository includes no frontend or Caddy configuration, this diagram shows logical responsibilities rather than deployment placement. The local Caddy assumption is recorded in [Decisions to skip](../decisions.md).

## Authorization: consume before exchanging

![Authorization sequence from start through callback completion](authorization-sequence.svg)

The start route creates state and PKCE material, then `BeginAuth` stores the verifier and pending attempt before returning the authorization URL and cookie. On callback, `ConsumeAuth` matches and deletes the attempt atomically before any provider exchange. `CompleteAuth` saves the connection and rotates the cookie in one transaction, preserving the session deadline and other providers. See [`providerOAuthStart` and `providerOAuthCallback`](../../internal/mediator/server.go#L173-L308) and the [store transactions](../../internal/session/store.go#L241-L348).

Invalid, expired, and replayed attempts stop before the provider. Once a valid attempt is consumed, denial, a missing code, exchange failure, or failed completion cannot make it reusable. Completion also rejects a logged-out, expired, or already-rotated session. The complete [authorization leaf](authorization.md) covers roles, records, HTTP details, outcomes, and cookie rotation. The known overlapping-attempt limit remains in [Decisions to skip](../decisions.md). Tests: [`TestOAuthFlow`](../../internal/mediator/oauth_flow_test.go#L24-L235) and [`TestAuthorizationTransactions`](../../internal/session/store_test.go#L67-L119).

## Token retrieval: share work, guard persistence

![Token retrieval sequence with the cache branch, shared refresh, and guarded persistence](token-retrieval-sequence.svg)

When expiry is unknown or more than two minutes remain, the mediator returns cached credentials without a write. Near expiry, it coordinates one refresh per stable session/provider. Concurrent callers share the result, and each waiter can cancel its own wait. The leader rechecks current state and commits a refresh claim before contacting the provider. Its request context controls the provider call; an independent five-second context controls outcome persistence, even after cancellation.

Provider HTTP runs outside SQL transactions and coordination locks. The store saves successful credentials only against the claimed revision. If the provider outcome is uncertain, it may have consumed a rotating refresh token, so the mediator discards that connection rather than reusing it. A known non-consuming rejection saves the original credentials to clear the claim marker, except `invalid_grant` and `bad_refresh_token`, which discard the connection; the sequence omits this branch. See [`accessConnection`](../../internal/mediator/refresh.go#L17-L115), [`CoordinateRefresh`](../../internal/session/refresh.go#L19-L45), and the [guarded store writes](../../internal/session/store.go#L392-L435).

If final persistence fails, the committed marker leaves the old credentials unavailable. Startup removes unfinished connections, so the user must authorize that provider again. Logout removes local session state but does not revoke provider-issued tokens. These are intentional limits in [Decisions to skip](../decisions.md). Tests: [`TestProviderToken_ConcurrentRefresh` and refresh failures](../../internal/mediator/refresh_test.go#L238-L390), plus [store recovery and refresh guards](../../internal/session/store_test.go#L194-L257).
