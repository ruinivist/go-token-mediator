# Token mediator architecture

`main` wires the process together. `mediator.Server` coordinates browser requests and provider exchanges; `session.Store` owns session state and its synchronization.

Use the [breakdown](architecture-breakdown.md) to reconstruct the design in smaller steps. These notes describe the current code, including its [intentional limits](<Decisions to skip.md>).

## Runtime and setup

![Deployment UML: browser, local Caddy, Go process, and provider](architecture-runtime.svg)

The frontend starts authorization through the mediator, receives an access token after authorization, and calls the provider's resource API directly. The backend keeps client secrets, refresh tokens, and proof-key verifiers. It does not proxy resource API requests.

The intended deployment has Caddy and Go on the same machine. Go must listen on a loopback IP. The OAuth rate limiter accepts a single `X-Forwarded-For` address from a loopback peer, so local Caddy must supply the client address. Proxy chains and remote proxies are outside this design. The repository does not supply a Caddy configuration or frontend.

Use the Go version declared in [go.mod](../go.mod). There are no third-party Go dependencies. To start the backend with the example configuration:

```sh
make run
```

For a configuration containing your provider registration details:

```sh
make run CONFIG_PATH=/path/to/config.json
```

`make run` sets `CONFIG_PATH`; running `go run .` directly requires you to set it. [config.example.json](../config.example.json) contains placeholder credentials. It starts the backend but does not provide working provider authorization.

| Configuration | Meaning |
| --- | --- |
| `host`, `port` | Loopback listener address and port. The example uses `127.0.0.1:8080`. |
| `session_lifetime`, `session_limit` | Absolute session lifetime and maximum number of stored sessions. The example uses `24h` and `1000`. |
| `rate_limit_per_minute`, `rate_limit_max_ips` | Shared OAuth allowance per IP and maximum tracked IPs. The example uses `60` and `10000`. |
| `frontend_origin_url` | Exact allowed browser origin, including scheme and port. |
| `frontend_completion_url` | Destination after a successful callback. |
| `providers` | Named provider credentials, authorization/token URLs, registered callback URL, and requested scopes. |

Configuration has no defaults. Loading rejects unknown fields and validates required values, positive limits, a loopback host, and a session lifetime between one second and 400 days. It does not comprehensively validate URL syntax or provider compatibility. Provider entries must match the flow described in [Decisions to skip](<Decisions to skip.md>).

For browser authorization, arrange HTTPS at Caddy, matching provider callback URLs, and a frontend/mediator placement compatible with the cookie's `SameSite=Lax` policy. Credentialed cross-origin requests need the frontend to include credentials. CORS permission alone does not override cookie restrictions. The example's HTTP URLs are starting configuration values, not a complete browser deployment; preserve the secure cookie protections when configuring it.

In [main.go](../main.go), startup loads configuration, creates one store, starts cleanup every ten minutes, and constructs the HTTP server. Interrupt or `SIGTERM` cancels the cleanup context and triggers a server `Shutdown` call with a five-second timeout. `Run` returns when `ListenAndServe` exits; it does not wait for the shutdown goroutine to finish draining requests.

## Reading the UML

![Class UML: mediator collaborators and session state ownership](architecture-uml.svg)

The diagrams show selected fields and operations. `+` means exported in Go; `~` means package-scoped. A filled diamond marks ownership, an open arrow marks a navigable association, and a dashed arrow marks a dependency. A stored pointer alone does not imply ownership. Blue names identify logic, green names identify state; color adds no UML semantics.

1. Start with `Server`. It holds configuration and a store supplied by `main`, creates its rate limiter and HTTP server, and wires middleware around route handlers.
2. Follow `Config` to its provider map. `ProviderConfig` holds registration details and performs authorization URL construction, code exchange, and refresh requests. These are concrete Go structs, with no provider interface or subclass hierarchy.
3. Follow `Store` to its private session map and `RWMutex`. Only the session package accesses the mutable session records. A `session` owns one absolute deadline, at most one pending authorization attempt, provider connections, and in-flight update records.
4. Connect `PendingAuth` to authorization. It holds the selected provider, random state, proof-key verifier, and start time. Starting another authorization replaces the previous pending attempt, including one for another provider.
5. Connect `Connection` to token retrieval. It holds access and refresh tokens, granted scopes, and separate token deadlines. Each provider name selects at most one connection per session. Getters return detached values.
6. Follow `connectionUpdate` to concurrent refresh. Its completion channel and error let requests share one update per session/provider. This coordination lives in the store; OAuth-specific decisions stay in the mediator's callback.

The class diagram splits session-owned records into a lower panel. Their map keys and multiplicities describe the stored state, not extra services.

## Browser HTTP boundary

| Route | Behavior |
| --- | --- |
| `GET /health` | Returns `{"status":"ok"}` without browser-origin or OAuth rate-limit checks. |
| `POST /oauth/{provider}/start` | Creates or reuses a session and returns `authorization_url`. |
| `GET /oauth/{provider}/callback` | Consumes pending authorization, exchanges the code, rotates the session ID, and redirects with `303`. |
| `POST /oauth/{provider}/token` | Returns an access token, refreshing when needed. |
| `POST /session/logout` | Deletes the session, clears its cookie, and returns `204`; it does not revoke tokens at the provider. |
| `OPTIONS` on the POST routes | Supports a credentialed browser preflight from the configured origin. |

Browser POST requests pass the exact-origin check, then require `X-OAuth-Bridge: 1`, `Content-Type: application/json`, and an empty object body, `{}`. The body limit is 8 KiB; fields, `null`, and additional JSON values are rejected. Preflights allow POST with `Content-Type` and `X-OAuth-Bridge`.

OAuth start, callback, and token requests share one fixed one-minute allowance per client IP. Logout and preflight requests do not use that allowance. Rejection returns `429` with `Retry-After`; reaching the session capacity also returns `429`, with `session_limit_reached`. Existing sessions are not evicted.

The `__Host-oauth_bridge` cookie contains only an opaque random session ID. It has `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, and no domain attribute. Its expiry follows the session's original absolute deadline. Browser-origin middleware sets `Cache-Control: no-store`; callback middleware also sets `Referrer-Policy: no-referrer`, including on rate-limit rejection.

## Authorization happy path

![Sequence UML: authorization start through callback completion](architecture-authorization.svg)

1. The frontend posts `{}` to the start route with the required headers and credentials. `GetOrCreate` reuses an active cookie session or creates one within the capacity limit. A newly created session gets a cookie.
2. The mediator generates random state and a verifier for Proof Key for Code Exchange (PKCE), then derives the S256 challenge. `SetPendingAuth` saves the provider, state, verifier, and creation time under the store lock. The response contains an authorization URL with the challenge, not the verifier. The later exchange must supply that verifier to prove it belongs to the same authorization attempt.
3. The browser navigates to that URL. After provider approval, it follows a redirect to the callback with a code and state, carrying the mediator's cookie.
4. `ConsumePendingAuth` checks session activity, provider, state, and the ten-minute attempt lifetime under one lock. A valid attempt is removed before any code exchange. Provider denial or a missing code is rejected after this consumption; retry requires a new start.
5. The mediator exchanges the code and verifier with the provider, using the request context. Client credentials travel in the form body. No store lock is held during the HTTP request.
6. After validating the response, `CompleteAuth` saves the connection and rotates the session ID in one locked operation. Other provider connections and the original session deadline survive. If the session was deleted or expired during the exchange, completion fails.
7. The callback sets the rotated cookie and redirects to `frontend_completion_url`. Tokens do not appear in this redirect. The frontend then calls the token route to obtain the access token.

Invalid callback state never reaches the provider. A consumed attempt cannot be replayed, even if the exchange fails. Overlapping login attempts have the ordering limit recorded in [Decisions to skip](<Decisions to skip.md>).

## Token retrieval and refresh

![Sequence UML: shared refresh and guarded state update](architecture-refresh.svg)

The token handler calls `Store.UpdateConnection` with a callback that receives a connection copy. That callback decides whether to return cached credentials, contact the provider, or remove the connection.

| Stored state | Decision |
| --- | --- |
| Access expiry unknown, or more than two minutes away | Return the existing token. Unknown expiry does not trigger proactive refresh. |
| Access expiry at most two minutes away; usable refresh token | Refresh, including when the access token has already expired. |
| No usable refresh token; access token still valid | Return the existing token until it expires. |
| No usable refresh token; access token expired | Remove the connection and require authorization again. |

On successful refresh, an omitted refresh token preserves the old one and its deadline. A replacement refresh token clears the old deadline unless the response supplies a new deadline. Omitted scope preserves the old scope. Omitted access-token lifetime produces an unknown access expiry.

The frontend receives `access_token`, `token_type: "Bearer"`, and optional remaining `expires_in` and `scope`. Refresh tokens remain on the backend. The handler checks known access expiry again before returning a successful response.

## Concurrency and failure handling

| Concern | Protection and tradeoff |
| --- | --- |
| Callback replay | Validate and consume the pending attempt atomically before exchanging a code. |
| Session fixation during completion | Save the connection and replace the session map key atomically. The previous ID stops working. |
| Concurrent refresh | Register `connectionUpdate` under the store lock before releasing it. Later requests wait on the same completion channel. |
| Unrelated users blocked by provider latency | Run the update callback outside the global lock, passing a connection copy. |
| Logout, expiry, or reconnect during refresh | Before writing, check that the session still belongs to the store, is active, and still has the original connection pointer. Discard stale results. |
| Session ID rotation during another provider's refresh | The write check follows the session's current ID. A request using the obsolete ID still fails when reading the result. |
| Cancellation | A waiter can cancel its wait without canceling the initiating request. The provider call uses the initiating request's context; its cancellation affects the shared update. |
| Delayed waiter | Read the current stored connection after completion. A delayed waiter may receive a newer refresh result; the shared update error is preserved. |
| Capacity and expiry | Expired sessions are rejected immediately on access, but occupy capacity until cleanup. Logout frees capacity immediately. |

Provider requests have a 15-second timeout, reject redirects, and read at most 64 KiB of response data. Validation checks successful status, JSON shape, bearer token type when present, nonempty tokens, and positive, representable lifetimes. Initial authorization additionally requires `token_type`; refresh accepts its omission. HTTP header, read, and idle timeouts are five, ten, and sixty seconds respectively.

| Refresh outcome | Stored connection and browser result |
| --- | --- |
| `invalid_grant` or `bad_refresh_token` | Delete the connection; return `401 reauthorization_required`. |
| Uncertain consumption, such as a transport failure or malformed successful response | Delete the connection; return a sanitized `502 provider_error` or `504 provider_timeout`. The next token request requires authorization. |
| Other explicit provider rejection | Retain the connection, but return a sanitized provider error for this request. |
| Missing or stale session/connection | Return `401 reauthorization_required`. |

Automatic retries are absent: codes are single-use, and a refresh token might have rotated even when the response was lost. Logout deletes local state only. An access token already issued to the browser can remain valid at the provider.

## Guidance when changing the design

- Keep HTTP validation and provider protocol decisions in `mediator`; keep mutable state and atomic operations in `session`. `main` supplies the concrete collaborators. No extra interface is needed for this arrangement.
- Preserve check-and-change operations as store methods. Separate calls to validate then consume, or save then rotate, would reopen race windows.
- Keep provider HTTP calls outside the store lock. Sharing a mutex is insufficient if an old response can overwrite a replacement connection.
- Return copies across the store boundary. Do not expose the session map or pointers to stored connections.
- Preserve exact-origin, header, body, cookie, cancellation, response-limit, and error-sanitizing checks together. Never log credentials, session cookies, codes, state, or tokens.
- Use the existing `httptest` providers for changes. [OAuth flow tests](../internal/mediator/oauth_flow_test.go) cover completion and browser-visible behavior; [refresh tests](../internal/mediator/refresh_test.go) cover expiry and upstream outcomes; [store tests](../internal/session/store_test.go) cover atomic operations and races. Run `go test -race ./...` when synchronization changes.
- Keep the system's in-memory, single-process limits explicit. Read [Decisions to skip](<Decisions to skip.md>) before proposing persistence, additional provider modes, or more rate-limit policies.
