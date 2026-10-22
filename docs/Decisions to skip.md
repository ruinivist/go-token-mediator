# Decisions to skip

- Login attempts can overlap. If an older OAuth callback finishes after a newer login starts, there is no extra check to order the attempts, so one may fail.
- When the session store is full, it rejects new sessions and keeps the existing ones. Logging out frees a slot immediately. Expired sessions free their slots during periodic cleanup.
- Sessions live in memory in a single process. Restarting the server means users have to reconnect. Saving sessions across restarts or sharing them between instances is outside this project's scope.
- Providers need to support the OAuth flow used here: authorization codes with S256 PKCE, form-encoded token requests with client credentials in the body, and JSON responses containing bearer tokens. Support for other provider behavior should come from a specific need and be verified with that provider.
- The mediator does not limit how often it sends requests to each provider.
- OAuth requests have one limit per IP in one-minute windows. A client can use its full allowance just before a reset and again just after it. People sharing an IP share the limit. There are no separate limits per user or route, or controls to spread requests evenly over time.
- The rate limiter tracks a limited number of IPs. Once it's full, requests from new IPs are rejected until the next window. Restarting clears the counts, and separate server processes don't share them.
- Go listens on loopback behind Caddy on the same machine and reads one client IP from Caddy's forwarding header. There is no support for proxy chains or remote proxies, and no configuration for trusted address ranges.
