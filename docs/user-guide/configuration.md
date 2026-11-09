# Configure the mediator

## Step 3: write the production configuration

Use the GitHub-only example below to prepare your settings with your own domains and credentials. During [deployment](deployment.md), copy the example to `config.json` in the repository checkout and edit it with these values.

```json
{
  "database_path": "/var/lib/token-mediator/sessions.db",
  "host": "127.0.0.1",
  "port": 8080,
  "session_lifetime": "24h",
  "session_limit": 1000,
  "rate_limit_per_minute": 60,
  "rate_limit_max_ips": 10000,
  "frontend_origin_url": "https://app.example.com",
  "frontend_completion_url": "https://app.example.com/oauth/complete",
  "providers": {
    "github": {
      "client_id": "replace_with_github_client_id",
      "client_secret": "replace_with_github_client_secret",
      "auth_url": "https://github.com/login/oauth/authorize",
      "token_url": "https://github.com/login/oauth/access_token",
      "redirect_url": "https://auth.example.com/oauth/github/callback",
      "scopes": ["read:user", "user:email"]
    }
  }
}
```

Keep the provider key `github` if you use the paths shown here. The callback's `{provider}` segment must match the key. Register the exact `redirect_url` with GitHub.

`frontend_origin_url` must exactly match the browser app's origin, with no trailing slash. `frontend_completion_url` is the separate page the callback redirects to after login. The backend does not add a provider name to that URL.

The mediator must listen on a loopback IP; keep `127.0.0.1:8080` with the Caddy setup in this guide. Docker uses the host network, so the address and Caddy's `reverse_proxy 127.0.0.1:8080` stay unchanged. The configured SQLite path, `/var/lib/token-mediator/sessions.db`, is inside the container and stored in a Docker-managed volume. Docker creates the volume from the image's database directory, which is ready for the non-root mediator; no host database-folder setup is needed. Keep every required field shown above. Session and rate limits must be positive integers. `session_lifetime` must be between one second and 400 days. It is an absolute deadline and does not extend when the user is active. Choose `session_limit` for the number of concurrent sessions the store may hold; it rejects new sessions at capacity rather than evicting existing ones.

`rate_limit_per_minute` is a shared fixed-window limit for OAuth requests from each IP. People behind the same IP share it, and requests can bunch up on either side of a window reset. `rate_limit_max_ips` caps the IPs tracked in a window; when that table is full, new IPs are rejected until the reset.

Keep client secrets out of frontend code and source control. The next step creates the private configuration file, then starts the container.

Continue with [deployment](deployment.md).
