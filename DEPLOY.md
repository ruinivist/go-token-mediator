# Deploy behind Caddy on Debian or Ubuntu

This guide runs the Go service and Caddy on one Linux server. Caddy serves
`auth.example.com`; deploy the frontend separately at `app.example.com`.
Replace both example domains with your own throughout.

## Before you start

- Point `auth.example.com` to this server. Allow inbound TCP traffic on ports
  80 and 443 so Caddy can obtain and renew certificates.
- Install Caddy with the [official Debian or Ubuntu instructions](https://caddyserver.com/docs/install#debian-ubuntu-raspbian). Use the package's systemd service.
- Install the Go version declared in [`go.mod`](go.mod), then check out this repository on the server.
- Make sure the frontend implements `https://app.example.com/oauth/complete`.

Both sites must use HTTPS and share the `example.com` parent domain. The session
cookie uses `SameSite=Lax`, so browsers send it between these two sites. Keep
Caddy directly reachable from the internet. This service does not support a
CDN or another proxy in front of Caddy.

## Configure the service

Create a system user and a private configuration directory. The install command
sets the configuration file's owner and mode before you add credentials.

```sh
sudo useradd --system --user-group --no-create-home token-mediator
sudo install -d -o root -g token-mediator -m 0750 /etc/token-mediator
sudo install -o root -g token-mediator -m 0640 config.example.json /etc/token-mediator/config.json
sudoedit /etc/token-mediator/config.json
```

In the copied [`config.example.json`](config.example.json), change these values:

- Set `database_path` to `/var/lib/token-mediator/sessions.db`.
- Keep `host` at `127.0.0.1` and `port` at `8080`.
- Set `frontend_origin_url` to `https://app.example.com`, without a trailing slash.
- Set `frontend_completion_url` to `https://app.example.com/oauth/complete`.
- For each provider you use, set its real `client_id` and `client_secret`. Set
  `redirect_url` to the matching callback below and register that exact URL with
  the provider. Keep the provider's correct authorization URL, token URL, and
  scopes. Remove provider entries you do not use.

```text
https://auth.example.com/oauth/github/callback
https://auth.example.com/oauth/google/callback
```

Keep `session_lifetime`, `session_limit`, `rate_limit_per_minute`, and
`rate_limit_max_ips` in the file with valid values. The configuration loader
requires these settings.

The frontend must send browser POST requests with `credentials: "include"`,
`X-OAuth-Bridge: 1`, `Content-Type: application/json`, and the body `{}`. The
configured frontend origin must match the browser's origin exactly.

## Build and install

Build from the checked-out repository using the Go version declared in
`go.mod`, then install the binary:

```sh
cd /path/to/go-token-mediator
go build -o ./token-mediator .
sudo install -o root -g root -m 0755 ./token-mediator /usr/local/bin/token-mediator
rm ./token-mediator
```

Create `/etc/systemd/system/token-mediator.service`:

```ini
[Unit]
Description=Token mediator
After=network-online.target
Wants=network-online.target

[Service]
User=token-mediator
Group=token-mediator
Environment=CONFIG_PATH=/etc/token-mediator/config.json
StateDirectory=token-mediator
UMask=0077
ExecStart=/usr/local/bin/token-mediator
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

`StateDirectory` creates persistent writable storage at
`/var/lib/token-mediator`. SQLite keeps its database there across service
restarts and binary updates. It creates the database with mode `0600`. The
database and any backups contain provider credentials, so keep them private.
Run one service process only; the SQLite file has exclusive process ownership.

Load and start the service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now token-mediator
```

## Configure Caddy

Edit `/etc/caddy/Caddyfile` and add:

```caddyfile
auth.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy manages HTTPS certificates and forwards the client IP expected by the
service. Do not rewrite `X-Forwarded-For` or put another proxy in front of
Caddy. Keep port `8080` private to the server. Do not enable access logs or
other request logging that records callback query strings. Provider callbacks
contain authorization codes and state in the URL.

Validate the file, then enable and reload Caddy:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

## Check the deployment

Check the service and its public health endpoint:

```sh
sudo systemctl status token-mediator --no-pager
curl -i https://auth.example.com/health
```

The health request should return `200` with `{"status":"ok"}`. Then test a
browser login from the frontend: start provider authorization, finish at the
provider, and confirm the callback returns to the frontend completion page.

For an update, build and install the new binary with the same commands, then
restart the service. Keep `/var/lib/token-mediator` and the private config file.
