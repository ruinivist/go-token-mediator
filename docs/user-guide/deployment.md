# Deploy the service

## Step 4: run the container and Caddy

Run these commands from `~/token-mediator`, with Docker running and Caddy installed.

Copy only for first-time setup; don't overwrite an existing `config.json`.

```sh
# Create the file private to your user.
umask 077
cp config.example.json config.json
# Keep yourself as owner; the container reads as group 65532.
sudo chown "$(id -u):65532" config.json
# Allow reads by you and the container only.
sudo chmod 0640 config.json
```

Open `config.json` in your editor and enter the [Step 3 settings](configuration.md).

The `sessions` volume persists the database and credentials. Run only one mediator per database; do not use `docker compose down -v` unless you intend to delete sessions and provider connections.

```sh
export MEDIATOR_IMAGE=ghcr.io/ruinivist/go-token-mediator:main
sudo docker pull ghcr.io/ruinivist/go-token-mediator:main
sudo env MEDIATOR_IMAGE="$MEDIATOR_IMAGE" docker compose up -d
```

Add this site to `/etc/caddy/Caddyfile`:

```caddyfile
auth.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy must be internet-facing: do not add a proxy or rewrite `X-Forwarded-For`, this is to ensure rate limiting based on ips works correctly.

```sh
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

Continue with [frontend requests](frontend.md).
