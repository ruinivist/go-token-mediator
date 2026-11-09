# Operate the service

## Step 6: check the deployment

From the repository checkout, use the same image as deployment to check the container and public health endpoint:

```sh
export MEDIATOR_IMAGE=ghcr.io/ruinivist/go-token-mediator:main
sudo env MEDIATOR_IMAGE="$MEDIATOR_IMAGE" docker compose ps
sudo env MEDIATOR_IMAGE="$MEDIATOR_IMAGE" docker compose logs --tail=100 mediator
curl -i https://auth.example.com/health
```

The health endpoint returns `200` and `{"status":"ok"}` when the HTTP server answers. It does not check provider availability. Then test a complete browser login from the frontend and confirm the callback returns to `/oauth/complete`.

### Troubleshooting responses

| Status | Check |
| --- | --- |
| `400` | Browser `POST`s return `invalid_request` if `Content-Type: application/json` is missing or wrong, or the body is missing, invalid, or not `{}`. A callback may also have invalid state, a provider denial, or no code. Start a new login; authorization codes cannot be reused. |
| `403` | Check that the browser's `Origin` exactly matches `frontend_origin_url` and that the POST includes `X-OAuth-Bridge: 1`. |
| `401` | The session or provider connection is missing or expired. Connect that provider again. |
| `429` | OAuth requests share a per-IP fixed one-minute limit, and a full session store also rejects new sessions. For `rate_limited`, use `Retry-After` when present. |
| `502` | A provider rejected the exchange or returned an invalid response. Compare the provider's registered callback URL with its configured `redirect_url`; they must match exactly. Also check credentials, scopes, and provider status. |
| `503` | Check the container logs and whether Docker can use the managed `sessions` volume. |
| `504` | The provider request timed out. Check network and provider status. |

For the session cookie to reach the mediator, both sites need HTTPS under the same registrable parent domain, and browser requests to the mediator must use `credentials: "include"`.

Do not blindly retry an authorization exchange or refresh. Codes are single-use, and a provider may rotate a refresh token before a request fails. An interrupted refresh or failed final write may require reconnecting that provider.

Never log or share provider tokens, client credentials, session cookies, authorization codes, or state. Check that Caddy request logs do not include callback query strings.

### Upgrade the container

Pull the current `main` image and recreate the service:

```sh
export MEDIATOR_IMAGE=ghcr.io/ruinivist/go-token-mediator:main
sudo docker pull ghcr.io/ruinivist/go-token-mediator:main
sudo env MEDIATOR_IMAGE="$MEDIATOR_IMAGE" docker compose up -d
```

Keep the managed `sessions` volume when replacing or upgrading the container. Deleting it removes sessions and provider connections; do not run `docker compose down -v` unless you intend to remove them.
