# Prerequisites

## Step 1: prepare the server

The examples use GitHub as the OAuth provider.

This guide uses one Arch Linux server with rootful Docker for the mediator and Caddy on the host. On other distributions, use the equivalent packages and service commands. The frontend must already be deployed separately at `https://app.example.com`; the mediator will use `https://auth.example.com`. Replace those example names with your own. Both sites need HTTPS and the same registrable parent domain so the browser can send the mediator's `SameSite=Lax` session cookie.

Before continuing:

- Point `auth.example.com` at the server and allow inbound TCP ports 80 and 443. Caddy uses them to obtain and renew certificates.
- Install Docker, Compose, Caddy, and Git from the Arch repositories:

  ```sh
  sudo pacman -Syu docker docker-compose caddy git
  ```

  Start the rootful Docker service:

  ```sh
  sudo systemctl enable --now docker
  ```

  Docker access grants root-equivalent control of the host. Use `sudo docker` commands; do not grant access to the Docker socket through a user group. The [Caddy package](https://caddyserver.com/docs/install#arch-linux-manjaro-parabola) includes its systemd service; the deployment step enables it.

- Clone the repository and enter its directory:

  ```sh
  git clone https://github.com/ruinivist/go-token-mediator.git "$HOME/token-mediator"
  cd "$HOME/token-mediator"
  ```

- Keep Caddy directly reachable from the internet. Do not put a CDN or another proxy in front of it; the service expects one client address from local Caddy.

The frontend completion page at `https://app.example.com/oauth/complete` is configured later. Continue with [OAuth app registration](oauth-apps.md).
