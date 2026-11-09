# go-token-mediator documentation

go-token-mediator is a small OAuth backend for browser applications. It keeps provider client secrets and refresh tokens on the server, then gives the frontend access tokens to call provider APIs directly.

- Stores OAuth sessions and provider connections in SQLite.
- Uses authorization code flow with PKCE and refreshes tokens on the backend when needed.
- Runs in a Linux container behind Caddy on one server, with the browser app hosted separately.

Start with the [prerequisites](user-guide/prerequisites.md), or read the [developer guide](arch/overview.md). The supported container setup uses rootful Docker, Caddy on the host, a local configuration file, and a Docker-managed SQLite volume.

## Documentation map

- [User guide](user-guide/prerequisites.md): current setup, configuration, deployment, frontend integration, and operations.
- [Architecture](arch/overview.md): component ownership, current flows, and implementation explanations.
- [Decisions to skip](decisions.md): intentional limits, not a feature backlog.
- [Archive](archive/devlog.md): historical notes, not current usage guidance or contracts.

`SUMMARY.md` is the mdBook navigation; this page is the documentation map. Use lowercase kebab-case filenames, except `README.md` and `AGENTS.md`.

Run `make docs` to build the book or `make docs-serve` to serve it locally.
