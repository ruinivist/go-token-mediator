# go-token-mediator

Lightest token mediator

Read the [architecture notes](docs/architecture.md) for setup, UML, and design guidance, or the [breakdown](docs/architecture-breakdown.md) for incremental recall.

The backend keeps client secrets and refresh tokens private. The frontend obtains
access tokens from the mediator and calls provider APIs directly.

Sessions persist in SQLite through the pure Go `modernc.org/sqlite` driver.
Set the required `database_path` in your configuration; the example uses
`./data/sessions.db`, relative to the working directory. One process owns the
file exclusively. New directories use `0700` and the database uses `0600`.

The first deployment starts empty and requires reconnection. Later committed
sessions survive restarts. An interrupted refresh requires reconnection for
that provider. Database files and backups contain sensitive credentials.

Configuration requires a positive `session_limit`; the example sets it to `1000`.
At the limit, new sessions receive HTTP `429` with `session_limit_reached`.
Existing sessions keep working and are never evicted. Logout frees a slot immediately;
expired sessions free slots when the periodic cleanup runs (every 10 minutes).

Reference:
[IETF token-mediating backend guidance](https://www.ietf.org/ietf-ftp/rfc/rfc10017.html#section-6.2).
