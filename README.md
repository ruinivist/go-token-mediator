# go-token-mediator

Lightest token mediator
Some sites like Github do not support a client only OAuth path and force you to put a client credential
on the frontend, which is fine as NOT having to do that is not any more secure, browser is inherently less
secure than a mediating backned ( or a bff as the best case ).
Refresh tokens are also NOT SHARED which is the whole point of a mediator else it could just have been a
token exchange.

- sqlite ( as worse case they'll have to login again )

Configuration requires a positive `session_limit`; the example sets it to `1000`.
At the limit, new sessions receive HTTP `429` with `session_limit_reached`.
Existing sessions keep working and are never evicted. Logout frees a slot immediately;
expired sessions free slots when the periodic cleanup runs (every 10 minutes).

Reference:
[IETF token-mediating backend guidance](https://www.ietf.org/ietf-ftp/rfc/rfc10017.html#section-6.2).
