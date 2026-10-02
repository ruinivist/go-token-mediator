# go-token-mediator

Lightest token mediator
Some sites like Github do not support a client only OAuth path and force you to put a client credential
on the frontend, which is fine as NOT having to do that is not any more secure, browser is inherently less
secure than a mediating backned ( or a bff as the best case ).
Refresh tokens are also NOT SHARED which is the whole point of a mediator else it could just have been a
token exchange.

- sqlite ( as worse case they'll have to login again )

Reference:
[IETF token-mediating backend guidance](https://www.ietf.org/ietf-ftp/rfc/rfc10017.html#section-6.2).
