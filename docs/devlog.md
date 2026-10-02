# Devlog

## general idea

1. **`POST /oauth/github/start`**: Go creates the session, sets the `HttpOnly` cookie in the browser, and returns GitHub's login URL.
2. **User authorizes**: Browser navigates to GitHub.
3. **`GET /oauth/github/callback`**: GitHub redirects to Go. Go exchanges the code for tokens, saves them in memory, rotates the cookie, and `302` redirects the browser to `completion_url`. So one redirect to another redirect from my backend.
4. **`POST /oauth/github/token`**: Frontend JS calls Go with the cookie. Go returns the raw access token in JSON.
5. **Direct API calls**: Frontend JS uses the access token directly against `https://api.github.com/...`.
6. **`POST /session/logout`**: Go deletes the server session and clears the cookie.

We never send in refresh token at all else it defeats the whole purpose
of such a setup, you might as well put the client credential.

## making a good config

Often multiple providers are configured on the same site so we need to handle
multiple.

Common values

- port
- frontend origin ( why? for cors and csrf defense, my backend must verify
  origins )
- frontend completion url to redirect back to

Per provider

- client id
- client secret
- auth url
- token url
- callback url ( what the providers redirects to, my backend )
- scopes
