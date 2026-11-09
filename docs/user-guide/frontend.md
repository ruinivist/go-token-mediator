# Connect the frontend

## Step 5: start login and use tokens

Browser requests to the mediator need the exact configured origin, cookies, and the empty JSON body. The `X-OAuth-Bridge` header is required on every browser `POST`.

This small helper sends the required headers and reports a status without assuming every error response is JSON:

```js
const mediator = "https://auth.example.com";

async function mediatorPost(path) {
  const response = await fetch(`${mediator}${path}`, {
    method: "POST",
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "X-OAuth-Bridge": "1",
    },
    body: "{}",
  });

  if (!response.ok) {
    throw new Error(`Mediator request failed with HTTP ${response.status}`);
  }
  return response;
}
```

These examples use GitHub as the OAuth provider. Start authorization from your connect button:

```js
async function connect() {
  const response = await mediatorPost("/oauth/github/start");
  const { authorization_url } = await response.json();
  location.assign(authorization_url);
}
```

On `/oauth/complete`, request the GitHub access token:

```js
const response = await mediatorPost("/oauth/github/token");
const { access_token } = await response.json();
```

Use the access token for a direct request to GitHub's API:

```js
const apiResponse = await fetch("https://api.github.com/user", {
  headers: { Authorization: `Bearer ${access_token}` },
});
if (!apiResponse.ok) {
  throw new Error(`Provider request failed with HTTP ${apiResponse.status}`);
}
```

The token endpoint may also return `expires_in` in seconds and `scope`; call it again when you need a current token. The mediator can refresh only when the provider issued a refresh token. Do not include mediator cookies on provider API calls. Keep access tokens in memory and out of browser storage and logs.

Log out by posting to `/session/logout`. It returns `204 No Content`; do not parse a response body:

```js
await mediatorPost("/session/logout");
```

Logout removes the mediator's local session and all provider connections for it. It does not revoke tokens at GitHub.

Continue with [operations](operations.md).
