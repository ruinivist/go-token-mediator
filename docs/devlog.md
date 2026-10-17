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

## session model - what do we store?

Reference for response: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

GH supports both expiring and non-expiring models.
A non-expiring response.

```json
{
  "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
  "token_type": "bearer",
  "scope": "repo,gist"
}
```

Expiring

```json
{
  "access_token": "gho_16C7e42F292c6912E7710c838347Ae178B4a",
  "token_type": "bearer",
  "scope": "repo,gist",
  "expires_in": 28800,
  "refresh_token": "ghr_1B4a2e77838347a7E420ce178F2E7c6912...",
  "refresh_token_expires_in": 15897600
}
```

Error ( with 200 OK )

```json
{
  "error": "bad_verification_code",
  "error_description": "The code passed is incorrect or has expired.",
  "error_uri": "https://docs.github.com/..."
}
```

To handle both we need atleast a common model as "ProviderTokenResponse"
that handles both expiring and non-expiring in one.

Ofc for the client side, session state, another model is needed too.

Let's start in order. At the first /oauth/provider/start,
I need to send back the provider oauth url build in full.
So state, code_challenege and code_challenge_method, a list of scopes,
response_type=code ( fixed ), client id and redirect uri.

All 7 are standard in the spec.

Why the redirect uri? A provider still checks, does not trust blindly. This is
just to filter in case provider allows for multiple redirect uris to be
registered ( an app can have an app specific one ).

But not all of this needs to be maintained forever. A lot many are straight
from the config or fixed for our model

All we need would be 4 models.

- a map of "session id" strings -> Sessions
- Session is created at start and stored pending auth state ( latest )
  and list of connections
- connections is just the actual tokens / refresh token etc

> above was primarily done in `session_store.go`, basic crud and models + cleanup worker for expired tokens

## http server

just adding a health endpoint for now

## `oauth/{provider}/start`

for state we can re-use the same string generation as it's for session id.
so just pkce needs to be implemented along with the api server,
and that is just hashing my random secret to get code challenge.

## `oauth/{provider}/callback`

Gh would redirect back with a code and state to my backend ( <- is partly correct ). This is what
the full flow looks like, I was misunderstanding redirects.

1. GitHub -> Browser: "Go to http://mybackend:8080/oauth/github/callback?code=C" (302)

2. Browser -> Go: GET /oauth/github/callback?code=C

3. Go -> GitHub API: POST /login/oauth/access_token (Go exchanges code for tokens)
   [Takes ~50ms]

4. GitHub -> Go: Here are your access_token and refresh_token!
   [Go saves tokens into session memory]

5. Go -> Browser: "All done! Now go to http://localhost:3000/completion" (302)
   (Go finally answers the waiting browser from step 2)

6. Browser -> Frontend: Browser loads http://localhost:3000/completion

Why wait before redirecting to completion? technically you could fetch the access tokens in
parallel but this will needlessly introduce a race condition for no real gain.

### how to test with a locally mocked server?

go has `httptest`, now that we are talking to github endpoint, it's good
from a testing and even for dev to have a test server that does acts as
github for me.

A quick guide of httptest, it makes a server that lives just for the test.
Idea being that it's for mocking outgoing requests to other external apis.
Note that recorder is for incoming requests to my endpoints and is in memory
while an httptest server would make an actual local server.

---

I had been consulting the RFC on this more and more, a well written one which this is, really
has everything define explicitly, have also put in comments the relevant sections as and when
I encounter those or had to refer RFC.

## Refactoring session to internal

While implementing I found myself using the sessions internal map that should be read under a lock
multiple times, not to mention that I was retuning pointers to those internal session structs.
I wanted to make the map private and then stop returning pointers and instead switch to all read
writes going via the session store using session id instead so that there is never a race error.

## Mocking an OAuth server to running tests on flows

I wasn't very keen on writign it myself so let codex handle it.
The mock_test makes a mock oauth server that is very much bound to a local port so it's almost a real thing,
and and the flow test just simulates different actions

# Preflight and how browser and server communicate as trusted parties in the world of arbitary code

what is a preflight
when is it triggered
can scritp spoof origin etc
practice of setting custom headers
implication if I do no set a customer header like X-OAuth-Bridge?
is all this hjeader doing a forcing and protection against generic attacks
what does the server need to ENSURE that it's doing it's part in the communication safely

Update: I wrote this all in learning-security

## A little of a refactor.

I made an `internal/mediator` boundary as well, point being it'll allow to
hide the internals from startup code.

## `oauth/{provider}/token`

I'm skipping refesh for now but otherwise it's straigthforward.
Skipping auto-refresh handling. If there is an expiry it sends it back. We also need to be handling OPTIONS requests, that is pending still.

This is the point where I started to let codex do some of the impl, it's useful to remind me of cases that I could not have caught.
For example, the read timeout for decoding json bodies, could've been a DOS if left unchecked.

## Same site modes

We set the same site mode in `setSessionCookie` in helpers. This table explains what is allowed under lax.

| Frontend → mediator                                      | Relationship                 | Current `SameSite=Lax` cookie     |
| -------------------------------------------------------- | ---------------------------- | --------------------------------- |
| `http://localhost:3000` → `http://localhost:8080`        | Different origins, same site | Compatible                        |
| `https://app.example.com` → `https://auth.example.com`   | Different origins, same site | Compatible                        |
| `https://app.example.com` → `https://mediator.other.com` | Different sites              | Blocked on frontend `fetch` calls |

## Why is token endpoint a POST with `{}` body

A get does not make sense as the verb is read but here we are making changes to the server state as well ( refresh/rotate if close to expiry ).

## Adding a refresh

choices

- done if close to expiry ( 2 min )
- provider responses capped to 64kib
- no retries

The way it works it that on /token request we check if refresh needed ( <2 mins to expiry ). If needed, then check for in flight updates to the same id to avoid making another one. Then if none exists, make a refresh call and return updated.

## Problem of double refresh

3 requests: A, B, C.

A is first and B waits for A's refresh to be done.
C occurs after A's refresh is done but before B resumes.

What happens is that A is finished nicely so clears markers, B is signalled but hasn't gotten CPU yet.
C arrives and sees no marker and refreshes ( this is assuming tokens are TOO short lived so not a real problem, we'll
anyways be refreshing on each request ).
C succeeds, and now B wakes up, sees token #1 ( it was passed by A ) when stored is different and fails.
The fix is just to signal B and let it read from store.
