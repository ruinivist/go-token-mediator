# Token mediator breakdown

Read the [full architecture note](architecture.md) first. This guide builds the design by responsibility; the full note contains setup, complete sequences, concurrency details, and failure handling.

| Part | Adds |
| --- | --- |
| 1. Session ownership | A place for one browser's pending authorization and provider connections. |
| 2. Authorization | A validated, single-use path from browser approval to a saved connection. |
| 3. Token retrieval | Cached access tokens and one shared refresh per session/provider. |

Each diagram shows selected members. `+` means exported; `~` means package-scoped. State lives in one Go process.

## 1. Give session state one owner

![Focused UML: store and session-owned data](architecture-session-core.svg)

Start with `Store`: a map keyed by opaque `ID`, a capacity limit, and an `RWMutex`. A `session` holds its original deadline, one optional `PendingAuth`, and a map of `Connection` records keyed by provider.

`GetOrCreate` reuses an active session or creates one. `GetConnection` returns a copy. `Delete` removes the whole session. Cleanup periodically removes expired records; expiry checks already reject them before cleanup runs.

Keep the records behind store methods. This gives later operations one place to validate and change related state under a lock. It also keeps capacity and absolute expiry independent of browser activity.

## 2. Turn browser approval into a connection

![Focused UML: authorization responsibilities and atomic operations](architecture-auth-core.svg)

Add `Server` to coordinate HTTP and `ProviderConfig` to build the provider URL and exchange the code. Reuse the store for the attempt and its result.

1. After browser POST checks, `SetPendingAuth` records the provider, random state, verifier, and start time. The browser receives the authorization URL with the verifier's challenge.
2. At callback, `ConsumePendingAuth` validates the cookie session, provider, state, and attempt age, then removes the attempt under the same lock. Reject invalid attempts before contacting the provider.
3. Exchange the code outside the lock. On success, `CompleteAuth` saves the connection and rotates the session ID atomically, preserving the original deadline and other connections.

Only one pending attempt exists per session. A consumed attempt stays consumed if the provider call fails. A session deleted or expired during the call cannot be completed.

## 3. Return tokens without duplicating refresh work

![Focused UML: callback policy and shared connection update](architecture-refresh-core.svg)

The token route needs a current access token. Keep the OAuth refresh policy in the handler's callback; add `UpdateConnection` and the per-provider `connectionUpdate` records to coordinate access to stored state.

1. Under the store lock, find the connection and register an update, or join an existing one. An update has a completion channel and shared error.
2. Release the lock and run the callback on a connection copy. Return cached credentials when suitable; refresh when the known access deadline is within two minutes and a usable refresh token exists.
3. Reacquire the lock. Confirm session membership, expiry, and original connection identity before storing or deleting the result. Close the completion channel after publishing it.
4. Waiters read the current connection or shared error. Each waiter can cancel its own wait; the initiating request's context controls the provider call.

The callback returns a connection pointer to retain or replace credentials, or `nil` to delete them, including on error. This matters when refresh-token consumption is uncertain: retaining an old rotating token could reuse credentials the provider has already consumed. Logout and reconnect must also prevent a late result from restoring old state.
