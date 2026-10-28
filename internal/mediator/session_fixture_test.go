// SQL-backed fixtures prepare sessions through real authorization transactions.
// Browser and provider tests share these fixtures without the archived store API.
package mediator

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"token-mediator/internal/session"
)

// ---------- Fixtures ----------

func newTestStore(t *testing.T, limit int, lifetime time.Duration) *session.Store {
	t.Helper()
	store, err := session.Open(t.Context(), filepath.Join(t.TempDir(), "sessions.db"), lifetime, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func authorize(t *testing.T, store *session.Store, cookie session.ID, connections ...session.Connection) session.BrowserSession {
	t.Helper()
	var browser session.BrowserSession
	for _, connection := range connections {
		var err error
		browser, err = store.BeginAuth(t.Context(), cookie, session.PendingAuth{Provider: connection.Provider, State: "fixture", PKCEVerifier: "verifier"})
		if err != nil {
			t.Fatal(err)
		}
		_, handle, err := store.ConsumeAuth(t.Context(), browser.ID, connection.Provider, "fixture")
		if err != nil {
			t.Fatal(err)
		}
		browser, err = store.CompleteAuth(t.Context(), handle, connection)
		if err != nil {
			t.Fatal(err)
		}
		cookie = browser.ID
	}
	return browser
}

// expiredSession seeds a deadline before opening the store used by HTTP tests.
// This avoids clock sleeps and external inspection of an owned database.
func expiredSession(t *testing.T) (*session.Store, session.BrowserSession) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "expired.db")
	store, err := session.Open(t.Context(), path, time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	browser := authorize(t, store, "", session.Connection{Provider: "mock", AccessToken: "expired-session"})
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), "UPDATE sessions SET expires_at=0"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = session.Open(t.Context(), path, time.Hour, 1000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store, browser
}
