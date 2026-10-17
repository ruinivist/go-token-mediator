// These tests verify session ownership, expiry, and synchronization.
// They exercise the store used by the HTTP OAuth flow.
package session

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// ---------- Session lifecycle ----------

func TestStore_CRUD(t *testing.T) {
	store := NewStore()

	// create
	id, err := store.Create(1 * time.Hour)
	if err != nil {
		t.Fatalf("failed to create session, err = %v", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(string(id))
	if err != nil || len(decoded) != 32 {
		t.Fatal("expected a base64url session ID containing 32 random bytes")
	}

	// read
	if !store.Has(id) {
		t.Fatal("failed to retrieve stored session")
	}

	// delete
	store.Delete(id)
	if store.Has(id) {
		t.Fatal("expected session to be deleted")
	}
}

func TestStore_Cleanup(t *testing.T) {
	store := NewStore()

	// create
	id, err := store.Create(-1 * time.Second)
	if err != nil {
		t.Fatalf("failed to create session, err = %v", err)
	}

	// read rejected
	if store.Has(id) {
		t.Fatalf("session should be expired but wasn't")
	}
	activeID, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// sweep clean should delete
	store.cleanupExpired()
	store.mtx.RLock()
	defer store.mtx.RUnlock()

	_, exists := store.sessions[id]

	if exists {
		t.Fatalf("cleanup failed to delete expired session")
	}
	if _, exists := store.sessions[activeID]; !exists {
		t.Fatal("cleanup deleted an active session")
	}
}

func TestStore_GetOrCreate(t *testing.T) {
	store := NewStore()

	// 1. When empty/missing ID, creates new session
	id1, created, err := store.GetOrCreate("", 1*time.Hour)
	if err != nil || !created || id1 == "" || !store.Has(id1) {
		t.Fatalf("expected new session to be created")
	}

	// 2. When valid ID passed, returns existing session
	id2, created, err := store.GetOrCreate(id1, 1*time.Hour)
	if err != nil || created || id2 != id1 {
		t.Fatalf("expected existing session to be returned without re-creating")
	}

	expiredID, err := store.Create(-time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []ID{"missing", expiredID} {
		newID, created, err := store.GetOrCreate(id, time.Hour)
		if err != nil || !created || newID == id || !store.Has(newID) {
			t.Fatalf("expected a new active session for %q", id)
		}
	}
}

// ---------- OAuth state ----------

func TestStore_OAuthStateTransitions(t *testing.T) {
	store := NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pending := PendingAuth{
		Provider:     "github",
		State:        "state",
		PKCEVerifier: "verifier",
		CreatedAt:    time.Now(),
	}
	if !store.SetPendingAuth(id, pending) {
		t.Fatal("failed to save pending auth")
	}
	pending.PKCEVerifier = "changed-after-save"
	if _, ok := store.ConsumePendingAuth(id, "other-provider", "state"); ok {
		t.Fatal("consumed pending auth with wrong provider")
	}
	if _, ok := store.ConsumePendingAuth(id, "github", "wrong-state"); ok {
		t.Fatal("consumed pending auth with wrong state")
	}
	got, ok := store.ConsumePendingAuth(id, "github", "state")
	if !ok || got.PKCEVerifier != "verifier" {
		t.Fatal("failed to consume valid pending auth")
	}
	if _, ok := store.ConsumePendingAuth(id, "github", "state"); ok {
		t.Fatal("consumed pending auth more than once")
	}

	pending.CreatedAt = time.Now().Add(-11 * time.Minute)
	if !store.SetPendingAuth(id, pending) {
		t.Fatal("failed to save old pending auth")
	}
	if _, ok := store.ConsumePendingAuth(id, "github", "state"); ok {
		t.Fatal("consumed expired pending auth")
	}
	pending.State = "new-state"
	pending.CreatedAt = time.Now()
	if !store.SetPendingAuth(id, pending) {
		t.Fatal("failed to replace pending auth")
	}
	if _, ok := store.ConsumePendingAuth(id, "github", "state"); ok {
		t.Fatal("consumed replaced pending auth")
	}
	if _, ok := store.ConsumePendingAuth(id, "github", "new-state"); !ok {
		t.Fatal("failed to consume replacement pending auth")
	}
}

func TestStore_ConnectionCopies(t *testing.T) {
	store := NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	connection := Connection{Provider: "github", AccessToken: "token"}
	if !store.SaveConnection(id, connection) {
		t.Fatal("failed to save connection")
	}
	connection.AccessToken = "changed-after-save"
	got, ok := store.GetConnection(id, "github")
	if !ok || got.AccessToken != "token" {
		t.Fatal("saved connection did not match")
	}
	got.AccessToken = "changed-after-read"
	again, ok := store.GetConnection(id, "github")
	if !ok || again.AccessToken != "token" {
		t.Fatal("changing the returned connection changed stored state")
	}
	if _, ok := store.GetConnection(id, "missing"); ok {
		t.Fatal("retrieved an unknown connection")
	}
}

// Checks that inactive sessions reject reads and writes, even with a saved connection.
func TestStore_InactiveSessions(t *testing.T) {
	store := NewStore()
	expiredID, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	connection := Connection{Provider: "github", AccessToken: "token"}
	if !store.SaveConnection(expiredID, connection) {
		t.Fatal("failed to save connection before session expiry")
	}
	store.mtx.Lock()
	store.sessions[expiredID].expiresAt = time.Now().Add(-time.Second)
	store.mtx.Unlock()

	deletedID, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.Delete(deletedID)
	pending := PendingAuth{Provider: "github", State: "state", CreatedAt: time.Now()}
	for _, id := range []ID{"", "missing", expiredID, deletedID} {
		if store.Has(id) {
			t.Errorf("inactive session %q reported active", id)
		}
		if store.SetPendingAuth(id, pending) || store.SaveConnection(id, connection) {
			t.Errorf("modified inactive session %q", id)
		}
		if _, ok := store.ConsumePendingAuth(id, "github", "state"); ok {
			t.Errorf("consumed auth for inactive session %q", id)
		}
		if _, ok := store.GetConnection(id, "github"); ok {
			t.Errorf("retrieved connection for inactive session %q", id)
		}
	}
}

// ---------- Concurrent access ----------

func TestStore_ConcurrentAccess(t *testing.T) {
	store := NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				gotID, created, err := store.GetOrCreate(id, time.Hour)
				if err != nil || created || gotID != id {
					t.Error("failed to reuse active session")
					return
				}
				if !store.SaveConnection(id, Connection{Provider: "github", AccessToken: "token"}) {
					t.Error("failed to save connection")
					return
				}
				connection, ok := store.GetConnection(id, "github")
				if !ok || connection.AccessToken != "token" {
					t.Error("failed to read connection")
					return
				}
				connection.AccessToken = "local-copy"
				store.SetPendingAuth(id, PendingAuth{Provider: "github", State: "state", CreatedAt: time.Now()})
				store.ConsumePendingAuth(id, "github", "state")
				temporaryID, err := store.Create(-time.Second)
				if err != nil {
					t.Error(err)
					return
				}
				store.cleanupExpired()
				store.Delete(temporaryID)
			}
		})
	}
	wg.Wait()
}

func TestStore_ConcurrentConsumePendingAuth(t *testing.T) {
	store := NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !store.SetPendingAuth(id, PendingAuth{Provider: "github", State: "state", CreatedAt: time.Now()}) {
		t.Fatal("failed to save pending auth")
	}
	start := make(chan struct{})
	successes := make(chan bool, 16)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			<-start
			_, ok := store.ConsumePendingAuth(id, "github", "state")
			successes <- ok
		})
	}
	close(start)
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one successful consumer, got %d", count)
	}
}

// ---------- In-flight connection updates ----------

func TestStore_UpdateConnectionCoalesces(t *testing.T) {
	for _, fail := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			store := NewStore()
			id, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "old"})
			store.SaveConnection(id, Connection{Provider: "other", AccessToken: "unrelated"})
			otherID, err := store.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			store.SaveConnection(otherID, Connection{Provider: "mock", AccessToken: "other-session"})
			release := make(chan struct{})
			calls := 0
			upstreamErr := errors.New("upstream failure")
			update := func(conn Connection) (*Connection, error) {
				calls++
				<-release
				if fail {
					return nil, upstreamErr
				}
				conn.AccessToken = "new"
				return &conn, nil
			}
			var wg sync.WaitGroup
			for range 16 {
				wg.Go(func() {
					conn, err := store.UpdateConnection(t.Context(), id, "mock", update)
					if fail {
						if !errors.Is(err, upstreamErr) {
							t.Errorf("error = %v", err)
						}
					} else if err != nil || conn.AccessToken != "new" {
						t.Errorf("connection = %v, error = %v", conn, err)
					}
				})
			}
			synctest.Wait()
			if calls != 1 {
				t.Fatalf("updates = %d, want 1", calls)
			}
			// Other providers and sessions remain usable while the update blocks.
			for _, key := range []struct {
				id       ID
				provider string
			}{{id, "other"}, {otherID, "mock"}} {
				_, err := store.UpdateConnection(t.Context(), key.id, key.provider, func(c Connection) (*Connection, error) { return &c, nil })
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancelled := make(chan error, 1)
			go func() { _, err := store.UpdateConnection(ctx, id, "mock", update); cancelled <- err }()
			synctest.Wait()
			cancel()
			if err := <-cancelled; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			close(release)
			wg.Wait()
			if calls != 1 {
				t.Fatalf("updates = %d, want 1", calls)
			}
		})
	}
}

func TestStore_UpdateConnectionDiscardsStaleResults(t *testing.T) {
	for _, action := range []string{"delete", "expire", "reconnect"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := NewStore()
				id, err := store.Create(time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "old"})
				release := make(chan struct{})
				result := make(chan error, 1)
				go func() {
					_, err := store.UpdateConnection(t.Context(), id, "mock", func(c Connection) (*Connection, error) {
						<-release
						c.AccessToken = "stale"
						return &c, nil
					})
					result <- err
				}()
				synctest.Wait()
				switch action {
				case "delete":
					store.Delete(id)
				case "expire":
					time.Sleep(2 * time.Minute)
				case "reconnect":
					store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "reconnected"})
				}
				close(release)
				if err := <-result; !errors.Is(err, ErrNoConnection) {
					t.Fatal(err)
				}
				conn, ok := store.GetConnection(id, "mock")
				if action == "reconnect" {
					if !ok || conn.AccessToken != "reconnected" {
						t.Fatal("overwrote reconnect")
					}
				} else if ok {
					t.Fatal("restored inactive session")
				}
			})
		})
	}
}

func TestStore_UpdateConnectionDelayedWaiterReadsLatest(t *testing.T) {
	store := NewStore()
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "old"}) {
		t.Fatal("save connection failed")
	}

	started := make(chan struct{})
	release := make(chan struct{})
	completed := make(chan error, 1)
	go func() {
		_, err := store.UpdateConnection(t.Context(), id, "mock", func(c Connection) (*Connection, error) {
			close(started)
			<-release
			c.AccessToken = "first"
			c.ExpiresAt = time.Now().Add(time.Minute)
			return &c, nil
		})
		completed <- err
	}()
	<-started
	store.mtx.RLock()
	sess := store.sessions[id]
	flight := sess.updates["mock"]
	store.mtx.RUnlock()
	close(release)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}

	_, err = store.UpdateConnection(t.Context(), id, "mock", func(c Connection) (*Connection, error) {
		c.AccessToken = "second"
		return &c, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Resume the first refresh's waiter after the second refresh has finished.
	got, err := store.connectionUpdateResult(id, "mock", sess, flight)
	if err != nil || got.AccessToken != "second" {
		t.Fatalf("delayed waiter token = %q, error = %v; want second token", got.AccessToken, err)
	}
}
