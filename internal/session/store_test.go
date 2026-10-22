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
	store := NewStore(1000)

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

func TestStore_SessionLimit(t *testing.T) {
	store := NewStore(1)
	id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookieID := range []ID{"", "unknown"} {
		if _, _, err := store.GetOrCreate(cookieID, time.Hour); !errors.Is(err, ErrSessionLimit) {
			t.Fatalf("create at capacity: error = %v", err)
		}
	}
	if reused, created, err := store.GetOrCreate(id, time.Hour); err != nil || created || reused != id {
		t.Fatal("could not reuse existing session at capacity")
	}
	newID, _, err := store.CompleteAuth(id, Connection{Provider: "mock", AccessToken: "token"})
	if err != nil || !store.Has(newID) {
		t.Fatal("could not complete authorization at capacity")
	}
	if _, err := store.Create(time.Hour); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("rotation changed capacity: error = %v", err)
	}
	store.Delete(newID)
	if _, err := store.Create(-time.Second); err != nil {
		t.Fatalf("logout did not free capacity: %v", err)
	}
	store.cleanupExpired()
	if _, err := store.Create(time.Hour); err != nil {
		t.Fatalf("cleanup did not free capacity: %v", err)
	}
}

func TestStore_ConcurrentSessionLimit(t *testing.T) {
	const limit, requests = 4, 32
	store := NewStore(limit)
	results := make(chan error, requests)
	var workers sync.WaitGroup
	for range requests {
		workers.Go(func() {
			_, err := store.Create(time.Hour)
			results <- err
		})
	}
	workers.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, ErrSessionLimit) {
			t.Fatal(err)
		}
	}
	if created != limit || len(store.sessions) != limit {
		t.Fatalf("created %d sessions, stored %d, limit %d", created, len(store.sessions), limit)
	}
}

func TestStore_Cleanup(t *testing.T) {
	store := NewStore(1000)

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
	store := NewStore(1000)

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

func TestStore_CompleteAuth(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		store := NewStore(1000)
		id, err := store.Create(time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		deadline, _ := store.ExpiresAt(id)
		other := Connection{Provider: "other", AccessToken: "unrelated"}
		if !store.SaveConnection(id, other) {
			t.Fatal("could not save unrelated connection")
		}
		time.Sleep(5 * time.Minute)
		connection := Connection{Provider: "mock", AccessToken: "authorized", RefreshToken: "refresh"}
		newID, expiresAt, err := store.CompleteAuth(id, connection)
		if err != nil || newID == "" || newID == id || !expiresAt.Equal(deadline) {
			t.Fatalf("completion = %q, %v, %v", newID, expiresAt, err)
		}
		if store.Has(id) {
			t.Fatal("old session ID is still active")
		}
		for _, want := range []Connection{connection, other} {
			if got, ok := store.GetConnection(newID, want.Provider); !ok || got != want {
				t.Fatalf("connection = %+v, want %+v", got, want)
			}
		}
		if after, ok := store.ExpiresAt(newID); !ok || !after.Equal(deadline) {
			t.Fatal("completion changed the stored deadline")
		}
		if _, _, err := store.CompleteAuth(id, connection); !errors.Is(err, ErrNoConnection) {
			t.Fatal("completion accepted the old ID")
		}
	})
}

func TestStore_CompleteAuthRejectsInactiveSessions(t *testing.T) {
	for _, action := range []string{"missing", "expired", "deleted"} {
		t.Run(action, func(t *testing.T) {
			store := NewStore(1000)
			id := ID("unknown")
			if action != "missing" {
				lifetime := time.Hour
				if action == "expired" {
					lifetime = -time.Second
				}
				var err error
				id, err = store.Create(lifetime)
				if err != nil {
					t.Fatal(err)
				}
				if action == "deleted" {
					store.Delete(id)
				}
			}
			newID, expiry, err := store.CompleteAuth(id, Connection{Provider: "mock", AccessToken: "new"})
			if !errors.Is(err, ErrNoConnection) || newID != "" || !expiry.IsZero() {
				t.Fatalf("completion = %q, %v, %v", newID, expiry, err)
			}
		})
	}
}

func TestStore_OAuthStateTransitions(t *testing.T) {
	store := NewStore(1000)
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
	store := NewStore(1000)
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
	store := NewStore(1000)
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
	store := NewStore(1000)
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
	store := NewStore(1000)
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
			store := NewStore(1000)
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
				store := NewStore(1000)
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

func TestStore_UpdateConnectionFollowsAuthCompletion(t *testing.T) {
	for _, action := range []string{"refresh", "rejected", "delete", "expire", "reconnect"} {
		t.Run(action, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := NewStore(1000)
				id, err := store.Create(time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				if !store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "old", RefreshToken: "spent"}) {
					t.Fatal("could not prepare connection")
				}
				release := make(chan struct{})
				oldResult := make(chan error, 1)
				calls := 0
				update := func(conn Connection) (*Connection, error) {
					calls++
					<-release
					if action == "rejected" {
						return nil, ErrNoConnection
					}
					conn.AccessToken = "fresh"
					conn.RefreshToken = "replacement"
					return &conn, nil
				}
				go func() {
					_, err := store.UpdateConnection(t.Context(), id, "mock", update)
					oldResult <- err
				}()
				synctest.Wait()
				newID, _, err := store.CompleteAuth(id, Connection{Provider: "other", AccessToken: "authorized"})
				if err != nil {
					t.Fatal(err)
				}
				var waiter sync.WaitGroup
				waiter.Go(func() {
					conn, err := store.UpdateConnection(t.Context(), newID, "mock", update)
					if action == "refresh" {
						if err != nil || conn.AccessToken != "fresh" || conn.RefreshToken != "replacement" {
							t.Errorf("new-ID waiter = %+v, %v", conn, err)
						}
					} else if !errors.Is(err, ErrNoConnection) {
						t.Errorf("new-ID waiter error = %v, want ErrNoConnection", err)
					}
				})
				synctest.Wait()
				switch action {
				case "delete":
					store.Delete(newID)
				case "expire":
					time.Sleep(2 * time.Minute)
				case "reconnect":
					newID, _, err = store.CompleteAuth(newID, Connection{Provider: "mock", AccessToken: "reconnected"})
					if err != nil {
						t.Fatal(err)
					}
				}
				close(release)
				if err := <-oldResult; !errors.Is(err, ErrNoConnection) {
					t.Fatalf("old-ID request error = %v, want ErrNoConnection", err)
				}
				waiter.Wait()
				if calls != 1 {
					t.Fatalf("refresh calls = %d, want 1", calls)
				}
				conn, ok := store.GetConnection(newID, "mock")
				switch action {
				case "refresh":
					if !ok || conn.AccessToken != "fresh" || conn.RefreshToken != "replacement" {
						t.Fatal("rotation lost refreshed credentials")
					}
				case "reconnect":
					if !ok || conn.AccessToken != "reconnected" {
						t.Fatal("refresh overwrote the newer connection")
					}
				default:
					if ok {
						t.Fatal("refresh retained a rejected or inactive connection")
					}
				}
			})
		})
	}
}

func TestStore_UpdateConnectionDelayedWaiterReadsLatest(t *testing.T) {
	store := NewStore(1000)
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

func TestStore_SessionLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{time.Hour, 400 * 24 * time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				store := NewStore(1000)
				now := time.Now()
				id, err := store.Create(lifetime)
				if err != nil {
					t.Fatal(err)
				}
				deadline, ok := store.ExpiresAt(id)
				if !ok || !deadline.Equal(now.Add(lifetime)) {
					t.Fatalf("unexpected deadline: %v", deadline)
				}
				if reused, created, err := store.GetOrCreate(id, 2*time.Hour); err != nil || created || reused != id {
					t.Fatal("failed to reuse active session")
				}
				pending := PendingAuth{Provider: "mock", State: "state", CreatedAt: time.Now()}
				if !store.SetPendingAuth(id, pending) || !store.SaveConnection(id, Connection{Provider: "mock", AccessToken: "old"}) {
					t.Fatal("could not prepare active session")
				}
				if _, err := store.UpdateConnection(t.Context(), id, "mock", func(conn Connection) (*Connection, error) {
					conn.AccessToken = "new"
					return &conn, nil
				}); err != nil {
					t.Fatal(err)
				}
				if after, ok := store.ExpiresAt(id); !ok || !after.Equal(deadline) {
					t.Fatal("session reuse or connection update changed deadline")
				}
				time.Sleep(11 * time.Minute)
				if _, ok := store.ConsumePendingAuth(id, "mock", "state"); ok {
					t.Fatal("accepted expired authorization attempt")
				}
				pending.CreatedAt = time.Now()
				if !store.SetPendingAuth(id, pending) {
					t.Fatal("could not replace pending attempt")
				}
				if _, ok := store.ConsumePendingAuth(id, "mock", "state"); !ok {
					t.Fatal("rejected live authorization attempt")
				}
				time.Sleep(lifetime - 11*time.Minute)
				if store.Has(id) {
					t.Fatal("incorrect session validity at finite deadline")
				}
				if _, ok := store.ExpiresAt(id); ok {
					t.Fatal("incorrect deadline lookup")
				}
				if _, ok := store.GetConnection(id, "mock"); ok {
					t.Fatal("incorrect connection access")
				}
				if store.SetPendingAuth(id, pending) || store.SaveConnection(id, Connection{Provider: "mock"}) {
					t.Fatal("incorrect session write access")
				}
				_, err = store.UpdateConnection(t.Context(), id, "mock", func(conn Connection) (*Connection, error) { return &conn, nil })
				if !errors.Is(err, ErrNoConnection) {
					t.Fatalf("unexpected update error: %v", err)
				}
				store.cleanupExpired()
				if _, exists := store.sessions[id]; exists {
					t.Fatal("incorrect cleanup result")
				}
				store.Delete(id)
				if store.Has(id) {
					t.Fatal("session survived logout")
				}
			})
		})
	}
}
