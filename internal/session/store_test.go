// These tests verify session ownership, expiry, and synchronization.
// They exercise the store used by the HTTP OAuth flow.
package session

import (
	"encoding/base64"
	"sync"
	"testing"
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

func TestStore_InactiveSessions(t *testing.T) {
	store := NewStore()
	expiredID, err := store.Create(-time.Second)
	if err != nil {
		t.Fatal(err)
	}
	deletedID, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store.Delete(deletedID)
	pending := PendingAuth{Provider: "github", State: "state", CreatedAt: time.Now()}
	connection := Connection{Provider: "github", AccessToken: "token"}
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
