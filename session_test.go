package main

import (
	"testing"
	"time"
)

func TestSessionStore_CRUD(t *testing.T) {
	store := NewSessionStore()

	// create
	sess, err := store.Create(1 * time.Hour)
	if err != nil {
		t.Fatalf("failed to create session, err = %v", err)
	}

	// read
	read, ok := store.Get(sess.ID)
	if !ok || read.ID != sess.ID {
		t.Fatal("failed to retrieve stored session")
	}

	// delete
	store.Delete(sess.ID)
	if _, ok := store.Get(sess.ID); ok {
		t.Fatal("expected session to be deleted")
	}
}

func TestSessionStore_Cleanup(t *testing.T) {
	store := NewSessionStore()

	// create
	sess, err := store.Create(-1 * time.Second)
	if err != nil {
		t.Fatalf("failed to create session, err = %v", err)
	}

	// read rejected
	if _, ok := store.Get(sess.ID); ok {
		t.Fatalf("session should be expired but wasn't")
	}

	// sweep clean should delete
	store.cleanupExpired()
	store.mtx.RLock()
	defer store.mtx.RUnlock()

	_, exists := store._session[sess.ID]

	if exists {
		t.Fatalf("cleanup failed to delete expired session")
	}
}

func TestSessionStore_GetOrCreate(t *testing.T) {
	store := NewSessionStore()

	// 1. When empty/missing ID, creates new session
	sess1, created, err := store.GetOrCreate("", 1*time.Hour)
	if err != nil || !created || sess1 == nil {
		t.Fatalf("expected new session to be created")
	}

	// 2. When valid ID passed, returns existing session
	sess2, created, err := store.GetOrCreate(sess1.ID, 1*time.Hour)
	if err != nil || created || sess2.ID != sess1.ID {
		t.Fatalf("expected existing session to be returned without re-creating")
	}
}

func TestSessionStore_OAuthStateTransitions(t *testing.T) {
	store := NewSessionStore()
	sess, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	pending := PendingAuth{
		Provider:     "github",
		State:        "state",
		PKCEVerifier: "verifier",
		CreatedAt:    time.Now(),
	}
	if !store.SetPendingAuth(sess.ID, pending) {
		t.Fatal("failed to save pending auth")
	}
	if _, ok := store.ConsumePendingAuth(sess.ID, "github", "wrong-state"); ok {
		t.Fatal("consumed pending auth with wrong state")
	}
	got, ok := store.ConsumePendingAuth(sess.ID, "github", "state")
	if !ok || got.PKCEVerifier != pending.PKCEVerifier {
		t.Fatal("failed to consume valid pending auth")
	}
	if _, ok := store.ConsumePendingAuth(sess.ID, "github", "state"); ok {
		t.Fatal("consumed pending auth more than once")
	}

	connection := Connection{Provider: "github", AccessToken: "token"}
	if !store.SaveConnection(sess.ID, connection) {
		t.Fatal("failed to save connection")
	}
	if sess.Connections["github"].AccessToken != connection.AccessToken {
		t.Fatal("saved connection did not match")
	}
}
