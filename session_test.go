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

	_, exists := store.sessions[sess.ID]

	if exists {
		t.Fatalf("cleanup failed to delete expired session")
	}
}
