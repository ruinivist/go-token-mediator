package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// ==== models ====

type SessionId string

// global session state for all users
type SessionStore struct {
	mtx      sync.RWMutex
	sessions map[SessionId]*Session
}

// main state for per user session details
type Session struct {
	ID          SessionId
	ExpiresAt   time.Time
	PendingAuth *PendingAuth
	Connections map[string]*Connection // provider -> connection
}

// latest oauth flow started for a session, valid for 10 mins
type PendingAuth struct {
	Provider     string
	State        string    // 32 bytes, echoed back
	PKCEVerifier string    // we send this to prove hash was by us
	CreatedAt    time.Time // reject if more than 10 mins
}

// note: token scheme is always bearer, assumed

// per provider, holds the tokens, scopes and expiry info
type Connection struct {
	Provider     string
	AccessToken  string
	RefreshToken string
	// in case we got denied, store from response what scoped
	// were actually allowed
	Scopes    string
	ExpiresAt time.Time
}

// ==== Session store usage function

// Make a new session store, expected to be used as a singleton
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[SessionId]*Session),
	}
}

// Add a new session with certain lifetime
func (s *SessionStore) Create(lifetime time.Duration) (*Session, error) {
	id, err := generateRandomString(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:          SessionId(id),
		ExpiresAt:   time.Now().Add(lifetime),
		Connections: make(map[string]*Connection),
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.sessions[session.ID] = session
	return session, nil
}

// get session details based on session id
func (s *SessionStore) Get(id SessionId) (*Session, bool) {
	// RWMutex is writer biased
	// "R"Lock so concurrent reads can work
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	sess, ok := s.sessions[id]
	if !ok {
		return nil, false
	}

	// check if expired
	if time.Now().After(sess.ExpiresAt) {
		return nil, false
	}

	return sess, true
}

// background worker for periodic cleanup of expired sessions
func (s *SessionStore) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.cleanupExpired()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// for all session, remove ones which are expired
func (s *SessionStore) cleanupExpired() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			// this delete while iteration is perfectly valid in go, unlike
			// some other langs
			delete(s.sessions, id)
		}
	}
}

// logout by session id
func (s *SessionStore) Delete(id SessionId) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	delete(s.sessions, id)
}

// ==== helper functions ====

// base64 url encoded string of nBytes bytes
func generateRandomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes, err = %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(b)
	return encoded, nil
}
