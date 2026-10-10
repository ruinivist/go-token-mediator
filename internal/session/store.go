// Package session owns in-memory session state and its synchronization.
// The HTTP OAuth flow uses it to manage pending authorization and connections.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// ---------- Models ----------

type ID string

// global session state for all users
type Store struct {
	mtx      sync.RWMutex
	sessions map[ID]*session
}

// main state for per user session details
type session struct {
	expiresAt   time.Time
	pendingAuth *PendingAuth
	connections map[string]*Connection // provider -> connection
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

// ---------- Session access ----------

// Make a new session store, expected to be used as a singleton
func NewStore() *Store {
	return &Store{
		sessions: make(map[ID]*session),
	}
}

// Add a new session with certain lifetime
func (s *Store) Create(lifetime time.Duration) (ID, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes, err = %w", err)
	}
	id := ID(base64.RawURLEncoding.EncodeToString(b))

	sess := &session{
		expiresAt:   time.Now().Add(lifetime),
		connections: make(map[string]*Connection),
	}

	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.sessions[id] = sess
	return id, nil
}

// Has reports whether a session exists and has not expired.
func (s *Store) Has(id ID) bool {
	// RWMutex is writer biased
	// "R"Lock so concurrent reads can work
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	sess, ok := s.sessions[id]
	return ok && !time.Now().After(sess.expiresAt)
}

// GetConnection returns a detached connection value from an active session.
func (s *Store) GetConnection(id ID, provider string) (Connection, bool) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.expiresAt) {
		return Connection{}, false
	}
	connection, ok := sess.connections[provider]
	if !ok {
		return Connection{}, false
	}
	return *connection, true
}

// GetOrCreate returns an existing active session ID or creates a new one.
// The boolean reports true if a new session was created.
func (s *Store) GetOrCreate(id ID, lifetime time.Duration) (ID, bool, error) {
	if id != "" && s.Has(id) {
		return id, false, nil
	}

	newID, err := s.Create(lifetime)
	if err != nil {
		return "", false, err
	}
	return newID, true, nil
}

// logout by session id
func (s *Store) Delete(id ID) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	delete(s.sessions, id)
}

// ---------- OAuth state ----------

// SetPendingAuth replaces the session's pending OAuth flow.
func (s *Store) SetPendingAuth(id ID, pending PendingAuth) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.expiresAt) {
		return false
	}
	sess.pendingAuth = &pending
	return true
}

// ConsumePendingAuth validates and removes a pending OAuth flow atomically.
func (s *Store) ConsumePendingAuth(id ID, provider, state string) (*PendingAuth, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.expiresAt) || sess.pendingAuth == nil {
		return nil, false
	}

	pending := sess.pendingAuth
	if pending.Provider != provider || pending.State != state || time.Since(pending.CreatedAt) > 10*time.Minute {
		return nil, false
	}

	sess.pendingAuth = nil
	copy := *pending
	return &copy, true
}

// SaveConnection stores a provider connection in an active session.
func (s *Store) SaveConnection(id ID, connection Connection) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.expiresAt) {
		return false
	}
	sess.connections[connection.Provider] = &connection
	return true
}

// ---------- Cleanup ----------

// background worker for periodic cleanup of expired sessions
func (s *Store) StartCleanupWorker(ctx context.Context, interval time.Duration) {
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
func (s *Store) cleanupExpired() {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	now := time.Now()
	for id, sess := range s.sessions {
		if now.After(sess.expiresAt) {
			// this delete while iteration is perfectly valid in go, unlike
			// some other langs
			delete(s.sessions, id)
		}
	}
}
