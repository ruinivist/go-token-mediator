package main

import (
	"context"
	"sync"
	"time"
)

// ==== models ====

type SessionId string

// global session state for all users
type SessionStore struct {
	mtx      sync.RWMutex
	_session map[SessionId]*Session
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
		_session: make(map[SessionId]*Session),
	}
}

// TODO: Move SessionStore into its own package to enforce access boundaries.
// TODO: Create, Get, and GetOrCreate return live *Session pointers that let callers bypass the store lock.
// Return IDs/existence results instead, and copy connection values under RLock when reads are needed.

// Add a new session with certain lifetime
func (s *SessionStore) Create(lifetime time.Duration) (*Session, error) {
	id, err := GenerateRandomString(32)
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

	s._session[session.ID] = session
	return session, nil
}

// get session details based on session id
func (s *SessionStore) Get(id SessionId) (*Session, bool) {
	// RWMutex is writer biased
	// "R"Lock so concurrent reads can work
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	sess, ok := s._session[id]
	if !ok {
		return nil, false
	}

	// check if expired
	if time.Now().After(sess.ExpiresAt) {
		return nil, false
	}

	return sess, true
}

// these funcs below are added to modify session store, it's easy to forget to do it under
// lock hence session store's internal map was makde private

// SetPendingAuth replaces the session's pending OAuth flow.
func (s *SessionStore) SetPendingAuth(id SessionId, pending PendingAuth) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s._session[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return false
	}
	sess.PendingAuth = &pending
	return true
}

// ConsumePendingAuth validates and removes a pending OAuth flow atomically.
func (s *SessionStore) ConsumePendingAuth(id SessionId, provider, state string) (*PendingAuth, bool) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s._session[id]
	if !ok || time.Now().After(sess.ExpiresAt) || sess.PendingAuth == nil {
		return nil, false
	}

	pending := sess.PendingAuth
	if pending.Provider != provider || pending.State != state || time.Since(pending.CreatedAt) > 10*time.Minute {
		return nil, false
	}

	sess.PendingAuth = nil
	copy := *pending
	return &copy, true
}

// SaveConnection stores a provider connection in an active session.
func (s *SessionStore) SaveConnection(id SessionId, connection Connection) bool {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	sess, ok := s._session[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		return false
	}
	sess.Connections[connection.Provider] = &connection
	return true
}

// GetOrCreate returns an existing active session or creates a new one.
// The boolean reports true if a new session was created.
func (s *SessionStore) GetOrCreate(id SessionId, lifetime time.Duration) (*Session, bool, error) {
	if id != "" {
		if sess, ok := s.Get(id); ok {
			return sess, false, nil
		}
	}

	newSess, err := s.Create(lifetime)
	if err != nil {
		return nil, false, err
	}
	return newSess, true, nil
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
	for id, sess := range s._session {
		if now.After(sess.ExpiresAt) {
			// this delete while iteration is perfectly valid in go, unlike
			// some other langs
			delete(s._session, id)
		}
	}
}

// logout by session id
func (s *SessionStore) Delete(id SessionId) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	delete(s._session, id)
}
