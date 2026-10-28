// Package session owns durable SQLite sessions and guarded credential writes.
// The mediator uses its transactions without holding them during provider calls.
package session

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"modernc.org/sqlite"
)

// ---------- Models ----------

type ID string

type BrowserSession struct {
	ID        ID
	ExpiresAt time.Time
}

type PendingAuth struct {
	Provider     string
	State        string
	PKCEVerifier string
}

// Connection is a detached set of bearer credentials; zero deadlines mean unknown.
// The mediator uses it for provider calls and browser access-token responses.
type Connection struct {
	Provider         string
	AccessToken      string
	RefreshToken     string
	Scopes           string
	ExpiresAt        time.Time
	RefreshExpiresAt time.Time
}

// AuthHandle binds a consumed authorization to its original cookie and provider.
// Only ConsumeAuth can create a usable handle for callback completion.
type AuthHandle struct {
	session  int64
	cookie   ID
	provider string
}

// ConnectionRef binds conditional writes to a stable session and row revision.
// LoadConnection returns it without exposing SQL identities.
type ConnectionRef struct {
	session  int64
	row      int64
	revision int64
	provider string
}

type RefreshClaim struct{ ref ConnectionRef }

type Store struct {
	db       *sql.DB
	lifetime time.Duration
	limit    int
	mu       sync.Mutex
	flights  map[refreshKey]*refreshFlight
}

var (
	ErrNoSession    = errors.New("no active session")
	ErrNoConnection = errors.New("no active provider connection")
	ErrInvalidAuth  = errors.New("invalid authorization")
	ErrSessionLimit = errors.New("session limit reached")
	ErrStale        = errors.New("stale connection reference")
	ErrRefreshing   = errors.New("connection refresh unfinished")
	ErrStorage      = errors.New("session storage unavailable")
)

// ---------- Database lifecycle ----------

var openMu sync.Mutex

var schema = []string{
	`CREATE TABLE sessions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 cookie TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL
)`,
	`CREATE TABLE pending_auth (
 session_id INTEGER PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 state TEXT NOT NULL,
 verifier TEXT NOT NULL,
 created_at INTEGER NOT NULL
)`,
	`CREATE TABLE connections (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 provider TEXT NOT NULL,
 access_token TEXT NOT NULL,
 refresh_token TEXT NOT NULL,
 scopes TEXT NOT NULL,
 expires_at INTEGER,
 refresh_expires_at INTEGER,
 revision INTEGER NOT NULL DEFAULT 1,
 refreshing INTEGER NOT NULL DEFAULT 0 CHECK(refreshing IN (0,1)),
 UNIQUE(session_id, provider)
)`,
}

// Open acquires exclusive database ownership before schema setup and recovery.
// Runtime startup calls it before starting cleanup or serving HTTP.
func Open(ctx context.Context, path string, lifetime time.Duration, limit int) (*Store, error) {
	if path == "" || lifetime <= 0 || limit <= 0 {
		return nil, errors.New("database path, positive lifetime and capacity required")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, storage(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, storage(err)
	}
	// Serialize creation so another Open cannot lock a newly created file before its creator closes it.
	openMu.Lock()
	defer openMu.Unlock()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, storage(err)
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, storage(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, storage(err)
	}
	if !info.Mode().IsRegular() {
		return nil, storage(errors.New("database path must be a regular file"))
	}
	// Closing an extra descriptor for an existing file would release SQLite's POSIX locks.
	if err := os.Chmod(path, 0600); err != nil {
		return nil, storage(err)
	}
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{}
	// DSN pragmas run on every physical connection, including replacements.
	for _, pragma := range []string{"busy_timeout(5000)", "locking_mode(EXCLUSIVE)", "journal_mode(DELETE)", "synchronous(EXTRA)", "foreign_keys(ON)"} {
		q.Add("_pragma", pragma)
	}
	q.Set("_txlock", "immediate")
	u.RawQuery = q.Encode()
	connector, err := sqlite.NewConnector(u.String())
	if err != nil {
		return nil, storage(err)
	}
	db := sql.OpenDB(exclusiveConnector{connector})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, lifetime: lifetime, limit: limit, flights: make(map[refreshKey]*refreshFlight)}
	if err := s.initialize(ctx); err != nil {
		db.Close()
		return nil, storage(err)
	}
	return s, nil
}

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != 1 {
		return errors.New("unsupported session schema version")
	}
	rows, err := tx.QueryContext(ctx, "SELECT sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		return err
	}
	var existing []string
	for rows.Next() {
		var statement string
		if err := rows.Scan(&statement); err != nil {
			rows.Close()
			return err
		}
		existing = append(existing, statement)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if version == 0 {
		if len(existing) != 0 {
			return errors.New("unrecognized existing session schema")
		}
		for _, statement := range schema {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, "PRAGMA user_version = 1"); err != nil {
			return err
		}
	} else {
		expected := []string{schema[2], schema[1], schema[0]}
		if len(existing) != len(expected) {
			return errors.New("unrecognized session schema")
		}
		for i := range expected {
			if existing[i] != expected[i] {
				return errors.New("unrecognized session schema")
			}
		}
	}
	// A committed claim may have consumed a rotating token before interruption.
	if _, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE refreshing = 1"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Close() error { return storage(s.db.Close()) }

// ---------- Authorization transactions ----------

// BeginAuth replaces pending authorization in an active or newly allocated session.
// The returned browser metadata preserves the original absolute deadline.
func (s *Store) BeginAuth(ctx context.Context, cookie ID, pending PendingAuth) (BrowserSession, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var key, deadline int64
	err = tx.QueryRowContext(ctx, "SELECT id, expires_at FROM sessions WHERE cookie = ? AND expires_at > ?", cookie, now.UnixMicro()).Scan(&key, &deadline)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sessions").Scan(&count); err != nil {
			return BrowserSession{}, storage(err)
		}
		if count >= s.limit {
			return BrowserSession{}, ErrSessionLimit
		}
		cookie, err = generateID()
		if err != nil {
			return BrowserSession{}, storage(err)
		}
		deadline = now.Add(s.lifetime).UnixMicro()
		result, err := tx.ExecContext(ctx, "INSERT INTO sessions(cookie, expires_at) VALUES (?, ?)", cookie, deadline)
		if err != nil {
			return BrowserSession{}, storage(err)
		}
		key, err = result.LastInsertId()
		if err != nil {
			return BrowserSession{}, storage(err)
		}
	} else if err != nil {
		return BrowserSession{}, storage(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pending_auth(session_id, provider, state, verifier, created_at) VALUES (?, ?, ?, ?, ?)
 ON CONFLICT(session_id) DO UPDATE SET provider=excluded.provider, state=excluded.state, verifier=excluded.verifier, created_at=excluded.created_at`, key, pending.Provider, pending.State, pending.PKCEVerifier, now.UnixMicro())
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	if err := tx.Commit(); err != nil {
		return BrowserSession{}, storage(err)
	}
	return BrowserSession{cookie, time.UnixMicro(deadline).UTC()}, nil
}

// ConsumeAuth removes only an active session's matching, unexpired attempt.
// The callback receives its verifier and handle before any provider exchange.
func (s *Store) ConsumeAuth(ctx context.Context, cookie ID, provider, state string) (string, AuthHandle, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", AuthHandle{}, storage(err)
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var key int64
	var verifier string
	err = tx.QueryRowContext(ctx, `SELECT s.id, p.verifier FROM sessions s JOIN pending_auth p ON p.session_id=s.id
 WHERE s.cookie=? AND s.expires_at>? AND p.provider=? AND p.state=? AND p.created_at>=?`, cookie, now.UnixMicro(), provider, state, now.Add(-10*time.Minute).UnixMicro()).Scan(&key, &verifier)
	if errors.Is(err, sql.ErrNoRows) {
		return "", AuthHandle{}, ErrInvalidAuth
	}
	if err != nil {
		return "", AuthHandle{}, storage(err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM pending_auth WHERE session_id=?", key); err != nil {
		return "", AuthHandle{}, storage(err)
	}
	if err := tx.Commit(); err != nil {
		return "", AuthHandle{}, storage(err)
	}
	return verifier, AuthHandle{key, cookie, provider}, nil
}

// CompleteAuth saves the handle's provider and rotates its original cookie atomically.
// Callback completion cannot restore a logged-out session or overwrite a later rotation.
func (s *Store) CompleteAuth(ctx context.Context, handle AuthHandle, connection Connection) (BrowserSession, error) {
	if connection.Provider != handle.provider {
		return BrowserSession{}, ErrInvalidAuth
	}
	cookie, err := generateID()
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	defer tx.Rollback()
	var deadline int64
	err = tx.QueryRowContext(ctx, `UPDATE sessions SET cookie=? WHERE id=? AND cookie=? AND expires_at>? RETURNING expires_at`, cookie, handle.session, handle.cookie, time.Now().UnixMicro()).Scan(&deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return BrowserSession{}, ErrInvalidAuth
	}
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	// Delete and insert give reconnects a never-reused row identity.
	if _, err := tx.ExecContext(ctx, "DELETE FROM connections WHERE session_id=? AND provider=?", handle.session, handle.provider); err != nil {
		return BrowserSession{}, storage(err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO connections(session_id,provider,access_token,refresh_token,scopes,expires_at,refresh_expires_at) VALUES (?,?,?,?,?,?,?)`, handle.session, connection.Provider, connection.AccessToken, connection.RefreshToken, connection.Scopes, deadlineValue(connection.ExpiresAt), deadlineValue(connection.RefreshExpiresAt))
	if err != nil {
		return BrowserSession{}, storage(err)
	}
	if err := tx.Commit(); err != nil {
		return BrowserSession{}, storage(err)
	}
	return BrowserSession{cookie, time.UnixMicro(deadline).UTC()}, nil
}

// ---------- Connection reads and conditional writes ----------

// Acquire the pooled connection before reading the clock so queued operations check current expiry.

func (s *Store) LoadConnection(ctx context.Context, cookie ID, provider string) (Connection, ConnectionRef, error) {
	dbConn, err := s.db.Conn(ctx)
	if err != nil {
		return Connection{}, ConnectionRef{}, storage(err)
	}
	defer dbConn.Close()
	var conn Connection
	var ref ConnectionRef
	var row, accessDeadline, refreshDeadline sql.NullInt64
	var refreshing sql.NullBool
	err = dbConn.QueryRowContext(ctx, `SELECT s.id, c.id, coalesce(c.revision,0),
 coalesce(c.access_token,''), coalesce(c.refresh_token,''), coalesce(c.scopes,''),
 c.expires_at, c.refresh_expires_at, c.refreshing
 FROM sessions s LEFT JOIN connections c ON c.session_id=s.id AND c.provider=?
 WHERE s.cookie=? AND s.expires_at>?`, provider, cookie, time.Now().UnixMicro()).Scan(&ref.session, &row, &ref.revision, &conn.AccessToken, &conn.RefreshToken, &conn.Scopes, &accessDeadline, &refreshDeadline, &refreshing)
	if errors.Is(err, sql.ErrNoRows) {
		return Connection{}, ref, ErrNoSession
	}
	if err != nil {
		return Connection{}, ref, storage(err)
	}
	if !row.Valid {
		return Connection{}, ref, ErrNoConnection
	}
	ref.row, ref.provider = row.Int64, provider
	if refreshing.Bool {
		return Connection{}, ref, ErrRefreshing
	}
	conn.Provider = provider
	if accessDeadline.Valid {
		conn.ExpiresAt = time.UnixMicro(accessDeadline.Int64).UTC()
	}
	if refreshDeadline.Valid {
		conn.RefreshExpiresAt = time.UnixMicro(refreshDeadline.Int64).UTC()
	}
	return conn, ref, nil
}

func (s *Store) ClaimRefresh(ctx context.Context, ref ConnectionRef) (RefreshClaim, error) {
	dbConn, err := s.db.Conn(ctx)
	if err != nil {
		return RefreshClaim{}, storage(err)
	}
	defer dbConn.Close()
	result, err := dbConn.ExecContext(ctx, `UPDATE connections SET refreshing=1,revision=revision+1 WHERE id=? AND session_id=? AND provider=? AND revision=? AND refreshing=0
 AND EXISTS(SELECT 1 FROM sessions WHERE id=? AND expires_at>?)`, ref.row, ref.session, ref.provider, ref.revision, ref.session, time.Now().UnixMicro())
	if err := changed(result, err); err != nil {
		return RefreshClaim{}, err
	}
	ref.revision++
	return RefreshClaim{ref}, nil
}

func (s *Store) FinishRefresh(ctx context.Context, claim RefreshClaim, connection Connection) error {
	ref := claim.ref
	if connection.Provider != ref.provider {
		return ErrStale
	}
	dbConn, err := s.db.Conn(ctx)
	if err != nil {
		return storage(err)
	}
	defer dbConn.Close()
	result, err := dbConn.ExecContext(ctx, `UPDATE connections SET access_token=?,refresh_token=?,scopes=?,expires_at=?,refresh_expires_at=?,refreshing=0,revision=revision+1
 WHERE id=? AND session_id=? AND provider=? AND revision=? AND refreshing=1
 AND EXISTS(SELECT 1 FROM sessions WHERE id=? AND expires_at>?)`, connection.AccessToken, connection.RefreshToken, connection.Scopes, deadlineValue(connection.ExpiresAt), deadlineValue(connection.RefreshExpiresAt), ref.row, ref.session, ref.provider, ref.revision, ref.session, time.Now().UnixMicro())
	return changed(result, err)
}

// DiscardConnection removes only the exact revision loaded or claimed.
// Reconnects and later refreshes make earlier references stale.
func (s *Store) DiscardConnection(ctx context.Context, ref ConnectionRef) error {
	dbConn, err := s.db.Conn(ctx)
	if err != nil {
		return storage(err)
	}
	defer dbConn.Close()
	result, err := dbConn.ExecContext(ctx, `DELETE FROM connections WHERE id=? AND session_id=? AND provider=? AND revision=?
 AND EXISTS(SELECT 1 FROM sessions WHERE id=? AND expires_at>?)`, ref.row, ref.session, ref.provider, ref.revision, ref.session, time.Now().UnixMicro())
	return changed(result, err)
}

func (c RefreshClaim) Reference() ConnectionRef { return c.ref }

func (s *Store) Logout(ctx context.Context, cookie ID) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE cookie=?", cookie)
	return storage(err)
}

func (s *Store) CleanupExpired(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", time.Now().UnixMicro())
	return storage(err)
}

// ---------- Helpers ----------

func storage(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStorage, err)
}

func changed(result sql.Result, err error) error {
	if err != nil {
		return storage(err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return storage(err)
	}
	if count == 0 {
		return ErrStale
	}
	return nil
}

func deadlineValue(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMicro()
}

func generateID() (ID, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return ID(base64.RawURLEncoding.EncodeToString(b)), nil
}
