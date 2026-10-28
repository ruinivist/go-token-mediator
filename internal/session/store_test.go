// These tests exercise durable transactions, recovery, and refresh coordination.
// They use temporary files and seeded SQL deadlines at the store boundary.
package session

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// ---------- Fixtures ----------

func openStore(t *testing.T, path string, limit int) *Store {
	t.Helper()
	s, err := Open(t.Context(), path, time.Hour, limit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func begin(t *testing.T, s *Store, cookie ID, provider string) BrowserSession {
	t.Helper()
	browser, err := s.BeginAuth(t.Context(), cookie, PendingAuth{provider, "state", "verifier"})
	if err != nil {
		t.Fatal(err)
	}
	return browser
}

func connect(t *testing.T, s *Store, cookie ID, provider string) BrowserSession {
	t.Helper()
	browser := begin(t, s, cookie, provider)
	verifier, handle, err := s.ConsumeAuth(t.Context(), browser.ID, provider, "state")
	if err != nil || verifier != "verifier" {
		t.Fatalf("consume: %v", err)
	}
	browser, err = s.CompleteAuth(t.Context(), handle, Connection{Provider: provider, AccessToken: "access", RefreshToken: "refresh", Scopes: "read"})
	if err != nil {
		t.Fatal(err)
	}
	return browser
}

func execSQL(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}

// ---------- Authorization and expiry ----------

func TestAuthorizationTransactions(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := connect(t, s, "", "other")
	original := browser
	browser = begin(t, s, browser.ID, "mock")
	if browser != original {
		t.Fatal("begin renewed session")
	}
	for _, tc := range []struct {
		cookie          ID
		provider, state string
	}{{browser.ID, "wrong", "state"}, {browser.ID, "mock", "wrong"}, {"unknown", "mock", "state"}} {
		if _, _, err := s.ConsumeAuth(t.Context(), tc.cookie, tc.provider, tc.state); !errors.Is(err, ErrInvalidAuth) {
			t.Fatalf("invalid consume: %v", err)
		}
	}
	_, handle, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); !errors.Is(err, ErrInvalidAuth) {
		t.Fatal("callback replay accepted")
	}
	if _, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "wrong"}); !errors.Is(err, ErrInvalidAuth) {
		t.Fatal("provider mismatch accepted")
	}
	execSQL(t, s, `CREATE TEMP TRIGGER reject_connection BEFORE INSERT ON connections BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	if _, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "mock"}); !errors.Is(err, ErrStorage) {
		t.Fatalf("write failure: %v", err)
	}
	if _, _, err := s.LoadConnection(t.Context(), browser.ID, "other"); err != nil {
		t.Fatalf("failed write rotated cookie: %v", err)
	}
	execSQL(t, s, "DROP TRIGGER reject_connection")
	rotated, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "mock", AccessToken: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if rotated.ID == browser.ID || !rotated.ExpiresAt.Equal(original.ExpiresAt) {
		t.Fatal("rotation metadata")
	}
	if _, _, err := s.LoadConnection(t.Context(), browser.ID, "other"); !errors.Is(err, ErrNoSession) {
		t.Fatal("obsolete cookie accepted")
	}
	for _, provider := range []string{"mock", "other"} {
		if _, _, err := s.LoadConnection(t.Context(), rotated.ID, provider); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "mock"}); !errors.Is(err, ErrInvalidAuth) {
		t.Fatal("obsolete handle accepted")
	}
}

func TestCapacityExpiryAndCleanup(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 1)
	browser := begin(t, s, "", "mock")
	execSQL(t, s, "UPDATE pending_auth SET created_at=?", time.Now().Add(-11*time.Minute).UnixMicro())
	if _, _, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); !errors.Is(err, ErrInvalidAuth) {
		t.Fatal("expired pending auth accepted")
	}
	if _, err := s.BeginAuth(t.Context(), "", PendingAuth{}); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("capacity: %v", err)
	}
	begin(t, s, browser.ID, "other")
	execSQL(t, s, "UPDATE sessions SET expires_at=?", time.Now().Add(-time.Second).UnixMicro())
	if _, _, err := s.LoadConnection(t.Context(), browser.ID, "mock"); !errors.Is(err, ErrNoSession) {
		t.Fatal("expired session accepted")
	}
	if _, err := s.BeginAuth(t.Context(), browser.ID, PendingAuth{}); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("expired session freed capacity before cleanup")
	}
	if err := s.CleanupExpired(t.Context()); err != nil {
		t.Fatal(err)
	}
	fresh := connect(t, s, "", "mock")
	var count int
	if err := s.db.QueryRowContext(t.Context(), "SELECT count(*) FROM pending_auth").Scan(&count); err != nil || count != 0 {
		t.Fatal("pending auth did not cascade")
	}
	if err := s.Logout(t.Context(), fresh.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Logout(t.Context(), fresh.ID); err != nil {
		t.Fatal(err)
	}
	begin(t, s, "", "mock")
}

func TestBeginRollback(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 1)
	execSQL(t, s, `CREATE TEMP TRIGGER reject_pending BEFORE INSERT ON pending_auth BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	if _, err := s.BeginAuth(t.Context(), "", PendingAuth{}); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	execSQL(t, s, "DROP TRIGGER reject_pending")
	begin(t, s, "", "mock")
}

func TestCompletionRejectsInactiveSession(t *testing.T) {
	for _, mode := range []string{"logout", "expiry", "rotation"} {
		t.Run(mode, func(t *testing.T) {
			s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
			browser := begin(t, s, "", "mock")
			_, handle, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state")
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "logout":
				if err := s.Logout(t.Context(), browser.ID); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				execSQL(t, s, "UPDATE sessions SET expires_at=0")
			case "rotation":
				connect(t, s, browser.ID, "other")
			}
			if _, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "mock"}); !errors.Is(err, ErrInvalidAuth) {
				t.Fatalf("completion: %v", err)
			}
		})
	}
}

// ---------- Persistence and ownership ----------

func TestReopenAndRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "sessions.db")
	s := openStore(t, path, 10)
	browser := connect(t, s, "", "mock")
	browser = connect(t, s, browser.ID, "other")
	conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRefresh(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	conn.AccessToken, conn.RefreshToken = "refreshed", "rotated"
	conn.ExpiresAt = time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	if err := s.FinishRefresh(t.Context(), claim, conn); err != nil {
		t.Fatal(err)
	}
	pending := begin(t, s, browser.ID, "third")
	loggedOut := connect(t, s, "", "mock")
	if err := s.Logout(t.Context(), loggedOut.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, 10)
	loaded, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil || loaded != conn {
		t.Fatalf("credentials did not persist: %v", err)
	}
	verifier, handle, err := s.ConsumeAuth(t.Context(), browser.ID, "third", "state")
	if err != nil || verifier != "verifier" {
		t.Fatal("pending auth did not persist")
	}
	completed, err := s.CompleteAuth(t.Context(), handle, Connection{Provider: "third"})
	if err != nil || !completed.ExpiresAt.Equal(pending.ExpiresAt) {
		t.Fatal("deadline did not persist")
	}
	if _, _, err := s.LoadConnection(t.Context(), loggedOut.ID, "mock"); !errors.Is(err, ErrNoSession) {
		t.Fatal("logout did not persist")
	}
	if _, err := s.ClaimRefresh(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openStore(t, path, 10)
	if _, _, err := s.LoadConnection(t.Context(), completed.ID, "mock"); !errors.Is(err, ErrNoConnection) {
		t.Fatalf("interrupted refresh reused: %v", err)
	}
	if _, _, err := s.LoadConnection(t.Context(), completed.ID, "other"); err != nil {
		t.Fatal("recovery lost unrelated provider")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("database permissions")
	}
	info, err = os.Stat(filepath.Dir(path))
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("directory permissions")
	}
}

func TestOwnershipAndSchema(t *testing.T) {
	if path := os.Getenv("TOKEN_MEDIATOR_INSPECT_DATABASE"); path != "" {
		db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(1)")
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var count int
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM sessions").Scan(&count); err == nil {
			t.Fatal("external process bypassed exclusive ownership")
		}
		return
	}
	path := filepath.Join(t.TempDir(), "sessions.db")
	first := openStore(t, path, 10)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	second, err := Open(ctx, path, time.Hour, 10)
	if second != nil {
		second.Close()
		t.Fatal("second owner opened database")
	}
	if !errors.Is(err, ErrStorage) {
		t.Fatalf("ownership: %v", err)
	}
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestOwnershipAndSchema$")
	child.Env = append(os.Environ(), "TOKEN_MEDIATOR_INSPECT_DATABASE="+path)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("exclusive ownership lost after second open: %v\n%s", err, output)
	}
	execSQL(t, first, "PRAGMA user_version=2")
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(t.Context(), path, time.Hour, 10); err == nil {
		s.Close()
		t.Fatal("unsupported version accepted")
	}
	for _, version := range []int{0, 1} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "unknown.db")
			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("CREATE TABLE unknown(value TEXT)"); err != nil {
				t.Fatal(err)
			}
			if version == 1 {
				if _, err := db.Exec("PRAGMA user_version=1"); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			if s, err := Open(t.Context(), path, time.Hour, 10); err == nil {
				s.Close()
				t.Fatal("unrecognized schema accepted")
			}
		})
	}
}

// ---------- Conditional refresh writes ----------

func TestRefreshReferences(t *testing.T) {
	for _, mode := range []string{"reconnect", "logout", "expiry", "rotate"} {
		t.Run(mode, func(t *testing.T) {
			s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
			browser := connect(t, s, "", "mock")
			conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
			if err != nil {
				t.Fatal(err)
			}
			claim, err := s.ClaimRefresh(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.ClaimRefresh(t.Context(), ref); !errors.Is(err, ErrStale) {
				t.Fatal("claim replay accepted")
			}
			if got, _, err := s.LoadConnection(t.Context(), browser.ID, "mock"); !errors.Is(err, ErrRefreshing) || got.AccessToken != "" || got.RefreshToken != "" {
				t.Fatal("marked credentials exposed")
			}
			switch mode {
			case "reconnect":
				browser = connect(t, s, browser.ID, "mock")
			case "logout":
				if err := s.Logout(t.Context(), browser.ID); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				execSQL(t, s, "UPDATE sessions SET expires_at=0")
			case "rotate":
				browser = connect(t, s, browser.ID, "other")
			}
			conn.AccessToken = "new"
			err = s.FinishRefresh(t.Context(), claim, conn)
			if mode == "rotate" {
				if err != nil {
					t.Fatal(err)
				}
				loaded, _, err := s.LoadConnection(t.Context(), browser.ID, "mock")
				if err != nil || loaded.AccessToken != "new" {
					t.Fatal("rotation lost refresh")
				}
			} else if !errors.Is(err, ErrStale) {
				t.Fatalf("stale finish: %v", err)
			}
			if err := s.DiscardConnection(t.Context(), ref); !errors.Is(err, ErrStale) {
				t.Fatal("stale discard accepted")
			}
		})
	}
}

func TestFailedFinishLeavesMarker(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := connect(t, s, "", "mock")
	browser = connect(t, s, browser.ID, "other")
	conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRefresh(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	execSQL(t, s, `CREATE TEMP TRIGGER reject_finish BEFORE UPDATE ON connections WHEN NEW.refreshing=0 BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	if err := s.FinishRefresh(t.Context(), claim, conn); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	if got, _, err := s.LoadConnection(t.Context(), browser.ID, "mock"); !errors.Is(err, ErrRefreshing) || got.RefreshToken != "" {
		t.Fatal("failed finish reused old credentials")
	}
	if _, _, err := s.LoadConnection(t.Context(), browser.ID, "other"); err != nil {
		t.Fatal("failed finish lost other provider")
	}
}

func TestConsumeConcurrent(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := begin(t, s, "", "mock")
	results := make(chan error, 10)
	for range 10 {
		go func() { _, _, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); results <- err }()
	}
	success := 0
	for range 10 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, ErrInvalidAuth) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("consumed %d times", success)
	}
}

func TestCoordinatorAcrossRotation(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := connect(t, s, "", "mock")
	_, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := s.CoordinateRefresh(t.Context(), ref, func() error { close(started); <-release; return ErrStale }); !errors.Is(err, ErrStale) {
			t.Error(err)
		}
	})
	<-started
	browser = connect(t, s, browser.ID, "other")
	_, rotatedRef, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil || rotatedRef.session != ref.session {
		t.Fatal("rotation changed stable identity")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.CoordinateRefresh(ctx, rotatedRef, func() error { t.Error("canceled operation ran"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Inspect the registered signal under its lock, then release all waiters together.
	s.mu.Lock()
	flight := s.flights[refreshKey{ref.session, ref.provider}]
	s.mu.Unlock()
	if flight == nil {
		t.Fatal("rotation lost in-flight coordination")
	}
	close(release)
	wg.Wait()
}

func TestConnectionSettingsAfterReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.db")
	s := openStore(t, path, 10)
	browser := connect(t, s, "", "mock")
	conn, err := s.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(any) error { return driver.ErrBadConn }); !errors.Is(err, driver.ErrBadConn) {
		t.Fatal(err)
	}
	conn.Close()
	for _, tc := range []struct {
		pragma string
		want   any
	}{
		{"foreign_keys", int64(1)}, {"busy_timeout", int64(5000)}, {"synchronous", int64(3)}, {"journal_mode", "delete"}, {"locking_mode", "exclusive"},
	} {
		var got any
		if err := s.db.QueryRowContext(t.Context(), "PRAGMA "+tc.pragma).Scan(&got); err != nil || got != tc.want {
			t.Fatalf("%s: got %v, err %v", tc.pragma, got, err)
		}
	}
	if _, _, err := s.LoadConnection(t.Context(), browser.ID, "mock"); err != nil {
		t.Fatal(err)
	}
	inspector, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer inspector.Close()
	var count int
	if err := inspector.QueryRowContext(t.Context(), "SELECT count(*) FROM sessions").Scan(&count); err == nil {
		t.Fatal("external inspection bypassed exclusive ownership")
	}
}

func TestLongTokenDeadline(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := connect(t, s, "", "mock")
	conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRefresh(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	conn.ExpiresAt = time.Date(2319, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := s.FinishRefresh(t.Context(), claim, conn); err != nil {
		t.Fatal(err)
	}
	loaded, _, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil || !loaded.ExpiresAt.Equal(conn.ExpiresAt) {
		t.Fatal("token deadline overflowed")
	}
}

func TestCoordinatorSharesErrorsAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := &Store{flights: make(map[refreshKey]*refreshFlight)}
		ref := ConnectionRef{session: 1, provider: "mock"}
		release := make(chan struct{})
		sentinel := errors.New("provider rejection")
		calls := 0
		work := func() error { calls++; <-release; return sentinel }
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if err := s.CoordinateRefresh(t.Context(), ref, work); !errors.Is(err, sentinel) {
					t.Error(err)
				}
			})
		}
		synctest.Wait()
		ctx, cancel := context.WithCancel(t.Context())
		canceled := make(chan error, 1)
		go func() { canceled <- s.CoordinateRefresh(ctx, ref, work) }()
		synctest.Wait()
		cancel()
		if err := <-canceled; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		// A blocked provider does not hold the coordinator lock for other providers.
		if err := s.CoordinateRefresh(t.Context(), ConnectionRef{session: 1, provider: "other"}, func() error { return nil }); err != nil {
			t.Fatal(err)
		}
		close(release)
		wg.Wait()
		if calls != 1 {
			t.Fatalf("shared operations: %d", calls)
		}
	})
}

func TestStorageFailuresAreDistinct(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := connect(t, s, "", "mock")
	browser = begin(t, s, browser.ID, "other")
	_, handle, err := s.ConsumeAuth(t.Context(), browser.ID, "other", "state")
	if err != nil {
		t.Fatal(err)
	}
	conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
	if err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRefresh(t.Context(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	_, beginErr := s.BeginAuth(t.Context(), browser.ID, PendingAuth{})
	_, _, consumeErr := s.ConsumeAuth(t.Context(), browser.ID, "other", "state")
	_, completeErr := s.CompleteAuth(t.Context(), handle, Connection{Provider: "other"})
	_, _, loadErr := s.LoadConnection(t.Context(), browser.ID, "mock")
	_, claimErr := s.ClaimRefresh(t.Context(), ref)
	for _, err := range []error{beginErr, consumeErr, completeErr, loadErr, claimErr, s.FinishRefresh(t.Context(), claim, conn), s.DiscardConnection(t.Context(), claim.Reference()), s.Logout(t.Context(), browser.ID), s.CleanupExpired(t.Context())} {
		if !errors.Is(err, ErrStorage) {
			t.Fatalf("database failure confused with missing state: %v", err)
		}
	}
}

// queuedContext signals when database/sql starts waiting for its held connection.
// It lets expiry tests advance persisted deadlines without clock sleeps.
type queuedContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *queuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestExpiryWhileWaitingForSQL(t *testing.T) {
	for _, operation := range []string{"load", "claim", "finish", "discard"} {
		t.Run(operation, func(t *testing.T) {
			s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
			browser := connect(t, s, "", "mock")
			conn, ref, err := s.LoadConnection(t.Context(), browser.ID, "mock")
			if err != nil {
				t.Fatal(err)
			}
			var claim RefreshClaim
			if operation == "finish" {
				claim, err = s.ClaimRefresh(t.Context(), ref)
				if err != nil {
					t.Fatal(err)
				}
			}
			held, err := s.db.Conn(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			ctx := &queuedContext{Context: t.Context(), waiting: make(chan struct{})}
			result := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "load":
					_, _, err = s.LoadConnection(ctx, browser.ID, "mock")
				case "claim":
					_, err = s.ClaimRefresh(ctx, ref)
				case "finish":
					err = s.FinishRefresh(ctx, claim, conn)
				case "discard":
					err = s.DiscardConnection(ctx, ref)
				}
				result <- err
			}()
			<-ctx.waiting
			if _, err := held.ExecContext(t.Context(), "UPDATE sessions SET expires_at=?", time.Now().UnixMicro()); err != nil {
				t.Fatal(err)
			}
			if err := held.Close(); err != nil {
				t.Fatal(err)
			}
			want := ErrStale
			if operation == "load" {
				want = ErrNoSession
			}
			if err := <-result; !errors.Is(err, want) {
				t.Fatalf("expired queued %s: %v", operation, err)
			}
		})
	}
}

func TestOpenRejectsDirectoryWithoutChangingPermissions(t *testing.T) {
	path := t.TempDir()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Open(t.Context(), path, time.Hour, 10); err == nil {
		s.Close()
		t.Fatal("opened a directory as database")
	}
	after, err := os.Stat(path)
	if err != nil || after.Mode() != before.Mode() {
		t.Fatal("invalid database path changed directory permissions")
	}
}

func TestConsumeRollback(t *testing.T) {
	s := openStore(t, filepath.Join(t.TempDir(), "sessions.db"), 10)
	browser := begin(t, s, "", "mock")
	execSQL(t, s, `CREATE TEMP TRIGGER reject_consume BEFORE DELETE ON pending_auth BEGIN SELECT RAISE(ABORT,'test failure'); END`)
	if verifier, _, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); !errors.Is(err, ErrStorage) || verifier != "" {
		t.Fatal("failed consume exposed a usable result")
	}
	execSQL(t, s, "DROP TRIGGER reject_consume")
	if verifier, _, err := s.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); err != nil || verifier != "verifier" {
		t.Fatal("failed consume removed pending attempt")
	}
}
