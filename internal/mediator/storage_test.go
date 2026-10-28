// These tests cover storage failures and HTTP shutdown around provider work.
// They keep browser errors sanitized and storage alive through final persistence.
package mediator

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"token-mediator/internal/session"
)

// ---------- Storage failures ----------

func TestStorageErrors(t *testing.T) {
	for _, route := range []string{"start", "callback", "token", "logout"} {
		t.Run(route, func(t *testing.T) {
			store := newTestStore(t, 10, time.Hour)
			browser := authorize(t, store, "", session.Connection{Provider: "mock", AccessToken: "private-token"})
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 100, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {}}}
			req := browserRequest("/oauth/mock/"+route, "{}")
			if route == "logout" {
				req = browserRequest("/session/logout", "{}")
			}
			if route == "callback" {
				req = httptest.NewRequest(http.MethodGet, "/oauth/mock/callback?code=private-code&state=private-state", nil)
			}
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(browser.ID)})
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
			if rec.Code != 503 || rec.Body.String() != "{\"error\":\"storage_unavailable\"}\n" || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("storage response: %d %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("storage failure lost cache protection")
			}
		})
	}
}

func TestFinalWriteFailureRecovery(t *testing.T) {
	for _, operation := range []string{"refresh", "callback"} {
		t.Run(operation, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sessions.db")
			store, err := session.Open(t.Context(), path, time.Hour, 10)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := store.Close(); err != nil {
					t.Error(err)
				}
				io.WriteString(w, `{"access_token":"new","token_type":"Bearer","refresh_token":"rotated","expires_in":3600}`)
			}))
			defer provider.Close()
			browser := authorize(t, store, "", session.Connection{Provider: "mock", AccessToken: "old", RefreshToken: "private-refresh", ExpiresAt: time.Now().Add(time.Minute)}, session.Connection{Provider: "other", AccessToken: "unrelated"})
			cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 100, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"mock": {TokenUrl: provider.URL}}}
			req := browserTokenRequest(browser.ID)
			if operation == "callback" {
				if _, err := store.BeginAuth(t.Context(), browser.ID, session.PendingAuth{Provider: "mock", State: "state"}); err != nil {
					t.Fatal(err)
				}
				req = httptest.NewRequest(http.MethodGet, "/oauth/mock/callback?state=state&code=code", nil)
				req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(browser.ID)})
			}
			rec := httptest.NewRecorder()
			NewServer(cfg, store).routes().ServeHTTP(rec, req)
			if rec.Code != 503 || strings.Contains(rec.Body.String(), "private") || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("final write response: %d %s", rec.Code, rec.Body.String())
			}
			reopened, err := session.Open(t.Context(), path, time.Hour, 10)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, _, err := reopened.LoadConnection(t.Context(), browser.ID, "other"); err != nil {
				t.Fatal("recovery removed other provider or session")
			}
			if operation == "refresh" {
				if _, _, err := reopened.LoadConnection(t.Context(), browser.ID, "mock"); !errors.Is(err, session.ErrNoConnection) {
					t.Fatalf("recovery retained unfinished refresh: %v", err)
				}
				again := httptest.NewRecorder()
				NewServer(cfg, reopened).routes().ServeHTTP(again, browserTokenRequest(browser.ID))
				if again.Code != 401 || calls.Load() != 1 {
					t.Fatal("reused old refresh token after failed final write")
				}
			} else {
				if _, _, err := reopened.ConsumeAuth(t.Context(), browser.ID, "mock", "state"); !errors.Is(err, session.ErrInvalidAuth) {
					t.Fatal("failed completion restored consumed attempt")
				}
			}
		})
	}
}

// ---------- Cookie rotation during refresh ----------

func TestRefreshWaiterAfterLeaderCookieRotation(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, `{"access_token":"shared","refresh_token":"rotated","expires_in":3600}`)
	}))
	defer provider.Close()
	synctest.Test(t, func(t *testing.T) {
		defer provider.CloseClientConnections()
		store, browser, handler := refreshFixture(t, provider.URL, time.Minute, true)
		_, ref, err := store.LoadConnection(t.Context(), browser.ID, "mock")
		if err != nil {
			t.Fatal(err)
		}
		started, release := make(chan struct{}), make(chan struct{})
		leaderDone := make(chan error, 1)
		go func() {
			leaderDone <- store.CoordinateRefresh(t.Context(), ref, func() error {
				close(started)
				<-release
				// Reproduce rotation between the leader's first read and its recheck.
				_, _, err := store.LoadConnection(t.Context(), browser.ID, "mock")
				return err
			})
		}()
		<-started
		rotated := authorize(t, store, browser.ID, session.Connection{Provider: "other", AccessToken: "unrelated"})
		waiterDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, browserTokenRequest(rotated.ID))
			waiterDone <- rec
		}()
		// Wait for the valid caller to join the paused leader, without timing sleeps.
		synctest.Wait()
		close(release)
		if err := <-leaderDone; !errors.Is(err, session.ErrNoSession) {
			t.Fatalf("obsolete leader: %v", err)
		}
		if rec := <-waiterDone; rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token":"shared"`) {
			t.Fatalf("valid waiter: %d %s", rec.Code, rec.Body.String())
		}
		old := httptest.NewRecorder()
		handler.ServeHTTP(old, browserTokenRequest(browser.ID))
		if old.Code != 401 || calls.Load() != 1 {
			t.Fatalf("obsolete caller: %d; refresh calls: %d", old.Code, calls.Load())
		}
	})
}

func TestRefreshWaiterAfterReconnection(t *testing.T) {
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.FormValue("refresh_token") != "replacement-refresh" {
			t.Error("refresh reused discarded credentials")
		}
		io.WriteString(w, `{"access_token":"refreshed-replacement","expires_in":3600}`)
	}))
	defer provider.Close()
	synctest.Test(t, func(t *testing.T) {
		defer provider.CloseClientConnections()
		store, browser, handler := refreshFixture(t, provider.URL, time.Minute, true)
		_, ref, err := store.LoadConnection(t.Context(), browser.ID, "mock")
		if err != nil {
			t.Fatal(err)
		}
		claim, err := store.ClaimRefresh(t.Context(), ref)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.DiscardConnection(t.Context(), claim.Reference()); err != nil {
			t.Fatal(err)
		}
		started, release := make(chan struct{}), make(chan struct{})
		leaderDone := make(chan error, 1)
		go func() {
			leaderDone <- store.CoordinateRefresh(t.Context(), ref, func() error {
				// Hold the old refresh's rejection after deletion, before sharing its error.
				close(started)
				<-release
				return session.ErrNoConnection
			})
		}()
		<-started
		replacement := authorize(t, store, browser.ID, session.Connection{
			Provider: "mock", AccessToken: "replacement", RefreshToken: "replacement-refresh",
			// A short lifetime makes the new caller join the still-pending old refresh.
			ExpiresAt: time.Now().Add(time.Minute),
		})
		waiterDone := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, browserTokenRequest(replacement.ID))
			waiterDone <- rec
		}()
		synctest.Wait()
		close(release)
		if err := <-leaderDone; !errors.Is(err, session.ErrNoConnection) {
			t.Fatalf("discarded connection: %v", err)
		}
		if rec := <-waiterDone; rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token":"refreshed-replacement"`) {
			t.Fatalf("reconnected waiter: %d %s", rec.Code, rec.Body.String())
		}
		if calls.Load() != 1 {
			t.Fatalf("replacement refresh calls: %d", calls.Load())
		}
	})
}

func TestRefreshAcrossCookieRotation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		io.WriteString(w, `{"access_token":"shared","refresh_token":"rotated","expires_in":3600}`)
	}))
	defer provider.Close()
	defer unblock()
	store, browser, handler := refreshFixture(t, provider.URL, time.Minute, true)
	oldResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, browserTokenRequest(browser.ID))
		oldResult <- rec
	}()
	<-started
	// Another provider stays usable and can rotate the cookie during the refresh.
	rotated := authorize(t, store, browser.ID, session.Connection{Provider: "other", AccessToken: "unrelated"})
	cfg := &Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 100, FeOrigin: "https://frontend.example", Providers: map[string]ProviderConfig{"other": {}}}
	other := browserRequest("/oauth/other/token", "{}")
	other.AddCookie(&http.Cookie{Name: sessionCookieName, Value: string(rotated.ID)})
	rec := httptest.NewRecorder()
	NewServer(cfg, store).routes().ServeHTTP(rec, other)
	if rec.Code != 200 {
		t.Fatal("provider request blocked unrelated SQL work")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, browserTokenRequest(rotated.ID))
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"access_token":"shared"`) {
				t.Errorf("rotated caller: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
	unblock()
	wg.Wait()
	if rec := <-oldResult; rec.Code != 401 {
		t.Fatalf("obsolete caller: %d %s", rec.Code, rec.Body.String())
	}
	if calls.Load() != 1 {
		t.Fatalf("refresh calls: %d", calls.Load())
	}
}

// ---------- Shutdown ordering ----------

func TestServerWaitsForFinalPersistence(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(map[bool]string{false: "graceful", true: "forced"}[force], func(t *testing.T) {
			store := newTestStore(t, 10, time.Hour)
			browser := authorize(t, store, "", session.Connection{Provider: "mock", AccessToken: "token"})
			server := NewServer(&Config{RateLimitPerMinute: 60, RateLimitMaxIPs: 100}, store)
			started, finish := make(chan struct{}), make(chan struct{})
			requestCanceled := make(chan struct{})
			persisted := make(chan error, 1)
			server.httpServer.Handler = server.trackRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				if force {
					<-r.Context().Done()
					close(requestCanceled)
				}
				<-finish
				ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), time.Second)
				defer cancel()
				persisted <- store.Logout(ctx, browser.ID)
			}))
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- server.serve(ctx, listener) }()
			clientDone := make(chan struct{})
			go func() {
				defer close(clientDone)
				response, err := http.Get("http://" + listener.Addr().String())
				if err == nil {
					response.Body.Close()
				}
			}()
			<-started
			shutdownStarted := make(chan struct{})
			server.httpServer.RegisterOnShutdown(func() { close(shutdownStarted) })
			cancel()
			<-shutdownStarted
			if force {
				<-requestCanceled
			}
			select {
			case err := <-result:
				t.Fatalf("Run returned before final persistence: %v", err)
			default:
			}
			close(finish)
			if err := <-persisted; err != nil {
				t.Fatalf("storage closed during handler: %v", err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			<-clientDone
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
