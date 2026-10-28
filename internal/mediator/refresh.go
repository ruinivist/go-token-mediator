// Token retrieval keeps OAuth refresh policy separate from SQL persistence.
// The browser token handler uses shared operations and reloads each caller's cookie.
package mediator

import (
	"context"
	"errors"
	"time"

	"token-mediator/internal/session"
)

// ---------- Refresh policy ----------

// shortcut: token lifetimes <=2m can repeatedly refresh and return 401 during overlap;
// adapt the buffer and completion handling when a provider needs such lifetimes.
func needsRefresh(conn session.Connection, now time.Time) bool {
	return !conn.ExpiresAt.IsZero() && conn.ExpiresAt.Sub(now) <= 2*time.Minute
}

func (s *Server) accessConnection(ctx context.Context, cookie session.ID, provider string, p ProviderConfig) (session.Connection, error) {
	for {
		conn, ref, err := s.store.LoadConnection(ctx, cookie, provider)
		if err != nil && !errors.Is(err, session.ErrRefreshing) {
			return session.Connection{}, err
		}
		if err == nil && !needsRefresh(conn, time.Now()) {
			return conn, nil
		}
		err = s.store.CoordinateRefresh(ctx, ref, func() error {
			// A completed operation or reconnect may have replaced the loaded revision.
			current, currentRef, err := s.store.LoadConnection(ctx, cookie, provider)
			if err != nil {
				return err
			}
			now := time.Now()
			if !needsRefresh(current, now) {
				return nil
			}
			if current.RefreshToken == "" || (!current.RefreshExpiresAt.IsZero() && !now.Before(current.RefreshExpiresAt)) {
				if now.Before(current.ExpiresAt) {
					return nil
				}
				if err := s.store.DiscardConnection(ctx, currentRef); err != nil {
					return err
				}
				return session.ErrNoConnection
			}
			claim, err := s.store.ClaimRefresh(ctx, currentRef)
			if err != nil {
				return err
			}
			resp, providerErr := p.refreshAccessToken(ctx, current.RefreshToken)
			// The provider may have consumed the token even after the browser disconnects.
			persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if providerErr != nil {
				var upstream *tokenError
				discard := errors.As(providerErr, &upstream) && (upstream.uncertain || upstream.code == "invalid_grant" || upstream.code == "bad_refresh_token")
				if discard {
					if err := s.store.DiscardConnection(persistCtx, claim.Reference()); err != nil {
						return err
					}
					if upstream.code == "invalid_grant" || upstream.code == "bad_refresh_token" {
						return session.ErrNoConnection
					}
				} else {
					if err := s.store.FinishRefresh(persistCtx, claim, current); err != nil {
						return err
					}
				}
				return providerErr
			}
			conn := current

			conn.AccessToken = resp.AccessToken
			conn.ExpiresAt = time.Time{}
			if resp.ExpiresIn != nil {
				conn.ExpiresAt = time.Now().Add(time.Duration(*resp.ExpiresIn) * time.Second)
			}
			if resp.RefreshToken != nil {
				conn.RefreshToken = *resp.RefreshToken
				// A replacement token does not inherit the previous token's deadline.
				conn.RefreshExpiresAt = time.Time{}
			}
			if resp.RefreshTokenExpiresIn != nil {
				conn.RefreshExpiresAt = time.Now().Add(time.Duration(*resp.RefreshTokenExpiresIn) * time.Second)
			}
			if resp.Scope != nil {
				conn.Scopes = *resp.Scope
			}
			return s.store.FinishRefresh(persistCtx, claim, conn)
		})
		// Rotation can invalidate only the leader's cookie before its recheck.
		// Retry with each caller's cookie; no provider call happened for ErrNoSession.
		if errors.Is(err, session.ErrStale) || errors.Is(err, session.ErrNoSession) {
			continue
		}
		// Validate even a waiter's obsolete cookie before returning a shared outcome.
		readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		current, _, readErr := s.store.LoadConnection(readCtx, cookie, provider)
		cancel()
		if errors.Is(readErr, session.ErrNoSession) || errors.Is(readErr, session.ErrStorage) {
			return session.Connection{}, readErr
		}
		// Reconnection can replace a discarded row before its refresh error is shared.
		// A successful reload must recheck that replacement, not inherit the old 401.
		if errors.Is(err, session.ErrNoConnection) && readErr == nil {
			continue
		}
		if err != nil {
			return session.Connection{}, err
		}
		return current, readErr
	}
}
