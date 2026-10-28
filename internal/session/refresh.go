// Refresh coordination shares completion signals and errors, never credentials.
// The mediator reloads SQL state for each browser after shared work completes.
package session

import "context"

// ---------- Coordination ----------

type refreshKey struct {
	session  int64
	provider string
}

type refreshFlight struct {
	done chan struct{}
	err  error
}

// CoordinateRefresh runs one operation per stable session identity and provider.
// The callback owns policy and runs without a coordination lock or transaction.
func (s *Store) CoordinateRefresh(ctx context.Context, ref ConnectionRef, refresh func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := refreshKey{ref.session, ref.provider}
	s.mu.Lock()
	if flight := s.flights[key]; flight != nil {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-flight.done:
			return flight.err
		}
	}
	flight := &refreshFlight{done: make(chan struct{})}
	s.flights[key] = flight
	s.mu.Unlock()
	err := refresh()
	s.mu.Lock()
	flight.err = err
	delete(s.flights, key)
	close(flight.done)
	s.mu.Unlock()
	return err
}
