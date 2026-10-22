// This file owns per-IP request counters and local Caddy client address handling.
// OAuth route middleware uses it before accessing sessions or contacting providers.
package mediator

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- Request counters ----------

type rateLimiter struct {
	mu      sync.Mutex
	counts  map[netip.Addr]int
	resetAt time.Time
	limit   int
	maxIPs  int
}

func newRateLimiter(limit, maxIPs int) *rateLimiter {
	return &rateLimiter{counts: make(map[netip.Addr]int), limit: limit, maxIPs: maxIPs}
}

// allow returns zero on admission, or the delay until the shared window resets.
// OAuth middleware supplies the current time; tests can exercise expiry without waiting.
func (l *rateLimiter) allow(ip netip.Addr, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	// shortcut: fixed windows allow boundary bursts, use a token bucket if smoother admission is needed.
	if !now.Before(l.resetAt) {
		clear(l.counts)
		l.resetAt = now.Add(time.Minute)
	}
	count := l.counts[ip]
	if count >= l.limit || (count == 0 && len(l.counts) >= l.maxIPs) {
		return l.resetAt.Sub(now)
	}
	l.counts[ip] = count + 1
	return 0
}

// ---------- HTTP middleware ----------

func (s *Server) rateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, ok := clientIP(r)
		if !ok {
			writeJSONError(w, "invalid_request", http.StatusBadRequest)
			return
		}
		if wait := s.limiter.allow(ip, time.Now()); wait > 0 {
			seconds := int64((wait + time.Second - 1) / time.Second)
			w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
			writeJSONError(w, "rate_limited", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

// ---------- Client addresses ----------

// clientIP accepts one client address from local Caddy, or the direct peer's IP.
// Configuration keeps the listener on loopback so external clients must go through Caddy.
func clientIP(r *http.Request) (netip.Addr, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	ip := peer.Addr().WithZone("").Unmap()
	forwarded := r.Header.Values("X-Forwarded-For")
	if !ip.IsLoopback() || len(forwarded) == 0 {
		return ip, true
	}
	if len(forwarded) != 1 {
		return netip.Addr{}, false
	}
	ip, err = netip.ParseAddr(strings.TrimSpace(forwarded[0]))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}
