package mediator

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
	"token-mediator/internal/session"
)

func writeJSONError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

// allowBrowserOrigin grants credentialed CORS only to the configured frontend.
func (s *Server) allowBrowserOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		w.Header().Set("Cache-Control", "no-store")
		if r.Header.Get("Origin") == "" || r.Header.Get("Origin") != s.cfg.FeOrigin {
			writeJSONError(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", s.cfg.FeOrigin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
		next(w, r)
	}
}

// callbackHeaders protects the callback URL even when middleware rejects the request.
// for example in rate limiting, this is so browsers don't cached anything on such sensitive
// requests
func callbackHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next(w, r)
	}
}

// validateBrowserPost checks the CSRF header and empty JSON body before calling the handler.
func (s *Server) validateBrowserPost(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get("X-OAuth-Bridge") != "1" {
			writeJSONError(w, "forbidden", http.StatusForbidden)
			return
		}

		// Accept application/json, including optional parameters such as charset.
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeJSONError(w, "invalid_request", http.StatusBadRequest)
			return
		}

		// Limit the body to 8 KiB before decoding it.
		r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
		decoder := json.NewDecoder(r.Body)

		// Require an empty object; reject fields, null, and other JSON shapes.
		var body map[string]json.RawMessage
		if err := decoder.Decode(&body); err != nil || body == nil || len(body) != 0 {
			writeJSONError(w, "invalid_request", http.StatusBadRequest)
			return
		}

		// Allow trailing whitespace, but reject another JSON value or extra bytes.
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			writeJSONError(w, "invalid_request", http.StatusBadRequest)
			return
		}

		// Run the route handler only after all checks pass.
		next(w, r)
	}
}

// base64 url encoded string of nBytes bytes
func generateRandomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes, err = %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(b)
	return encoded, nil
}

// 32 bytes pixy
func generatePKCE() (verifier, challenge string, err error) {
	// go allows you to name return values, these values above
	// are already declared, hence you do a = based assignment
	// instead of a := like declaration
	verifier, err = generateRandomString(32)
	if err != nil {
		return "", "", err
	}

	h := sha256.Sum256([]byte(verifier))
	// [32]byte -> []byte via slicing
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return verifier, challenge, nil

	// note on pixy
	// what I send to provider is bas64 encoded, any text string works
	// with 43-128 ascii characters.
	// then the rfc defines challenge as
	// code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	// which is why we sha265 the verifier AFTER encoding ( as that's the )
	// ascii that the provider would see
}

const sessionCookieName = "__Host-oauth_bridge"

func makeCookie(sessionID session.ID, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    string(sessionID),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	}
}
