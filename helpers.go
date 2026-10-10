package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	"token-mediator/internal/session"
)

// base64 url encoded string of nBytes bytes
func GenerateRandomString(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to read random bytes, err = %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(b)
	return encoded, nil
}

// 32 bytes pixy
func GeneratePKCE() (verifier, challenge string, err error) {
	// go allows you to name return values, these values above
	// are already declared, hence you do a = based assignment
	// instead of a := like declaration
	verifier, err = GenerateRandomString(32)
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

// writes the cookies to http response
func setSessionCookie(w http.ResponseWriter, id session.ID) {

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    string(id),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
