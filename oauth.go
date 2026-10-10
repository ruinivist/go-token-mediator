package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==== models ====

// gh uses this, and the standard speicifies the shape as well
// https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
// I believe any OAuth compliant provider will work with this
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	// why ptr? to distinguish an ommission leading to 0 default
	// vs an actual 0 response
	// with a ptr it'll be nil
	ExpiresIn    *int64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`

	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// ==== funcs ====

// OAUthUrl the client will redirect the user to
func (p *ProviderConfig) BuildAuthUrl(state, challenge string) string {
	params := url.Values{}
	// now the 7 fields they need
	params.Set("client_id", p.ClientId)
	params.Set("redirect_uri", p.RedirectUrl)
	params.Set("response_type", "code")
	params.Set("state", state)
	params.Set("code_challenge", challenge)
	params.Set("code_challenge_method", "S256")

	if len(p.Scopes) > 0 {
		params.Set("scope", strings.Join(p.Scopes, " "))
	}

	return p.AuthUrl + "?" + params.Encode()
}

// POSTs to token url with code and it's verifier to get access tokens
// along with the parent context to handle cancellations
func (p *ProviderConfig) FetchAccessToken(code, verifier string, ctx context.Context) (*TokenResponse, error) {
	/*
		encoding is encoding for the post body
		it can be "form-encoding" or "json"
		OAuth standard explicitly suggest using a form encoding with UTF8-chars
		send in the request body
		though in general providers often have support for json encoding if you
		set the content type as that
	*/

	// id + secret for proving this backend is the right one
	// code + verifier is to match THAT user's auth
	// redirect_uri is kinda redundant, it doesn't redirect to anything at this
	// step but is just a consistency check of sorts ( and the standard
	// requires that you MUST send it if you sent is initially, in the BuildAuthUrl
	// above )

	form := url.Values{}
	form.Set("client_id", p.ClientId)
	form.Set("client_secret", p.ClientSecret)
	form.Set("redirect_uri", p.RedirectUrl)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	// this is fixed for the code + pkce flow we have here
	form.Set("grant_type", "authorization_code")

	body := strings.NewReader((form.Encode()))

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		p.TokenUrl,
		body,
	)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// do the post
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// decode response to struct
	var result TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if resp.StatusCode == 400 {
		// https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
		return nil, errors.New(result.ErrorCode)
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("unknown error")
	}

	return &result, nil
}
