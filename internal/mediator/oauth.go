package mediator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==== models ====

// gh uses this, and the standard speicifies the shape as well
// https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
// I believe any OAuth compliant provider will work with this
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	// the spec guarantees token_type but fine to keep it optionalish here
	TokenType *string `json:"token_type"`
	// why ptr? to distinguish an ommission leading to 0 default
	// vs an actual 0 response
	// with a ptr it'll be nil
	ExpiresIn    *int64  `json:"expires_in"`
	RefreshToken *string `json:"refresh_token"`
	Scope        *string `json:"scope"`

	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// ==== funcs ====

// OAUthUrl the client will redirect the user to
func (p *ProviderConfig) buildAuthUrl(state, challenge string) string {
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
func (p *ProviderConfig) fetchAccessToken(code, verifier string, ctx context.Context) (*tokenResponse, error) {
	// code + verifier is to match THAT user's auth
	// redirect_uri is kinda redundant, it doesn't redirect to anything at this
	// step but is just a consistency check of sorts ( and the standard
	// requires that you MUST send it if you sent is initially, in the buildAuthUrl
	// above )
	form := url.Values{
		// this is fixed for the code + pkce flow we have here
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.RedirectUrl},
		"code":          {code},
		"code_verifier": {verifier},
	}
	return p.requestToken(ctx, form)
}

func (p *ProviderConfig) refreshAccessToken(ctx context.Context, refreshToken string) (*tokenResponse, error) {
	return p.requestToken(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	})
}

// tokenError separates explicit rejection from a possibly consumed rotating token.
// The refresh handler uses it to decide whether the connection can be retained.
type tokenError struct {
	code      string
	uncertain bool
	cause     error
}

func (e *tokenError) Error() string { return "provider token request failed" }
func (e *tokenError) Unwrap() error { return e.cause }

func (p *ProviderConfig) requestToken(ctx context.Context, form url.Values) (*tokenResponse, error) {
	/*
		encoding is encoding for the post body
		it can be "form-encoding" or "json"
		OAuth standard explicitly suggest using a form encoding with UTF8-chars
		send in the request body
		though in general providers often have support for json encoding if you
		set the content type as that
	*/

	// id + secret for proving this backend is the right one
	form.Set("client_id", p.ClientId)
	form.Set("client_secret", p.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.TokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &tokenError{cause: err}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// do the post
	client := &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &tokenError{cause: err, uncertain: true}
	}
	defer resp.Body.Close()

	const maxResponseBytes = 64 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, &tokenError{cause: err, uncertain: resp.StatusCode == http.StatusOK}
	}
	// decode response to struct
	var result *tokenResponse
	if len(body) > maxResponseBytes || json.Unmarshal(body, &result) != nil || result == nil {
		return nil, &tokenError{uncertain: resp.StatusCode == http.StatusOK}
	}
	if result.ErrorCode != "" || resp.StatusCode != http.StatusOK {
		// https://www.rfc-editor.org/rfc/rfc6749.html#section-5.1
		return nil, &tokenError{code: result.ErrorCode}
	}
	if result.AccessToken == "" ||
		(result.TokenType != nil && !strings.EqualFold(*result.TokenType, "Bearer")) ||
		(result.RefreshToken != nil && *result.RefreshToken == "") ||
		(result.ExpiresIn != nil && (*result.ExpiresIn <= 0 || *result.ExpiresIn > math.MaxInt64/int64(time.Second))) {
		return nil, &tokenError{uncertain: true, cause: errors.New("invalid token response")}
	}
	return result, nil
}
