package main

import (
	"net/url"
	"strings"
)

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
