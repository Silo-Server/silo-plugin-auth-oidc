package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryURLKeepsIssuerExact(t *testing.T) {
	tests := map[string]string{
		"https://auth.example/application/o/silo/": "https://auth.example/application/o/silo/.well-known/openid-configuration",
		"https://kc.example/realms/silo":           "https://kc.example/realms/silo/.well-known/openid-configuration",
		"https://idp.example":                      "https://idp.example/.well-known/openid-configuration",
	}
	for issuer, want := range tests {
		if got := DiscoveryURL(issuer); got != want {
			t.Errorf("DiscoveryURL(%q) = %q, want %q", issuer, got, want)
		}
	}
}

func TestValidateDiscovery(t *testing.T) {
	good := Discovery{
		Issuer:                "https://idp.example/",
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
		JWKSURI:               "https://idp.example/jwks",
	}
	if err := ValidateDiscovery(&good, "https://idp.example/"); err != nil {
		t.Fatalf("valid document: %v", err)
	}
	if err := ValidateDiscovery(&good, "https://idp.example"); !errors.Is(err, ErrConfig) {
		t.Errorf("slash-normalized issuer accepted: %v", err)
	}
	insecure := good
	insecure.TokenEndpoint = "http://idp.example/token"
	if err := ValidateDiscovery(&insecure, good.Issuer); !errors.Is(err, ErrConfig) {
		t.Errorf("http token endpoint accepted: %v", err)
	}
	noUserinfoHTTPS := good
	noUserinfoHTTPS.UserinfoEndpoint = "http://idp.example/userinfo"
	if err := ValidateDiscovery(&noUserinfoHTTPS, good.Issuer); !errors.Is(err, ErrConfig) {
		t.Errorf("http userinfo endpoint accepted: %v", err)
	}
}

func TestNewClientRejectsUnsafeSettings(t *testing.T) {
	for name, settings := range map[string]Settings{
		"http issuer":     {Issuer: "http://idp.example", ClientID: "c"},
		"no client":       {Issuer: "https://idp.example"},
		"unknown method":  {Issuer: "https://idp.example", ClientID: "c", TokenAuthMethod: "none"},
		"hs256 no secret": {Issuer: "https://idp.example", ClientID: "c", AllowHS256: true},
		"hs256 short secret": {Issuer: "https://idp.example", ClientID: "c", AllowHS256: true,
			ClientSecret: strings.Repeat("s", MinHS256SecretBytes-1)},
		"garbage CA":      {Issuer: "https://idp.example", ClientID: "c", CAPEM: "nope"},
		"relative issuer": {Issuer: "idp.example", ClientID: "c"},
	} {
		if _, err := NewClient(settings); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err = %v, want ErrConfig", name, err)
		}
	}
}

func TestS256Challenge(t *testing.T) {
	// RFC 7636 appendix B.
	if got := S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Errorf("S256Challenge = %q", got)
	}
}

func TestTokenResponseScopeAndExpiry(t *testing.T) {
	jwt := func(payload string) string {
		return "eyJhbGciOiJIUzUxMiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name        string
		body        string
		offline     bool
		wantExpires time.Time
	}{
		{"scope granted", `{"refresh_token":"rt","scope":"openid offline_access"}`, true, time.Time{}},
		{"scope refused", `{"refresh_token":"rt","scope":"openid profile"}`, false, time.Time{}},
		{"scope omitted (Zitadel)", `{"refresh_token":"rt"}`, true, time.Time{}},
		{"scope of the wrong type is ignored", `{"refresh_token":"rt","scope":["openid"]}`, true, time.Time{}},
		{"refresh_expires_in", `{"refresh_token":"rt","refresh_expires_in":1800}`, true, now.Add(30 * time.Minute)},
		{"refresh_expires_in as a string", `{"refresh_token":"rt","refresh_expires_in":"60"}`, true, now.Add(time.Minute)},
		{"Keycloak offline token: 0 means no expiry", `{"refresh_token":"rt","refresh_expires_in":0}`, true, time.Time{}},
		{"JWT refresh token exp", `{"refresh_token":"` + jwt(`{"exp":1800000600}`) + `"}`, true, time.Unix(1_800_000_600, 0)},
		{"JWT refresh token without exp", `{"refresh_token":"` + jwt(`{"typ":"Offline"}`) + `"}`, true, time.Time{}},
		{"no refresh token", `{"refresh_expires_in":1800}`, true, time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var token TokenResponse
			if err := json.Unmarshal([]byte(tt.body), &token); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := token.GrantsScope("offline_access"); got != tt.offline {
				t.Errorf("GrantsScope = %v, want %v", got, tt.offline)
			}
			if got := token.RefreshExpiry(now); !got.Equal(tt.wantExpires) {
				t.Errorf("RefreshExpiry = %v, want %v", got, tt.wantExpires)
			}
		})
	}
}

func TestErrSubjectMismatchIsInvalidToken(t *testing.T) {
	if !errors.Is(ErrSubjectMismatch, ErrInvalidToken) {
		t.Fatal("ErrSubjectMismatch must wrap ErrInvalidToken so sign-in still refuses it")
	}
}
