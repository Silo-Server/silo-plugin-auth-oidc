package oidc

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	withPAR := good
	withPAR.PushedAuthorizationRequestEndpoint = "https://idp.example/par"
	if err := ValidateDiscovery(&withPAR, good.Issuer); err != nil {
		t.Fatalf("valid PAR discovery: %v", err)
	}
	noPARHTTPS := good
	noPARHTTPS.PushedAuthorizationRequestEndpoint = "http://idp.example/par"
	if err := ValidateDiscovery(&noPARHTTPS, good.Issuer); !errors.Is(err, ErrConfig) {
		t.Errorf("http PAR endpoint accepted: %v", err)
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

func TestPushAuth(t *testing.T) {
	var status int
	var body string
	var gotForm url.Values
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotForm = r.PostForm
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	cert, _ := x509.ParseCertificate(srv.Certificate().Raw)
	if cert == nil {
		t.Fatal("failed to parse test cert")
	}
	client, err := NewClient(Settings{
		Issuer:       srv.URL,
		ClientID:     "silo",
		ClientSecret: "secret",
		CAPEM:        caPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	doc := &Discovery{
		Issuer:                             srv.URL,
		AuthorizationEndpoint:              srv.URL + "/authorize?acr=1",
		TokenEndpoint:                      srv.URL + "/token",
		JWKSURI:                            srv.URL + "/jwks",
		PushedAuthorizationRequestEndpoint: srv.URL + "/par",
	}
	req := AuthRequest{
		RedirectURI:   "https://silo.example/cb",
		State:         "st",
		Nonce:         "nn",
		CodeChallenge: "cc",
		Scopes:        []string{"openid", "profile"},
		Prompt:        "login",
		LoginHint:     "alice@example.com",
	}

	status, body = http.StatusCreated, `{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":90}`
	authURL, err := client.PushAuth(context.Background(), doc, req)
	if err != nil {
		t.Fatalf("PushAuth: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") || gotForm.Get("client_secret") != "" {
		t.Errorf("auth = %q, form secret = %q", gotAuth, gotForm.Get("client_secret"))
	}
	if gotForm.Get("code_challenge_method") != "S256" || gotForm.Get("nonce") != "nn" || gotForm.Get("login_hint") != "alice@example.com" {
		t.Errorf("PAR form = %v", gotForm)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("client_id") != "silo" || q.Get("request_uri") != "urn:ietf:params:oauth:request_uri:abc" || q.Get("acr") != "1" {
		t.Errorf("authorize query = %v", q)
	}
	for _, stripped := range []string{"redirect_uri", "state", "nonce", "code_challenge", "scope", "prompt", "login_hint"} {
		if q.Has(stripped) {
			t.Errorf("authorize query should not carry %q when using PAR", stripped)
		}
	}

	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"missing request_uri", http.StatusCreated, `{"expires_in":90}`, ErrConfig},
		{"400 invalid_request", http.StatusBadRequest, `{"error":"invalid_request","error_description":"bad redirect"}`, ErrConfig},
		{"502 server_error", http.StatusBadGateway, `{"error":"server_error"}`, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body = tc.status, tc.body
			if _, err := client.PushAuth(context.Background(), doc, req); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
