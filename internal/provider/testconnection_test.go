package provider

import (
	"context"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidctest"
)

func runTest(t *testing.T, p *Provider, cfg settings) *pluginv1.AuthTestConnectionResponse {
	t.Helper()
	resp, err := p.TestConnection(context.Background(), &pluginv1.AuthTestConnectionRequest{Config: cfg.entries(t)})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	return resp
}

func stepIDs(resp *pluginv1.AuthTestConnectionResponse) []string {
	var ids []string
	for _, step := range resp.GetSteps() {
		ids = append(ids, step.GetId())
	}
	return ids
}

func stepsByID(resp *pluginv1.AuthTestConnectionResponse) map[string]*pluginv1.AuthTestStep {
	byID := map[string]*pluginv1.AuthTestStep{}
	for _, step := range resp.GetSteps() {
		byID[step.GetId()] = step
	}
	return byID
}

func lastStep(resp *pluginv1.AuthTestConnectionResponse) *pluginv1.AuthTestStep {
	return resp.GetSteps()[len(resp.GetSteps())-1]
}

func TestTestConnectionHappyPath(t *testing.T) {
	idp := newIdP(t)
	p := New(nil) // running config stays empty; the staged config is tested
	cfg := baseSettings(idp)
	cfg.connection["provider_logout"] = true
	resp := runTest(t, p, cfg)
	if !resp.GetOk() {
		t.Fatalf("connection test failed: %+v", resp.GetSteps())
	}
	want := []string{stepSettings, stepDiscovery, stepIssuer, stepEndpoints, stepJWKS, stepClientAuth, stepClient, stepPKCE, stepScopes, stepLogout}
	if got := stepIDs(resp); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("steps = %v, want %v", got, want)
	}
	for _, step := range resp.GetSteps() {
		if step.GetLabel() == "" || step.GetMessage() == "" {
			t.Errorf("step %s lacks label or message", step.GetId())
		}
		if strings.Contains(step.GetMessage(), idp.ClientSecret) {
			t.Errorf("step %s echoes the client secret", step.GetId())
		}
	}
	steps := stepsByID(resp)
	if !strings.Contains(steps[stepClient].GetMessage(), "accepted the client ID and secret") {
		t.Errorf("client credentials message = %q", steps[stepClient].GetMessage())
	}
	if !strings.Contains(steps[stepLogout].GetMessage(), "post-logout redirect URI") {
		t.Errorf("logout message = %q, want the post-logout redirect reminder", steps[stepLogout].GetMessage())
	}

	// Nothing was persisted: the running configuration is still empty.
	if _, cfg, err := p.clientForTest(); err == nil || cfg.Issuer != "" {
		t.Fatalf("TestConnection changed the running configuration")
	}
}

func TestTestConnectionFailures(t *testing.T) {
	tests := []struct {
		name     string
		edit     func(idp *oidctest.IdP, cfg settings)
		failStep string
		message  string
	}{
		{
			name:     "missing issuer",
			edit:     func(_ *oidctest.IdP, cfg settings) { delete(cfg.connection, "issuer_url") },
			failStep: stepSettings, message: "Issuer URL is not set",
		},
		{
			name:     "http issuer",
			edit:     func(_ *oidctest.IdP, cfg settings) { cfg.connection["issuer_url"] = "http://idp.example" },
			failStep: stepSettings, message: "https",
		},
		{
			name:     "bad CA",
			edit:     func(_ *oidctest.IdP, cfg settings) { cfg.connection["ca_pem"] = "not a certificate" },
			failStep: stepSettings, message: "PEM",
		},
		{
			name:     "untrusted certificate",
			edit:     func(_ *oidctest.IdP, cfg settings) { delete(cfg.connection, "ca_pem") },
			failStep: stepDiscovery, message: "certificate",
		},
		{
			name:     "issuer trailing slash differs",
			edit:     func(idp *oidctest.IdP, cfg settings) { cfg.connection["issuer_url"] = idp.Issuer + "/" },
			failStep: stepIssuer, message: "trailing slash",
		},
		{
			name: "HS256 only without opt-in",
			edit: func(idp *oidctest.IdP, _ settings) {
				idp.Set(func(idp *oidctest.IdP) { idp.HS256 = true })
			},
			failStep: stepJWKS, message: "Allow HS256",
		},
		{
			name: "auth method not supported",
			edit: func(idp *oidctest.IdP, _ settings) {
				idp.Set(func(idp *oidctest.IdP) {
					idp.MutateDiscovery = func(doc map[string]any) {
						doc["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
					}
				})
			},
			failStep: stepClientAuth, message: "client_secret_basic",
		},
		{
			name: "HS256 with a short secret",
			edit: func(_ *oidctest.IdP, cfg settings) {
				cfg.connection["allow_hs256"] = true
				cfg.connection["client_secret"] = "only-sixteen-byt"
			},
			failStep: stepSettings, message: "at least 32 bytes",
		},
		{
			name:     "wrong client secret",
			edit:     func(_ *oidctest.IdP, cfg settings) { cfg.connection["client_secret"] = "wrong" },
			failStep: stepClient, message: "invalid_client",
		},
		{
			name: "PKCE plain only",
			edit: func(idp *oidctest.IdP, _ settings) {
				idp.Set(func(idp *oidctest.IdP) {
					idp.MutateDiscovery = func(doc map[string]any) { doc["code_challenge_methods_supported"] = []string{"plain"} }
				})
			},
			failStep: stepPKCE, message: "S256",
		},
		{
			name: "missing jwks_uri",
			edit: func(idp *oidctest.IdP, _ settings) {
				idp.Set(func(idp *oidctest.IdP) {
					idp.MutateDiscovery = func(doc map[string]any) { delete(doc, "jwks_uri") }
				})
			},
			failStep: stepEndpoints, message: "jwks_uri",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			cfg := baseSettings(idp)
			tt.edit(idp, cfg)
			resp := runTest(t, New(nil), cfg)
			if resp.GetOk() {
				t.Fatalf("connection test passed; want failure at %s", tt.failStep)
			}
			last := lastStep(resp)
			if last.GetOk() || last.GetId() != tt.failStep {
				t.Fatalf("last step = %s ok=%v (%s), want failed %s", last.GetId(), last.GetOk(), last.GetMessage(), tt.failStep)
			}
			if !strings.Contains(last.GetMessage(), tt.message) {
				t.Errorf("message %q does not mention %q", last.GetMessage(), tt.message)
			}
		})
	}
}

func TestTestConnectionIssuerMismatchHint(t *testing.T) {
	idp := newIdP(t, oidctest.WithIssuerSuffix("/application/o/silo/"))
	cfg := baseSettings(idp)
	// Both forms reach the same discovery URL, but the reported issuer keeps
	// its slash, so the slash-less setting must fail.
	cfg.connection["issuer_url"] = strings.TrimSuffix(idp.Issuer, "/")
	resp := runTest(t, New(nil), cfg)
	last := lastStep(resp)
	if last.GetId() != stepIssuer || last.GetOk() || !strings.Contains(last.GetMessage(), "trailing slash") {
		t.Fatalf("last step = %+v, want an issuer mismatch mentioning the trailing slash", last)
	}
}

// The offline-access note must match how CheckAccount reads a refused
// refresh token.
func TestTestConnectionRefreshLifetimeNote(t *testing.T) {
	idp := newIdP(t)
	scopes := func(cfg settings) string {
		t.Helper()
		resp := runTest(t, New(nil), cfg)
		if !resp.GetOk() {
			t.Fatalf("connection test failed: %+v", resp.GetSteps())
		}
		return stepsByID(resp)[stepScopes].GetMessage()
	}
	common := "signs the person out of Silo only while the token is known to be inside its lifetime"

	blank := scopes(baseSettings(idp))
	for _, want := range []string{common, "Refresh token lifetime is blank", "Offline Session Max Limited", "Offline Session Idle"} {
		if !strings.Contains(blank, want) {
			t.Errorf("scopes message with the lifetime blank = %q, want %q", blank, want)
		}
	}
	set := scopes(withLifetime(baseSettings(idp), "30d"))
	for _, want := range []string{common, "Refresh token lifetime is 30d, so a refusal within it counts as a revocation."} {
		if !strings.Contains(set, want) {
			t.Errorf("scopes message with the lifetime set = %q, want %q", set, want)
		}
	}
	if strings.Contains(set, "is blank") || strings.Contains(set, "Offline Session Max Limited") {
		t.Errorf("scopes message with the lifetime set still asks for it: %q", set)
	}
}

func TestTestConnectionScopeWarnings(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) {
		idp.MutateDiscovery = func(doc map[string]any) {
			doc["scopes_supported"] = []string{"openid", "profile", "email"}
			delete(doc, "end_session_endpoint")
		}
	})
	cfg := baseSettings(idp)
	cfg.connection["provider_logout"] = true
	resp := runTest(t, New(nil), cfg)
	if !resp.GetOk() {
		t.Fatalf("warnings must not fail the test: %+v", resp.GetSteps())
	}
	byID := stepsByID(resp)
	if !strings.Contains(byID[stepScopes].GetMessage(), "offline_access") {
		t.Errorf("scopes message = %q", byID[stepScopes].GetMessage())
	}
	// Silo's hourly task re-checks idle accounts, so the advice sizes the
	// lifetime by the re-check interval plus an hour, not by idle time.
	if msg := byID[stepScopes].GetMessage(); !strings.Contains(msg, "re-check interval plus about an hour") || strings.Contains(msg, "idle") {
		t.Errorf("scopes message lifetime advice = %q", msg)
	}
	if !strings.Contains(byID[stepLogout].GetMessage(), "no end_session_endpoint") {
		t.Errorf("logout message = %q", byID[stepLogout].GetMessage())
	}

	cfg.connection["request_offline_access"] = false
	byID = stepsByID(runTest(t, New(nil), cfg))
	if !strings.Contains(byID[stepScopes].GetMessage(), "absolute age limit") {
		t.Errorf("scopes message without offline access = %q", byID[stepScopes].GetMessage())
	}
}

func TestTestConnectionClientProbeQuirks(t *testing.T) {
	t.Run("authentik checks the redirect before the code", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.CheckRedirectAsClient = true })
		resp := runTest(t, New(nil), baseSettings(idp))
		if !resp.GetOk() {
			t.Fatalf("good credentials failed: %+v", resp.GetSteps())
		}
	})
	t.Run("keycloak answers 401 unauthorized_client", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.BadClientStatus, idp.BadClientError = 401, "unauthorized_client" })
		cfg := baseSettings(idp)
		cfg.connection["client_secret"] = "wrong"
		resp := runTest(t, New(nil), cfg)
		if last := lastStep(resp); resp.GetOk() || last.GetId() != stepClient || !strings.Contains(last.GetMessage(), "unauthorized_client") {
			t.Fatalf("bad secret not reported: %+v", resp.GetSteps())
		}
	})
	t.Run("zitadel answers 400 invalid_client", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.BadClientStatus, idp.BadClientError = 400, "invalid_client" })
		cfg := baseSettings(idp)
		cfg.connection["client_secret"] = "wrong"
		if resp := runTest(t, New(nil), cfg); resp.GetOk() {
			t.Fatal("bad secret passed")
		}
	})
}
