package provider

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidctest"
)

const testRedirect = "https://silo.example/api/v2/auth/oauth/7/callback"

// settings are the config groups passed to Configure; nil groups are omitted.
type settings struct {
	connection map[string]any
	claims     map[string]any
	access     map[string]any
}

func (s settings) entries(t *testing.T) []*pluginv1.ConfigEntry {
	t.Helper()
	var out []*pluginv1.ConfigEntry
	add := func(key string, value map[string]any) {
		if value == nil {
			return
		}
		st, err := structpb.NewStruct(value)
		if err != nil {
			t.Fatalf("config %s: %v", key, err)
		}
		out = append(out, &pluginv1.ConfigEntry{Key: key, Value: st})
	}
	add(keyConnection, s.connection)
	add(keyClaims, s.claims)
	add(keyAccess, s.access)
	return out
}

func baseSettings(idp *oidctest.IdP) settings {
	return settings{connection: map[string]any{
		"issuer_url":             idp.Issuer,
		"client_id":              idp.ClientID,
		"client_secret":          idp.ClientSecret,
		"ca_pem":                 idp.CAPEM(),
		"request_offline_access": true,
	}}
}

func newIdP(t *testing.T, opts ...oidctest.Option) *oidctest.IdP {
	t.Helper()
	idp := oidctest.New(t, opts...)
	idp.RedirectURIs = []string{testRedirect}
	idp.AddUser("alice", &oidctest.User{
		Subject: "alice-sub",
		IDTokenClaims: map[string]any{
			"preferred_username": "alice", "email": "alice@example.com", "email_verified": true,
			"name": "Alice Liddell", "groups": []any{"silo-users"},
			"picture": "https://img.example/alice.png",
		},
	})
	idp.AddUser("bob", &oidctest.User{
		Subject: "bob-sub",
		IDTokenClaims: map[string]any{
			"preferred_username": "bob", "email": "bob@example.com",
			"groups": []any{"silo-users", "silo-admins"},
		},
	})
	idp.AddUser("carol", &oidctest.User{
		Subject:       "carol-sub",
		IDTokenClaims: map[string]any{"preferred_username": "carol"},
	})
	return idp
}

func newProvider(t *testing.T, cfg settings) *Provider {
	t.Helper()
	return newProviderWithLog(t, cfg, io.Discard)
}

// newProviderWithLog is newProvider with its log written to logs.
func newProviderWithLog(t *testing.T, cfg settings, logs io.Writer) *Provider {
	t.Helper()
	p := New(slog.New(slog.NewTextHandler(logs, nil)))
	if err := p.Configure(context.Background(), cfg.entries(t)); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

type signInResult struct {
	init    *pluginv1.InitAuthorizeResponse
	account *pluginv1.AuthenticateResponse
}

func signIn(t *testing.T, p *Provider, idp *oidctest.IdP, login string) signInResult {
	t.Helper()
	init, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "host-state-" + login})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}
	code, state, err := idp.Login(init.GetAuthorizeUrl(), login)
	if err != nil {
		t.Fatalf("login at IdP: %v", err)
	}
	account, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: state, RedirectUri: testRedirect, ProviderState: init.GetProviderState(),
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	return signInResult{init: init, account: account}
}

func requireAccount(t *testing.T, account *pluginv1.AuthenticateResponse) {
	t.Helper()
	if account.GetDenial() != pluginv1.AuthDenial_AUTH_DENIAL_UNSPECIFIED || account.GetExternalSubject() == "" {
		t.Fatalf("sign-in denied: %s (%s)", account.GetDenial(), account.GetDenialDetail())
	}
}

func requireDenial(t *testing.T, account *pluginv1.AuthenticateResponse, want pluginv1.AuthDenial, detail string) {
	t.Helper()
	if account.GetDenial() != want {
		t.Fatalf("denial = %s (%s), want %s", account.GetDenial(), account.GetDenialDetail(), want)
	}
	if account.GetExternalSubject() != "" {
		t.Fatalf("denial carries external_subject %q; it must be empty", account.GetExternalSubject())
	}
	if detail != "" && !strings.Contains(account.GetDenialDetail(), detail) {
		t.Fatalf("denial detail %q does not mention %q", account.GetDenialDetail(), detail)
	}
}

func TestSignInHappyPath(t *testing.T) {
	idp := newIdP(t)
	cfg := baseSettings(idp)
	cfg.access = map[string]any{"allowed_groups": "silo-users", "admin_groups": "silo-admins"}
	p := newProvider(t, cfg)

	result := signIn(t, p, idp, "alice")
	account := result.account
	requireAccount(t, account)

	if got, want := account.GetExternalSubject(), idp.Issuer+"|alice-sub"; got != want {
		t.Errorf("external_subject = %q, want %q", got, want)
	}
	if account.GetIssuer() != idp.Issuer || account.GetUsername() != "alice" || account.GetEmail() != "alice@example.com" ||
		account.GetDisplayName() != "Alice Liddell" || account.GetPictureUrl() != "https://img.example/alice.png" {
		t.Errorf("unexpected account facts: %+v", account)
	}
	if account.EmailVerified == nil || !account.GetEmailVerified() {
		t.Errorf("email_verified = %v, want true", account.EmailVerified)
	}
	if got := account.GetGroups(); len(got) != 1 || got[0] != "silo-users" {
		t.Errorf("groups = %v", got)
	}
	if account.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Errorf("managed_role = %s, want USER", account.GetManagedRole())
	}
	state := account.GetRefreshState().GetFields()
	if state[refreshToken].GetStringValue() == "" || state[refreshIDToken].GetStringValue() == "" || state[refreshSubject].GetStringValue() != "alice-sub" {
		t.Errorf("refresh_state = %v", account.GetRefreshState())
	}

	// PKCE S256 and nonce went to the IdP; the verifier went to the token endpoint.
	authorize := idp.LastAuthorize().Query
	providerState := result.init.GetProviderState().GetFields()
	verifier := providerState[stateCodeVerifier].GetStringValue()
	if authorize.Get("code_challenge_method") != "S256" || authorize.Get("code_challenge") != oidc.S256Challenge(verifier) {
		t.Errorf("authorize PKCE = %q/%q", authorize.Get("code_challenge_method"), authorize.Get("code_challenge"))
	}
	if authorize.Get("nonce") == "" || authorize.Get("nonce") != providerState[stateNonce].GetStringValue() {
		t.Errorf("authorize nonce = %q", authorize.Get("nonce"))
	}
	if got := authorize.Get("scope"); got != "openid profile email offline_access" {
		t.Errorf("scope = %q", got)
	}
	if authorize.Get("state") != "host-state-alice" || authorize.Get("redirect_uri") != testRedirect {
		t.Errorf("state/redirect = %q/%q", authorize.Get("state"), authorize.Get("redirect_uri"))
	}
	token := idp.LastToken()
	if token.Form.Get("code_verifier") != verifier {
		t.Errorf("token request code_verifier missing")
	}
	if !strings.HasPrefix(token.Authorization, "Basic ") || token.Form.Get("client_secret") != "" {
		t.Errorf("default client auth should be client_secret_basic")
	}
}

func TestSignInAdminGroupsAndAllowedGroups(t *testing.T) {
	idp := newIdP(t)
	cfg := baseSettings(idp)
	cfg.access = map[string]any{"allowed_groups": "silo-users\n", "admin_groups": "silo-admins"}
	p := newProvider(t, cfg)

	bob := signIn(t, p, idp, "bob").account
	requireAccount(t, bob)
	if bob.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Errorf("bob managed_role = %s, want ADMIN", bob.GetManagedRole())
	}
	requireDenial(t, signIn(t, p, idp, "carol").account, pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "allowed group")
}

func TestSignInWithoutGroupRulesLeavesRoleToHost(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	carol := signIn(t, p, idp, "carol").account
	requireAccount(t, carol)
	if carol.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED {
		t.Errorf("managed_role = %s, want UNSPECIFIED", carol.GetManagedRole())
	}
	if carol.EmailVerified != nil {
		t.Errorf("email_verified = %v, want unset", carol.GetEmailVerified())
	}
}

func TestIDTokenValidationFailures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(claims map[string]any)
		detail string
	}{
		{"bad nonce", func(c map[string]any) { c["nonce"] = "attacker-nonce" }, "nonce"},
		{"missing nonce", func(c map[string]any) { delete(c, "nonce") }, "nonce"},
		{"wrong issuer", func(c map[string]any) { c["iss"] = "https://evil.example" }, "iss"},
		{"issuer with extra slash", func(c map[string]any) { c["iss"] = c["iss"].(string) + "/" }, "iss"},
		{"wrong audience", func(c map[string]any) { c["aud"] = "other-client" }, "aud"},
		{"audience list without client", func(c map[string]any) { c["aud"] = []any{"a", "b"} }, "aud"},
		{"foreign azp", func(c map[string]any) { c["aud"] = []any{"silo", "project"}; c["azp"] = "other" }, "azp"},
		{"expired", func(c map[string]any) { c["exp"] = float64(1_000_000) }, "expired"},
		{"missing exp", func(c map[string]any) { delete(c, "exp") }, "exp is missing"},
		{"nbf in the future", func(c map[string]any) { c["nbf"] = float64(9_999_999_999) }, "not valid yet"},
		{"iat in the future", func(c map[string]any) { c["iat"] = float64(9_999_999_999) }, "iat"},
		{"missing iat", func(c map[string]any) { delete(c, "iat") }, "iat"},
		{"missing sub", func(c map[string]any) { c["sub"] = "" }, "sub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.MutateIDToken = tt.mutate })
			p := newProvider(t, baseSettings(idp))
			requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, tt.detail)
		})
	}
}

func TestAudienceListWithMatchingAZP(t *testing.T) {
	// Zitadel puts the client and project IDs in aud.
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) {
		idp.MutateIDToken = func(c map[string]any) { c["aud"] = []any{"silo", "123456"}; c["azp"] = "silo" }
	})
	p := newProvider(t, baseSettings(idp))
	requireAccount(t, signIn(t, p, idp, "alice").account)
}

func TestSignatureAlgorithms(t *testing.T) {
	for _, alg := range []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	} {
		t.Run(string(alg), func(t *testing.T) {
			idp := newIdP(t, oidctest.WithAlgorithm(alg))
			p := newProvider(t, baseSettings(idp))
			requireAccount(t, signIn(t, p, idp, "alice").account)
		})
	}
}

func TestHS256RefusedByDefault(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.HS256 = true })
	p := newProvider(t, baseSettings(idp))
	requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "id_token")

	cfg := baseSettings(idp)
	cfg.connection["allow_hs256"] = true
	p = newProvider(t, cfg)
	requireAccount(t, signIn(t, p, idp, "alice").account)
}

func TestTamperedSignatureRejected(t *testing.T) {
	for _, tt := range []struct {
		name  string
		hs256 bool
	}{
		{"foreign key under the current kid", false},
		{"HS256 with the wrong secret", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.HS256 = tt.hs256 })
			cfg := baseSettings(idp)
			cfg.connection["allow_hs256"] = tt.hs256
			p := newProvider(t, cfg)
			client, _, err := p.clientForTest()
			if err != nil {
				t.Fatal(err)
			}
			// A token that passes every other check, so only the signature
			// check can refuse it.
			now := time.Now()
			claims := map[string]any{
				"iss": idp.Issuer, "sub": "alice-sub", "aud": idp.ClientID, "nonce": "n",
				"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
			}
			expect := oidc.Expectations{Nonce: "n", CheckNonce: true}
			if _, err := client.VerifyIDToken(context.Background(), idp.Sign(claims), expect); err != nil {
				t.Fatalf("control token rejected: %v", err)
			}
			idp.Set(func(idp *oidctest.IdP) { idp.SignWithForeignKey = true })
			_, err = client.VerifyIDToken(context.Background(), idp.Sign(claims), expect)
			if !errors.Is(err, oidc.ErrInvalidToken) || !strings.Contains(err.Error(), "signature") {
				t.Fatalf("forged signature: err = %v, want an invalid token signature error", err)
			}

			// The full sign-in refuses it too.
			requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "signature")
		})
	}
}

func TestKeyRotationRefetchesJWKS(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	requireAccount(t, signIn(t, p, idp, "alice").account)
	if jwks, _ := idp.Counts(); jwks != 1 {
		t.Fatalf("JWKS fetched %d times, want 1", jwks)
	}
	requireAccount(t, signIn(t, p, idp, "alice").account)
	if jwks, _ := idp.Counts(); jwks != 1 {
		t.Fatalf("JWKS fetched %d times with a known kid, want cache hit", jwks)
	}

	idp.RotateKey(jose.ES256)
	requireAccount(t, signIn(t, p, idp, "alice").account)
	if jwks, _ := idp.Counts(); jwks != 2 {
		t.Fatalf("JWKS fetched %d times after rotation, want 2", jwks)
	}

	// A second unknown kid right away is rate limited: no extra fetch.
	idp.RotateKey(jose.RS256)
	requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "kid")
	if jwks, _ := idp.Counts(); jwks != 2 {
		t.Fatalf("JWKS fetched %d times, want the refresh rate limited", jwks)
	}
}

func TestUserinfoOnlyClaims(t *testing.T) {
	// Authelia 4.39 puts profile, email and groups only in userinfo.
	idp := newIdP(t)
	idp.AddUser("dave", &oidctest.User{
		Subject: "dave-sub",
		UserinfoClaims: map[string]any{
			"preferred_username": "dave", "email": "dave@example.com", "email_verified": true,
			"name": "Dave", "groups": []any{"silo-users"},
			// Userinfo must not override protected claims.
			"iss": "https://evil.example", "tid": "evil",
		},
	})
	cfg := baseSettings(idp)
	cfg.connection["request_groups_scope"] = true
	cfg.access = map[string]any{"allowed_groups": "silo-users"}
	p := newProvider(t, cfg)
	account := signIn(t, p, idp, "dave").account
	requireAccount(t, account)
	if account.GetUsername() != "dave" || account.GetEmail() != "dave@example.com" || account.GetDisplayName() != "Dave" {
		t.Errorf("userinfo claims not merged: %+v", account)
	}
	if account.GetExternalSubject() != idp.Issuer+"|dave-sub" || account.GetIssuer() != idp.Issuer {
		t.Errorf("userinfo overrode the issuer: %q", account.GetExternalSubject())
	}
	if !strings.Contains(idp.LastAuthorize().Query.Get("scope"), "groups") {
		t.Errorf("groups scope not requested")
	}
	if _, hits := idp.Counts(); hits != 1 {
		t.Errorf("userinfo hits = %d, want 1", hits)
	}
}

func TestSignedUserinfo(t *testing.T) {
	idp := newIdP(t)
	idp.AddUser("dave", &oidctest.User{Subject: "dave-sub", UserinfoClaims: map[string]any{"email": "dave@example.com"}})
	idp.Set(func(idp *oidctest.IdP) { idp.SignedUserinfo = true })
	p := newProvider(t, baseSettings(idp))
	account := signIn(t, p, idp, "dave").account
	requireAccount(t, account)
	if account.GetEmail() != "dave@example.com" {
		t.Errorf("email = %q", account.GetEmail())
	}
}

func TestUserinfoSubjectMismatch(t *testing.T) {
	idp := newIdP(t)
	idp.AddUser("mallory", &oidctest.User{Subject: "mallory-sub", UserinfoClaims: map[string]any{"sub": "alice-sub"}})
	p := newProvider(t, baseSettings(idp))
	requireDenial(t, signIn(t, p, idp, "mallory").account, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "userinfo")
}

func TestUserinfoFailureIsProviderUnavailable(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.UserinfoStatus = 502 })
	p := newProvider(t, baseSettings(idp))
	requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "userinfo")
}

func TestGroupClaimShapesEndToEnd(t *testing.T) {
	tests := []struct {
		name    string
		claims  map[string]any
		groups  string
		allowed string
		admin   string
		want    pluginv1.AuthManagedRole
	}{
		{
			name:   "keycloak full paths",
			claims: map[string]any{"groups": []any{"/silo-users", "/silo-admins"}},
			groups: "groups", allowed: "silo-users", admin: "/silo-admins",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN,
		},
		{
			name: "kanidm spn and uuid",
			claims: map[string]any{"groups": []any{
				"00000000-0000-0000-0000-000000000035", "idm_all_persons@idm.example",
				"4b6a1c1e-0000-0000-0000-000000000001", "silo-users@idm.example",
			}},
			groups: "groups", allowed: "silo-users", admin: "silo-admins",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER,
		},
		{
			name:   "kanidm groups_name",
			claims: map[string]any{"groups_name": []any{"silo-users", "silo-admins"}},
			groups: "groups_name", allowed: "silo-users", admin: "silo-admins",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN,
		},
		{
			name: "zitadel project roles object",
			claims: map[string]any{"urn:zitadel:iam:org:project:roles": map[string]any{
				"silo-admins": map[string]any{"123": "silolab.example"},
				"silo-users":  map[string]any{"123": "silolab.example"},
			}},
			groups: "urn:zitadel:iam:org:project:roles", allowed: "silo-users", admin: "silo-admins",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN,
		},
		{
			name:   "nested roles path",
			claims: map[string]any{"realm_access": map[string]any{"roles": []any{"silo-users"}}},
			groups: "realm_access.roles", allowed: "silo-users", admin: "silo-admins",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER,
		},
		{
			name:   "entra group GUIDs",
			claims: map[string]any{"groups": []any{"8f2c1b1e-1111-4a4a-9c9c-000000000001"}},
			groups: "groups", allowed: "8f2c1b1e-1111-4a4a-9c9c-000000000001", admin: "8f2c1b1e-1111-4a4a-9c9c-000000000002",
			want: pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			idp.AddUser("erin", &oidctest.User{Subject: "erin-sub", UserinfoClaims: tt.claims})
			cfg := baseSettings(idp)
			cfg.claims = map[string]any{"groups": tt.groups}
			cfg.access = map[string]any{"allowed_groups": tt.allowed, "admin_groups": tt.admin}
			p := newProvider(t, cfg)
			account := signIn(t, p, idp, "erin").account
			requireAccount(t, account)
			if account.GetManagedRole() != tt.want {
				t.Errorf("managed_role = %s, want %s (groups %v)", account.GetManagedRole(), tt.want, account.GetGroups())
			}
		})
	}
}

func TestEmailVerifiedTriState(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  *bool
	}{
		{"true", true, ptr(true)},
		{"false (authentik)", false, ptr(false)},
		{"string false", "false", ptr(false)},
		{"missing", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			claims := map[string]any{"email": "erin@example.com"}
			if tt.value != nil {
				claims["email_verified"] = tt.value
			}
			idp.AddUser("erin", &oidctest.User{Subject: "erin-sub", IDTokenClaims: claims})
			p := newProvider(t, baseSettings(idp))
			account := signIn(t, p, idp, "erin").account
			requireAccount(t, account)
			switch {
			case tt.want == nil && account.EmailVerified != nil:
				t.Errorf("email_verified = %v, want unset", account.GetEmailVerified())
			case tt.want != nil && (account.EmailVerified == nil || account.GetEmailVerified() != *tt.want):
				t.Errorf("email_verified = %v, want %v", account.EmailVerified, *tt.want)
			}
		})
	}
}

func TestEntraSubject(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) {
		idp.MutateIDToken = func(c map[string]any) { c["tid"] = "tenant-1"; c["oid"] = "object-1" }
	})
	cfg := baseSettings(idp)
	cfg.claims = map[string]any{"subject": "entra"}
	p := newProvider(t, cfg)
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	if account.GetExternalSubject() != "tenant-1|object-1" {
		t.Errorf("external_subject = %q, want tenant-1|object-1", account.GetExternalSubject())
	}

	// Automatic mode keeps iss|sub for a non-Microsoft issuer even with tid/oid.
	auto := newProvider(t, baseSettings(idp))
	account = signIn(t, auto, idp, "alice").account
	if account.GetExternalSubject() != idp.Issuer+"|alice-sub" {
		t.Errorf("auto external_subject = %q", account.GetExternalSubject())
	}

	// Entra mode without tid/oid refuses instead of falling back.
	plain := newIdP(t)
	cfg = baseSettings(plain)
	cfg.claims = map[string]any{"subject": "entra"}
	requireDenial(t, signIn(t, newProvider(t, cfg), plain, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "tid")
}

func TestIssuerWithTrailingSlash(t *testing.T) {
	// authentik's issuer ends in a slash; it must be used exactly.
	idp := newIdP(t, oidctest.WithIssuerSuffix("/application/o/silo/"))
	p := newProvider(t, baseSettings(idp))
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	if !strings.HasSuffix(account.GetExternalSubject(), "/application/o/silo/|alice-sub") {
		t.Errorf("external_subject = %q", account.GetExternalSubject())
	}

	cfg := baseSettings(idp)
	cfg.connection["issuer_url"] = strings.TrimSuffix(idp.Issuer, "/")
	_, err := newProvider(t, cfg).InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("issuer without its trailing slash: err = %v, want FailedPrecondition", err)
	}
}

func TestCustomCARequired(t *testing.T) {
	idp := newIdP(t)
	cfg := baseSettings(idp)
	delete(cfg.connection, "ca_pem")
	p := newProvider(t, cfg)
	_, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("untrusted certificate: err = %v, want Unavailable", err)
	}
}

func TestClientSecretPost(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.AuthMethod = "client_secret_post" })
	p := newProvider(t, baseSettings(idp))
	requireDenial(t, signIn(t, p, idp, "alice").account, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "invalid_client")

	cfg := baseSettings(idp)
	cfg.connection["token_endpoint_auth_method"] = "client_secret_post"
	p = newProvider(t, cfg)
	requireAccount(t, signIn(t, p, idp, "alice").account)
	if form := idp.LastToken().Form; form.Get("client_secret") != idp.ClientSecret || idp.LastToken().Authorization != "" {
		t.Errorf("client_secret_post not used")
	}
}

func TestPromptAndLoginHint(t *testing.T) {
	idp := newIdP(t)
	cfg := baseSettings(idp)
	cfg.connection["prompt"] = "select_account"
	p := newProvider(t, cfg)

	init, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s", LoginHint: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	query := mustQuery(t, init.GetAuthorizeUrl())
	if query.Get("prompt") != "select_account" || query.Get("login_hint") != "alice@example.com" {
		t.Errorf("prompt/login_hint = %q/%q", query.Get("prompt"), query.Get("login_hint"))
	}

	init, err = p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s", Prompt: "login"})
	if err != nil {
		t.Fatal(err)
	}
	if got := mustQuery(t, init.GetAuthorizeUrl()).Get("prompt"); got != "login" {
		t.Errorf("request prompt = %q, want login", got)
	}

	_, err = p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s", Prompt: "bogus"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("bogus prompt: err = %v, want InvalidArgument", err)
	}
}

func TestExchangeCodeInputChecks(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	init, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "state-1"})
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := idp.Login(init.GetAuthorizeUrl(), "alice")
	if err != nil {
		t.Fatal(err)
	}

	_, err = p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: code, State: "state-1"})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing provider_state: err = %v, want InvalidArgument", err)
	}
	resp, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: code, State: "state-2", ProviderState: init.GetProviderState()})
	if err != nil {
		t.Fatal(err)
	}
	requireDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "state")

	resp, err = p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: "not-a-code", State: "state-1", ProviderState: init.GetProviderState()})
	if err != nil {
		t.Fatal(err)
	}
	requireDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "invalid_grant")
}

func TestIncompleteConfiguration(t *testing.T) {
	p := New(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := p.Configure(context.Background(), nil); err != nil {
		t.Fatalf("Configure with no entries: %v", err)
	}
	_, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("InitAuthorize: err = %v, want FailedPrecondition", err)
	}
	state, _ := structpb.NewStruct(map[string]any{stateCodeVerifier: "v", stateNonce: "n"})
	resp, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{Code: "c", ProviderState: state})
	if err != nil {
		t.Fatal(err)
	}
	requireDenial(t, resp, pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, "Issuer URL is not set")

	check, err := p.CheckAccount(context.Background(), &pluginv1.CheckAccountRequest{
		ExternalSubject: "x", RefreshState: mustStruct(t, map[string]any{refreshToken: "rt", refreshSubject: "s"}),
	})
	if err != nil || check.GetStatus() != pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE {
		t.Errorf("CheckAccount = %v, %v; want UNAVAILABLE", check.GetStatus(), err)
	}
	end, err := p.EndSessionUrl(context.Background(), &pluginv1.AuthEndSessionUrlRequest{})
	if err != nil || end.GetUrl() != "" {
		t.Errorf("EndSessionUrl = %q, %v; want empty", end.GetUrl(), err)
	}
}

func TestAuthenticatePasswordUnsupported(t *testing.T) {
	p := New(nil)
	_, err := p.Authenticate(context.Background(), &pluginv1.AuthenticateRequest{Username: "a", Password: "b"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Authenticate: err = %v, want Unimplemented", err)
	}
}

func TestEndSessionURL(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	req := &pluginv1.AuthEndSessionUrlRequest{
		ExternalSubject:       account.GetExternalSubject(),
		RefreshState:          account.GetRefreshState(),
		PostLogoutRedirectUri: "https://silo.example/login",
	}
	resp, err := p.EndSessionUrl(context.Background(), req)
	if err != nil || resp.GetUrl() != "" {
		t.Fatalf("provider logout off: url = %q, err = %v; want empty", resp.GetUrl(), err)
	}

	cfg := baseSettings(idp)
	cfg.connection["provider_logout"] = true
	p = newProvider(t, cfg)
	resp, err = p.EndSessionUrl(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	logout, err := url.Parse(resp.GetUrl())
	if err != nil {
		t.Fatal(err)
	}
	query := logout.Query()
	if !strings.HasPrefix(resp.GetUrl(), strings.TrimSuffix(idp.Issuer, "/")+"/logout?") ||
		query.Get("id_token_hint") != account.GetRefreshState().GetFields()[refreshIDToken].GetStringValue() ||
		query.Get("post_logout_redirect_uri") != "https://silo.example/login" || query.Get("client_id") != "silo" {
		t.Errorf("end-session URL = %s", resp.GetUrl())
	}

	// A provider without an end-session endpoint (Authelia) answers empty.
	idp.Set(func(idp *oidctest.IdP) {
		idp.MutateDiscovery = func(doc map[string]any) { delete(doc, "end_session_endpoint") }
	})
	p = newProvider(t, cfg)
	resp, err = p.EndSessionUrl(context.Background(), req)
	if err != nil || resp.GetUrl() != "" {
		t.Errorf("no end_session_endpoint: url = %q, err = %v", resp.GetUrl(), err)
	}
}

func TestInitAuthorizeRequiresRedirectAndState(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	if _, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{State: "s"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing redirect: err = %v", err)
	}
	if _, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing state: err = %v", err)
	}
}

func TestEachAuthorizationUsesFreshPKCEAndNonce(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, baseSettings(idp))
	first, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: "s"})
	if err != nil {
		t.Fatal(err)
	}
	a, b := first.GetProviderState().GetFields(), second.GetProviderState().GetFields()
	if a[stateCodeVerifier].GetStringValue() == b[stateCodeVerifier].GetStringValue() || a[stateNonce].GetStringValue() == b[stateNonce].GetStringValue() {
		t.Fatal("verifier or nonce reused across authorizations")
	}
	if len(a[stateCodeVerifier].GetStringValue()) < 43 {
		t.Fatalf("verifier too short: %d", len(a[stateCodeVerifier].GetStringValue()))
	}
}

func (p *Provider) clientForTest() (*oidc.Client, Config, error) {
	cfg, client, err := p.current()
	return client, cfg, err
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}

func mustStruct(t *testing.T, value map[string]any) *structpb.Struct {
	t.Helper()
	st, err := structpb.NewStruct(value)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func ptr[T any](value T) *T { return &value }
