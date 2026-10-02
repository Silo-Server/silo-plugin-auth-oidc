package provider

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidctest"
)

func checkAccount(t *testing.T, p *Provider, account *pluginv1.AuthenticateResponse) *pluginv1.CheckAccountResponse {
	t.Helper()
	return checkAccountCtx(t, context.Background(), p, account)
}

func checkAccountCtx(t *testing.T, ctx context.Context, p *Provider, account *pluginv1.AuthenticateResponse) *pluginv1.CheckAccountResponse {
	t.Helper()
	resp, err := p.CheckAccount(ctx, &pluginv1.CheckAccountRequest{
		ExternalSubject: account.GetExternalSubject(),
		RefreshState:    account.GetRefreshState(),
	})
	if err != nil {
		t.Fatalf("CheckAccount: %v", err)
	}
	return resp
}

func requireStatus(t *testing.T, resp *pluginv1.CheckAccountResponse, want pluginv1.CheckAccountStatus) {
	t.Helper()
	if resp.GetStatus() != want {
		t.Fatalf("status = %s, want %s", resp.GetStatus(), want)
	}
}

func groupsSettings(idp *oidctest.IdP) settings {
	cfg := baseSettings(idp)
	cfg.access = map[string]any{"allowed_groups": "silo-users", "admin_groups": "silo-admins"}
	return cfg
}

func TestCheckAccountActiveRotatesRefreshToken(t *testing.T) {
	idp := newIdP(t)
	// Keycloak offline tokens: rotated, with refresh_expires_in 0 unless
	// Offline Session Max Limited is on, so the lifetime comes from the
	// setting.
	idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens, idp.ZeroRefreshExpiresIn = true, true })
	p := newProvider(t, withLifetime(groupsSettings(idp), "30d"))
	account := signIn(t, p, idp, "bob").account
	requireAccount(t, account)
	firstRefresh := account.GetRefreshState().GetFields()[refreshToken].GetStringValue()

	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	if resp.GetAccount().GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN {
		t.Errorf("managed_role = %s, want ADMIN", resp.GetAccount().GetManagedRole())
	}
	rotated := resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue()
	if rotated == "" || rotated == firstRefresh {
		t.Fatalf("rotated refresh token not returned")
	}
	if idp.LastToken().Form.Get("grant_type") != "refresh_token" || idp.LastToken().Form.Get("refresh_token") != firstRefresh {
		t.Errorf("refresh grant not sent with the stored token")
	}

	// The spent token is refused now, inside the configured lifetime, which
	// reads as a revocation: the host must use the rotated state.
	stale := checkAccount(t, p, account)
	requireStatus(t, stale, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	account.RefreshState = resp.GetAccount().GetRefreshState()
	requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
}

func TestCheckAccountReappliesGroups(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, groupsSettings(idp))
	account := signIn(t, p, idp, "bob").account
	requireAccount(t, account)

	// Bob leaves silo-admins at the provider: the check demotes him.
	idp.Set(func(idp *oidctest.IdP) { idp.Users["bob"].IDTokenClaims["groups"] = []any{"silo-users"} })
	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	if resp.GetAccount().GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Errorf("managed_role = %s, want USER", resp.GetAccount().GetManagedRole())
	}

	// Bob leaves every allowed group: NOT_PERMITTED, with the rotated state kept.
	idp.Set(func(idp *oidctest.IdP) { idp.Users["bob"].IDTokenClaims["groups"] = []any{} })
	resp = checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	if resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue() == "" {
		t.Errorf("NOT_PERMITTED after a refresh must still return the refresh state")
	}
}

func TestCheckAccountUsesUserinfoWhenRefreshHasNoIDToken(t *testing.T) {
	// Authelia-style: groups only in userinfo, and no ID token on refresh.
	idp := newIdP(t)
	idp.AddUser("dave", &oidctest.User{Subject: "dave-sub", UserinfoClaims: map[string]any{"groups": []any{"silo-users"}}})
	idp.Set(func(idp *oidctest.IdP) { idp.OmitIDTokenOnRefresh = true })
	p := newProvider(t, groupsSettings(idp))
	account := signIn(t, p, idp, "dave").account
	requireAccount(t, account)
	storedIDToken := account.GetRefreshState().GetFields()[refreshIDToken].GetStringValue()

	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	if got := resp.GetAccount().GetRefreshState().GetFields()[refreshIDToken].GetStringValue(); got != storedIDToken {
		t.Errorf("stored id_token should be kept when the refresh returns none")
	}

	idp.Set(func(idp *oidctest.IdP) { idp.Users["dave"].UserinfoClaims["groups"] = []any{"other"} })
	requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
}

func TestCheckAccountStatuses(t *testing.T) {
	t.Run("no refresh token is UNSUPPORTED", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.OmitRefreshToken = true })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		fields := account.GetRefreshState().GetFields()
		if _, ok := fields[refreshToken]; ok || fields[refreshIDToken].GetStringValue() == "" {
			t.Fatalf("refresh_state without a refresh token = %v", account.GetRefreshState())
		}
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	})
	t.Run("empty state is UNSUPPORTED", func(t *testing.T) {
		p := newProvider(t, groupsSettings(newIdP(t)))
		requireStatus(t, checkAccount(t, p, &pluginv1.AuthenticateResponse{ExternalSubject: "x"}),
			pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	})
	t.Run("invalid discovery metadata is UNAVAILABLE without a grant", func(t *testing.T) {
		idp := newIdP(t)
		cfg := groupsSettings(idp)
		account := signIn(t, newProvider(t, cfg), idp, "alice").account
		requireAccount(t, account)
		idp.Set(func(idp *oidctest.IdP) {
			idp.MutateDiscovery = func(doc map[string]any) { doc["issuer"] = "https://elsewhere.example" }
		})
		tokens := tokenCount(idp)
		requireStatus(t, checkAccount(t, newProvider(t, cfg), account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		if tokenCount(idp) != tokens {
			t.Errorf("the refresh token was redeemed without usable provider metadata")
		}
	})
	t.Run("provider outage is UNAVAILABLE", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.TokenStatus = 503 })
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	})
	t.Run("wrong client secret is UNAVAILABLE, not a revocation", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.ClientSecret = "rotated-at-the-provider" })
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	})
	t.Run("userinfo outage is UNAVAILABLE with rotated state", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens = true })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.UserinfoStatus = 500 })
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		requireRotated(t, account, resp)
	})
	t.Run("changed account key is NOT_PERMITTED", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		account.ExternalSubject = "https://old-issuer.example|alice-sub"
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("refreshed id_token with another sub is UNAVAILABLE", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.MutateIDToken = func(c map[string]any) { c["sub"] = "someone-else" } })
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
	})
	t.Run("userinfo for another subject is NOT_PERMITTED", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.Users["alice"].UserinfoClaims = map[string]any{"sub": "someone-else"} })
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("signed userinfo with an unknown kid is UNAVAILABLE with rotated state", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) {
			idp.SignedUserinfo, idp.OmitIDTokenOnRefresh, idp.RotateRefreshTokens = true, true, true
		})
		p := newProvider(t, groupsSettings(idp))
		requireAccount(t, signIn(t, p, idp, "alice").account)
		// A rotation makes the next sign-in force a JWKS refetch, which opens
		// the rate-limit window.
		idp.RotateKey(jose.RS256)
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.RotateKey(jose.RS256)
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		requireRotated(t, account, resp)
	})
}

func requireRotated(t *testing.T, before *pluginv1.AuthenticateResponse, resp *pluginv1.CheckAccountResponse) {
	t.Helper()
	rotated := resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue()
	if rotated == "" || rotated == before.GetRefreshState().GetFields()[refreshToken].GetStringValue() {
		t.Fatalf("rotated refresh token not returned: %v", resp.GetAccount().GetRefreshState())
	}
}

func TestCheckAccountNeedsOfflineAccess(t *testing.T) {
	// Refresh tokens issued without offline_access are tied to the browser
	// session; the provider refuses them once it ends, which would read as a
	// revocation. They are not kept.
	t.Run("not requested", func(t *testing.T) {
		idp := newIdP(t)
		cfg := groupsSettings(idp)
		cfg.connection["request_offline_access"] = false
		p := newProvider(t, cfg)
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		requireStateKeys(t, account.GetRefreshState(), refreshIDToken, refreshSubject)
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
		if grant := idp.LastToken().Form.Get("grant_type"); grant != "authorization_code" {
			t.Errorf("CheckAccount sent a %s grant; it must not redeem anything", grant)
		}
	})
	t.Run("requested but not granted", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RefuseOfflineAccess = true })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		requireStateKeys(t, account.GetRefreshState(), refreshIDToken, refreshSubject)
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	})
	t.Run("granted without a scope field", func(t *testing.T) {
		// Zitadel omits scope; a missing scope grants what was requested.
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.OmitScope = true })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		requireStateKeys(t, account.GetRefreshState(), refreshToken, refreshIssuedAt, refreshGrantedAt, refreshIDToken, refreshSubject)
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	})
}

func TestCheckAccountRefreshExpiry(t *testing.T) {
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.RefreshExpiresIn, idp.RotateRefreshTokens = 3600, true })
	p := newProvider(t, groupsSettings(idp))
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	requireStateKeys(t, account.GetRefreshState(), refreshToken, refreshExpiresAt, refreshIssuedAt, refreshGrantedAt, refreshIDToken, refreshSubject)
	expiresAt := account.GetRefreshState().GetFields()[refreshExpiresAt].GetNumberValue()
	if want := float64(time.Now().Add(time.Hour).Unix()); expiresAt < want-60 || expiresAt > want+60 {
		t.Fatalf("refresh_expires_at = %v, want about %v", expiresAt, want)
	}

	// A rotated token carries its own expiry.
	idp.Set(func(idp *oidctest.IdP) { idp.RefreshExpiresIn = 7200 })
	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	if got := resp.GetAccount().GetRefreshState().GetFields()[refreshExpiresAt].GetNumberValue(); got < expiresAt+3000 {
		t.Errorf("rotated refresh_expires_at = %v, want about an hour later than %v", got, expiresAt)
	}

	// Once the provider-reported lifetime has passed, the token is not
	// redeemed: an expired token is not a revocation.
	// The answer drops the expired token, so the host stops storing it.
	tokens := tokenCount(idp)
	expired := &pluginv1.AuthenticateResponse{ExternalSubject: account.GetExternalSubject(), RefreshState: mustStruct(t, map[string]any{
		refreshToken:     resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue(),
		refreshExpiresAt: float64(time.Now().Add(-time.Minute).Unix()),
		refreshIDToken:   resp.GetAccount().GetRefreshState().GetFields()[refreshIDToken].GetStringValue(),
		refreshSubject:   "alice-sub",
	})}
	check := checkAccount(t, p, expired)
	requireStatus(t, check, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	if tokenCount(idp) != tokens {
		t.Error("an expired refresh token was presented to the provider")
	}
	requireStateKeys(t, check.GetAccount().GetRefreshState(), refreshIDToken, refreshSubject)
}

func TestCheckAccountWithoutFreshGroups(t *testing.T) {
	// Groups ride only on the ID token, and the refresh returns none. The
	// sign-in groups must not be re-used.
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.OmitIDTokenOnRefresh = true })
	p := newProvider(t, groupsSettings(idp))
	account := signIn(t, p, idp, "bob").account
	requireAccount(t, account)

	idp.Set(func(idp *oidctest.IdP) { idp.Users["bob"].IDTokenClaims["groups"] = []any{} })
	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	if resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue() == "" {
		t.Error("UNSUPPORTED after a refresh must still return the refresh state")
	}

	// Without group rules there is nothing stale to apply: ACTIVE, and no
	// profile facts are copied from the sign-in token.
	idp2 := newIdP(t)
	idp2.Set(func(idp *oidctest.IdP) { idp.OmitIDTokenOnRefresh = true })
	p = newProvider(t, baseSettings(idp2))
	account = signIn(t, p, idp2, "bob").account
	requireAccount(t, account)
	resp = checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	if got := resp.GetAccount(); len(got.GetGroups()) != 0 || got.GetEmail() != "" || got.GetExternalSubject() != account.GetExternalSubject() {
		t.Errorf("stale sign-in claims reused: %+v", got)
	}
}

func TestCheckAccountDeadline(t *testing.T) {
	t.Run("too little time left does not spend the token", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		tokens := tokenCount(idp)
		ctx, cancel := context.WithTimeout(context.Background(), minRefreshBudget-time.Second)
		defer cancel()
		requireStatus(t, checkAccountCtx(t, ctx, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		if tokenCount(idp) != tokens {
			t.Error("the refresh token was redeemed with too little time left")
		}
	})
	t.Run("slow userinfo still returns the rotated state in time", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens = true })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.UserinfoDelay = time.Minute })
		budget := minRefreshBudget + time.Second
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		started := time.Now()
		resp := checkAccountCtx(t, ctx, p, account)
		if elapsed := time.Since(started); elapsed >= budget-responseReserve/2 {
			t.Errorf("CheckAccount took %v; it must answer before the caller's %v deadline", elapsed, budget)
		}
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		requireRotated(t, account, resp)
	})
	t.Run("slow refresh grant answers before the deadline", func(t *testing.T) {
		// The refresh grant itself must stop responseReserve early, so the
		// answer marking its outcome unknown still reaches the host.
		idp := newIdP(t)
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		idp.Set(func(idp *oidctest.IdP) { idp.TokenDelay = time.Minute })
		budget := minRefreshBudget + time.Second
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		defer cancel()
		started := time.Now()
		resp := checkAccountCtx(t, ctx, p, account)
		if elapsed := time.Since(started); elapsed >= budget-responseReserve/2 {
			t.Errorf("CheckAccount took %v; the refresh grant must stop before the caller's %v deadline", elapsed, budget)
		}
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		fields := resp.GetAccount().GetRefreshState().GetFields()
		if !fields[refreshUncertain].GetBoolValue() {
			t.Errorf("refresh_state after an unanswered refresh = %v, want refresh_uncertain", resp.GetAccount().GetRefreshState())
		}
		if got, want := fields[refreshToken].GetStringValue(), account.GetRefreshState().GetFields()[refreshToken].GetStringValue(); got != want {
			t.Errorf("refresh token after an unanswered refresh = %q, want the stored one kept", got)
		}
	})
}

func tokenCount(idp *oidctest.IdP) int {
	var n int
	idp.Set(func(idp *oidctest.IdP) { n = len(idp.Tokens) })
	return n
}

func requireStateKeys(t *testing.T, state *structpb.Struct, want ...string) {
	t.Helper()
	var got []string
	for key := range state.GetFields() {
		got = append(got, key)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("refresh_state keys = %v, want %v", got, want)
	}
}

func TestCheckAccountNeverLeaksSecretsInState(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, groupsSettings(idp))
	account := signIn(t, p, idp, "alice").account
	resp := checkAccount(t, p, account)
	requireStateKeys(t, resp.GetAccount().GetRefreshState(), refreshToken, refreshIssuedAt, refreshGrantedAt, refreshIDToken, refreshSubject)
	if strings.Contains(resp.GetAccount().GetRefreshState().String(), idp.ClientSecret) {
		t.Error("refresh_state contains the client secret")
	}
}
