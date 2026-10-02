package provider

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidctest"
)

// withStateFields returns a copy of the account's refresh_state edited by fn.
func withStateFields(t *testing.T, account *pluginv1.AuthenticateResponse, fn func(fields map[string]any)) *pluginv1.AuthenticateResponse {
	t.Helper()
	fields := account.GetRefreshState().AsMap()
	fn(fields)
	return &pluginv1.AuthenticateResponse{ExternalSubject: account.GetExternalSubject(), RefreshState: mustStruct(t, fields)}
}

func issuedAgo(ago time.Duration) func(map[string]any) {
	return func(fields map[string]any) {
		fields[refreshIssuedAt] = float64(time.Now().Add(-ago).Unix())
	}
}

func grantedAgo(ago time.Duration) func(map[string]any) {
	return func(fields map[string]any) {
		fields[refreshGrantedAt] = float64(time.Now().Add(-ago).Unix())
	}
}

func withLifetime(cfg settings, lifetime string) settings {
	cfg.connection["refresh_token_lifetime"] = lifetime
	return cfg
}

func withMaxLifetime(cfg settings, lifetime string) settings {
	cfg.connection["refresh_token_max_lifetime"] = lifetime
	return cfg
}

const day = 24 * time.Hour

// Providers answer invalid_grant for an expired refresh token and a revoked
// one alike. The refusal is a revocation only while the token is known to be
// inside its lifetime.
func TestCheckAccountRefusedRefreshToken(t *testing.T) {
	t.Run("a provider lifetime hint: refusal is a revocation", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RefreshExpiresIn = 1800 })
		p := newProvider(t, groupsSettings(idp))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("a hint that the token is still valid wins over an elapsed setting", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RefreshExpiresIn = 1800 })
		p := newProvider(t, withLifetime(groupsSettings(idp), "90m"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		old := withStateFields(t, account, issuedAgo(2*time.Hour))
		idp.Revoke()
		requireStatus(t, checkAccount(t, p, old), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("Keycloak offline token: UNSUPPORTED with the setting blank, a revocation with it set", func(t *testing.T) {
		// refresh_expires_in 0 and no exp: Offline Session Max Limited is off.
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.ZeroRefreshExpiresIn = true })
		blank := newProvider(t, groupsSettings(idp))
		account := signIn(t, blank, idp, "alice").account
		requireAccount(t, account)
		requireStateKeys(t, account.GetRefreshState(), refreshToken, refreshIssuedAt, refreshGrantedAt, refreshIDToken, refreshSubject)
		set := newProvider(t, withLifetime(groupsSettings(idp), "30d"))
		idp.Revoke()
		requireStatus(t, checkAccount(t, blank, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
		requireStatus(t, checkAccount(t, set, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("Authelia-style opaque token without a lifetime is UNSUPPORTED", func(t *testing.T) {
		idp := newIdP(t)
		logs := &bytes.Buffer{}
		p := newProviderWithLog(t, groupsSettings(idp), logs)
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		tokens := tokenCount(idp)
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
		if tokenCount(idp) != tokens+1 {
			t.Error("the refresh token was not presented to the provider")
		}
		out := logs.String()
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "Refresh token lifetime") {
			t.Errorf("no warning naming the Refresh token lifetime setting:\n%s", out)
		}
		if refresh := account.GetRefreshState().GetFields()[refreshToken].GetStringValue(); strings.Contains(out, refresh) {
			t.Error("the log contains the refresh token")
		}
	})
	t.Run("Authelia-style with a 90 minute lifetime: refusal inside it is a revocation", func(t *testing.T) {
		idp := newIdP(t)
		logs := &bytes.Buffer{}
		p := newProviderWithLog(t, withLifetime(groupsSettings(idp), "90m"), logs)
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
		// 80 minutes in is still inside the lifetime.
		requireStatus(t, checkAccount(t, p, withStateFields(t, account, issuedAgo(80*time.Minute))),
			pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
		if strings.Contains(logs.String(), "level=WARN") {
			t.Errorf("a refusal inside the configured lifetime logged a warning:\n%s", logs.String())
		}
	})
	t.Run("Authelia-style with a 90 minute lifetime: refusal after it is expiry", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, withLifetime(groupsSettings(idp), "90m"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		for _, ago := range []time.Duration{2 * time.Hour, 90 * time.Minute, 89*time.Minute + 30*time.Second} {
			requireStatus(t, checkAccount(t, p, withStateFields(t, account, issuedAgo(ago))),
				pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
		}
	})
	t.Run("a state without an issue time is UNSUPPORTED", func(t *testing.T) {
		// Defensive: a token with no recorded issue time cannot be placed
		// inside the lifetime.
		idp := newIdP(t)
		p := newProvider(t, withLifetime(groupsSettings(idp), "90m"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		noIssueTime := withStateFields(t, account, func(fields map[string]any) { delete(fields, refreshIssuedAt) })
		requireStatus(t, checkAccount(t, p, noIssueTime), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	})
}

// A refused token is dead. The answer drops it, so the host stops presenting
// it, and a lifetime entered later cannot turn the old expiry into a
// revocation.
func TestCheckAccountRefusedTokenIsCleared(t *testing.T) {
	idp := newIdP(t)
	cfg := groupsSettings(idp)
	p := newProvider(t, cfg)
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	idp.Revoke()
	resp := checkAccount(t, p, account)
	requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	requireStateKeys(t, resp.GetAccount().GetRefreshState(), refreshIDToken, refreshSubject)
	if resp.GetAccount().GetRefreshState().GetFields()[refreshIDToken].GetStringValue() !=
		account.GetRefreshState().GetFields()[refreshIDToken].GetStringValue() {
		t.Error("the ID token for the end-session hint was not kept")
	}

	if err := p.Configure(context.Background(), withLifetime(cfg, "30d").entries(t)); err != nil {
		t.Fatal(err)
	}
	account.RefreshState = resp.GetAccount().GetRefreshState()
	tokens := tokenCount(idp)
	requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	if tokenCount(idp) != tokens {
		t.Error("a cleared refresh token was presented to the provider")
	}

	t.Run("a revocation also clears the token", func(t *testing.T) {
		idp := newIdP(t)
		p := newProvider(t, withLifetime(groupsSettings(idp), "30d"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Revoke()
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
		requireStateKeys(t, resp.GetAccount().GetRefreshState(), refreshIDToken, refreshSubject)
	})
}

// Zitadel's Refresh Token Expiration is absolute from sign-in, while the
// per-token lifetime restarts at every rotation. A refusal at the absolute
// cap is expiry, however recent the last rotation.
func TestCheckAccountAbsoluteRefreshLifetime(t *testing.T) {
	signedIn := func(t *testing.T, idp *oidctest.IdP) (*Provider, *pluginv1.AuthenticateResponse) {
		t.Helper()
		idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens = true })
		p := newProvider(t, withMaxLifetime(withLifetime(groupsSettings(idp), "30d"), "90d"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		return p, account
	}
	t.Run("a refusal at the cap is expiry", func(t *testing.T) {
		idp := newIdP(t)
		p, account := signedIn(t, idp)
		idp.Revoke()
		atCap := withStateFields(t, account, func(fields map[string]any) {
			grantedAgo(90 * day)(fields)
			issuedAgo(12 * time.Hour)(fields)
		})
		requireStatus(t, checkAccount(t, p, atCap), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
	})
	t.Run("a refusal before the cap is a revocation", func(t *testing.T) {
		idp := newIdP(t)
		p, account := signedIn(t, idp)
		idp.Revoke()
		beforeCap := withStateFields(t, account, func(fields map[string]any) {
			grantedAgo(60 * day)(fields)
			issuedAgo(12 * time.Hour)(fields)
		})
		requireStatus(t, checkAccount(t, p, beforeCap), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED)
	})
	t.Run("rotation keeps the grant time", func(t *testing.T) {
		idp := newIdP(t)
		p, account := signedIn(t, idp)
		old := withStateFields(t, account, grantedAgo(10*day))
		want := old.GetRefreshState().GetFields()[refreshGrantedAt].GetNumberValue()
		resp := checkAccount(t, p, old)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		requireRotated(t, old, resp)
		if got := resp.GetAccount().GetRefreshState().GetFields()[refreshGrantedAt].GetNumberValue(); got != want {
			t.Errorf("refresh_granted_at = %v after rotation, want %v", got, want)
		}
	})
}

// A refresh whose answer is lost may have spent the token at the provider.
// Its reuse refusal afterwards must not read as a revocation.
func TestCheckAccountLostRefreshResponse(t *testing.T) {
	for _, lose := range []struct {
		name   string
		status int
	}{{"502 after the rotation", 502}, {"connection dropped after the rotation", -1}} {
		t.Run(lose.name, func(t *testing.T) {
			idp := newIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens = true })
			p := newProvider(t, withLifetime(groupsSettings(idp), "30d"))
			account := signIn(t, p, idp, "alice").account
			requireAccount(t, account)

			idp.Set(func(idp *oidctest.IdP) { idp.LoseRefreshResponse = lose.status })
			resp := checkAccount(t, p, account)
			requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
			fields := resp.GetAccount().GetRefreshState().GetFields()
			if !fields[refreshUncertain].GetBoolValue() {
				t.Fatalf("refresh_state after a lost answer = %v, want refresh_uncertain", resp.GetAccount().GetRefreshState())
			}
			if fields[refreshToken].GetStringValue() != account.GetRefreshState().GetFields()[refreshToken].GetStringValue() {
				t.Fatal("the stored refresh token was not kept")
			}

			idp.Set(func(idp *oidctest.IdP) { idp.LoseRefreshResponse = 0 })
			account.RefreshState = resp.GetAccount().GetRefreshState()
			resp = checkAccount(t, p, account)
			requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)
			requireStateKeys(t, resp.GetAccount().GetRefreshState(), refreshIDToken, refreshSubject)
		})
	}
	t.Run("the next successful refresh clears the mark", func(t *testing.T) {
		idp := newIdP(t) // no rotation: the stored token stays valid
		p := newProvider(t, withLifetime(groupsSettings(idp), "30d"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		idp.Set(func(idp *oidctest.IdP) { idp.LoseRefreshResponse = 502 })
		account.RefreshState = checkAccount(t, p, account).GetAccount().GetRefreshState()
		idp.Set(func(idp *oidctest.IdP) { idp.LoseRefreshResponse = 0 })
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		if _, ok := resp.GetAccount().GetRefreshState().GetFields()[refreshUncertain]; ok {
			t.Error("refresh_uncertain survived a successful refresh")
		}
	})
}

func TestCheckAccountRefreshIssuedAt(t *testing.T) {
	issuedAt := func(resp *pluginv1.CheckAccountResponse) time.Time {
		return time.Unix(int64(resp.GetAccount().GetRefreshState().GetFields()[refreshIssuedAt].GetNumberValue()), 0)
	}
	signedIn := func(t *testing.T, idp *oidctest.IdP) (*Provider, *pluginv1.AuthenticateResponse) {
		t.Helper()
		p := newProvider(t, withLifetime(groupsSettings(idp), "90m"))
		account := signIn(t, p, idp, "alice").account
		requireAccount(t, account)
		at := account.GetRefreshState().GetFields()[refreshIssuedAt].GetNumberValue()
		if now := float64(time.Now().Unix()); at < now-60 || at > now+1 {
			t.Fatalf("refresh_issued_at = %v, want about %v", at, now)
		}
		return p, withStateFields(t, account, issuedAgo(time.Hour))
	}

	t.Run("a new refresh token restarts the clock", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.RotateRefreshTokens = true })
		p, account := signedIn(t, idp)
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		if got := issuedAt(resp); time.Since(got) > time.Minute {
			t.Errorf("rotated refresh_issued_at = %v, want about now", got)
		}
	})
	t.Run("the same refresh token handed back keeps its issue time", func(t *testing.T) {
		idp := newIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.EchoRefreshToken = true })
		p, account := signedIn(t, idp)
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		if got := issuedAt(resp); time.Since(got) < 59*time.Minute {
			t.Errorf("refresh_issued_at = %v, want the stored time an hour ago", got)
		}
	})
	t.Run("no refresh token in the answer keeps the stored one and its issue time", func(t *testing.T) {
		idp := newIdP(t)
		p, account := signedIn(t, idp)
		idp.Set(func(idp *oidctest.IdP) { idp.OmitRefreshToken = true })
		resp := checkAccount(t, p, account)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		if got := issuedAt(resp); time.Since(got) < 59*time.Minute {
			t.Errorf("refresh_issued_at = %v, want the stored time an hour ago", got)
		}
		if resp.GetAccount().GetRefreshState().GetFields()[refreshToken].GetStringValue() !=
			account.GetRefreshState().GetFields()[refreshToken].GetStringValue() {
			t.Error("the stored refresh token was not kept")
		}
	})
}

// A cold cache (after a restart or a settings change) must not let a slow
// provider spend the refresh budget before the grant.
func TestCheckAccountLoadsMetadataBeforeTheBudgetCheck(t *testing.T) {
	coldCheck := func(t *testing.T, idp *oidctest.IdP, slow func(idp *oidctest.IdP), timeout time.Duration) (*pluginv1.CheckAccountResponse, int) {
		t.Helper()
		cfg := groupsSettings(idp)
		account := signIn(t, newProvider(t, cfg), idp, "alice").account
		requireAccount(t, account)
		p := newProvider(t, cfg) // empty discovery and JWKS caches
		idp.Set(slow)
		tokens := tokenCount(idp)
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		resp := checkAccountCtx(t, ctx, p, account)
		return resp, tokenCount(idp) - tokens
	}
	budget := minRefreshBudget + time.Second
	slowBy := 2 * time.Second // leaves less than minRefreshBudget

	t.Run("slow discovery", func(t *testing.T) {
		idp := newIdP(t)
		resp, grants := coldCheck(t, idp, func(idp *oidctest.IdP) { idp.DiscoveryDelay = slowBy }, budget)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		if grants != 0 {
			t.Errorf("the refresh token was redeemed after discovery used up the budget")
		}
	})
	t.Run("slow JWKS", func(t *testing.T) {
		idp := newIdP(t)
		resp, grants := coldCheck(t, idp, func(idp *oidctest.IdP) { idp.JWKSDelay = slowBy }, budget)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE)
		if grants != 0 {
			t.Errorf("the refresh token was redeemed after the JWKS fetch used up the budget")
		}
	})
	t.Run("cold cache with time to spare", func(t *testing.T) {
		idp := newIdP(t)
		resp, grants := coldCheck(t, idp, func(idp *oidctest.IdP) { idp.DiscoveryDelay = 200 * time.Millisecond }, 30*time.Second)
		requireStatus(t, resp, pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
		if grants != 1 {
			t.Errorf("refresh grants = %d, want 1", grants)
		}
	})
}

func TestRefreshTokenLifetimeSetting(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{"", 0, true},
		{"  ", 0, true},
		{"0", 0, true},
		{"0d", 0, true},
		{"90m", 90 * time.Minute, true},
		{" 1h30m ", 90 * time.Minute, true},
		{"12h", 12 * time.Hour, true},
		{"30d", 30 * day, true},
		{"9999d", 9999 * day, true},
		{"999999h9999999m", 999999*time.Hour + 9999999*time.Minute, true},
		{"10000d", 0, false},
		{"1000000h", 0, false},
		{"-5m", 0, false},
		{"-1d", 0, false},
		{"90", 0, false},
		{"1.5d", 0, false},
		{"1.5h", 0, false},
		{"30s", 0, false},
		{"1d12h", 0, false},
		{"soon", 0, false},
	} {
		got, ok := parseLifetime(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseLifetime(%q) = %v, %v; want %v, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
		if matched := lifetimeRE.MatchString(tc.raw); matched != tc.ok {
			t.Errorf("LifetimePattern matches %q = %v; parseLifetime ok = %v", tc.raw, matched, tc.ok)
		}
		if tc.ok && got < 0 {
			t.Errorf("parseLifetime(%q) overflowed to %v", tc.raw, got)
		}
	}

	entries := func(field string, lifetime any) []*pluginv1.ConfigEntry {
		return []*pluginv1.ConfigEntry{{Key: keyConnection, Value: mustStruct(t, map[string]any{
			"issuer_url": "https://idp.example", "client_id": "silo", field: lifetime,
		})}}
	}
	cfg, err := ParseConfig(entries("refresh_token_lifetime", "90m"))
	if err != nil || cfg.RefreshTokenLifetime != 90*time.Minute || len(cfg.Problems()) != 0 || len(cfg.LifetimeProblems()) != 0 {
		t.Errorf("90m: err = %v, lifetime = %v, problems = %v %v", err, cfg.RefreshTokenLifetime, cfg.Problems(), cfg.LifetimeProblems())
	}
	cfg, err = ParseConfig(entries("refresh_token_max_lifetime", "90d"))
	if err != nil || cfg.RefreshTokenMaxLifetime != 90*day {
		t.Errorf("max 90d: err = %v, lifetime = %v", err, cfg.RefreshTokenMaxLifetime)
	}
	// An unreadable lifetime is unknown: it never stops sign-in.
	for _, field := range []string{"refresh_token_lifetime", "refresh_token_max_lifetime"} {
		cfg, err = ParseConfig(entries(field, "36500d"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RefreshTokenLifetime != 0 || cfg.RefreshTokenMaxLifetime != 0 || len(cfg.Problems()) != 0 {
			t.Errorf("%s 36500d: lifetimes %v %v, problems %v", field, cfg.RefreshTokenLifetime, cfg.RefreshTokenMaxLifetime, cfg.Problems())
		}
		if problems := cfg.LifetimeProblems(); len(problems) != 1 || !strings.Contains(problems[0], "at most 9999d") {
			t.Errorf("%s 36500d: lifetime problems = %v", field, problems)
		}
	}
	if _, err := ParseConfig(entries("refresh_token_lifetime", 90.0)); err == nil {
		t.Error("a number for refresh_token_lifetime should fail")
	}
}

func TestUnreadableLifetimeKeepsSignInWorking(t *testing.T) {
	idp := newIdP(t)
	cfg := withLifetime(groupsSettings(idp), "36500d")
	logs := &bytes.Buffer{}
	p := newProviderWithLog(t, cfg, logs)
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "Refresh token lifetime") {
		t.Errorf("Configure logged no warning for the lifetime:\n%s", logs.String())
	}
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	idp.Revoke()
	// Treated as unknown, so the refusal signs no one out.
	requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED)

	resp := runTest(t, New(nil), cfg)
	settingsStep := stepsByID(resp)[stepSettings]
	if resp.GetOk() || settingsStep.GetOk() || !strings.Contains(settingsStep.GetMessage(), "at most 9999d") {
		t.Fatalf("settings step = %+v, want a failure naming the cap", settingsStep)
	}
	if last := lastStep(resp); last.GetId() == stepSettings {
		t.Errorf("the connection test stopped at the settings step: %+v", resp.GetSteps())
	}
}
