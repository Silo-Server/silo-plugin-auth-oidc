package provider

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidctest"
)

// parIdP is a test provider that offers pushed authorization requests.
func parIdP(t *testing.T) *oidctest.IdP {
	t.Helper()
	idp := newIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.PAR = true })
	return idp
}

func withPAR(cfg settings, mode string) settings {
	cfg.connection["pushed_authorization"] = mode
	return cfg
}

func initAuthorize(t *testing.T, ctx context.Context, p *Provider, state string) (*pluginv1.InitAuthorizeResponse, error) {
	t.Helper()
	return p.InitAuthorize(ctx, &pluginv1.InitAuthorizeRequest{RedirectUri: testRedirect, State: state})
}

func requireCode(t *testing.T, err error, want codes.Code, contains ...string) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("err = %v, want code %s", err, want)
	}
	for _, text := range contains {
		if !strings.Contains(err.Error(), text) {
			t.Errorf("error %q does not mention %q", err.Error(), text)
		}
	}
}

func queryKeys(t *testing.T, raw string) []string {
	t.Helper()
	var keys []string
	for key := range mustQuery(t, raw) {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}

// Spec test 1: with PAR the browser URL carries only client_id and
// request_uri, the push carries every parameter, and sign-in completes.
func TestPARSignIn(t *testing.T) {
	idp := parIdP(t)
	p := newProvider(t, baseSettings(idp))
	init, err := p.InitAuthorize(context.Background(), &pluginv1.InitAuthorizeRequest{
		RedirectUri: testRedirect, State: "host-state", Prompt: "login", LoginHint: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("InitAuthorize: %v", err)
	}
	if got := queryKeys(t, init.GetAuthorizeUrl()); !slices.Equal(got, []string{"client_id", "request_uri"}) {
		t.Fatalf("authorization URL query keys = %v, want only client_id and request_uri", got)
	}
	query := mustQuery(t, init.GetAuthorizeUrl())
	if query.Get("client_id") != idp.ClientID || !strings.HasPrefix(query.Get("request_uri"), oidctest.RequestURIPrefix) {
		t.Fatalf("authorization URL query = %v", query)
	}

	fields := init.GetProviderState().GetFields()
	push := idp.LastPush()
	want := map[string]string{
		"response_type":         "code",
		"client_id":             idp.ClientID,
		"redirect_uri":          testRedirect,
		"scope":                 "openid profile email offline_access",
		"state":                 "host-state",
		"nonce":                 fields[stateNonce].GetStringValue(),
		"code_challenge":        oidc.S256Challenge(fields[stateCodeVerifier].GetStringValue()),
		"code_challenge_method": "S256",
		"prompt":                "login",
		"login_hint":            "alice@example.com",
	}
	for name, value := range want {
		if got := push.Form.Get(name); got != value || value == "" {
			t.Errorf("pushed %s = %q, want %q", name, got, value)
		}
	}
	if push.Form.Has("request_uri") || push.Form.Has("client_secret") {
		t.Errorf("push form = %v; it must not carry request_uri or, with HTTP Basic, the secret", push.Form)
	}
	if !strings.HasPrefix(push.Authorization, "Basic ") {
		t.Errorf("push authorization = %q, want HTTP Basic", push.Authorization)
	}

	code, state, err := idp.Login(init.GetAuthorizeUrl(), "alice")
	if err != nil {
		t.Fatalf("login at IdP: %v", err)
	}
	if state != "host-state" {
		t.Fatalf("callback state = %q", state)
	}
	account, err := p.ExchangeCode(context.Background(), &pluginv1.ExchangeCodeRequest{
		Code: code, State: state, RedirectUri: testRedirect, ProviderState: init.GetProviderState(),
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	requireAccount(t, account)
	if token := idp.LastToken(); token.Form.Get("redirect_uri") != testRedirect || token.Form.Get("code_verifier") == "" {
		t.Errorf("token request = %v, want redirect_uri and code_verifier", token.Form)
	}
}

// Spec test 2: one case per row of the decision table.
func TestPARDecisionTable(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		endpoint  bool
		wantPAR   bool
		wantError bool
	}{
		{name: "never, endpoint present", mode: PARNever, endpoint: true},
		{name: "never, endpoint absent", mode: PARNever},
		{name: "when_supported, endpoint absent", mode: PARWhenSupported},
		{name: "when_supported, endpoint present", mode: PARWhenSupported, endpoint: true, wantPAR: true},
		{name: "blank, endpoint absent", mode: ""},
		{name: "blank, endpoint present", mode: "", endpoint: true, wantPAR: true},
		{name: "always, endpoint present", mode: PARAlways, endpoint: true, wantPAR: true},
		{name: "always, endpoint absent", mode: PARAlways, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.PAR = tt.endpoint })
			p := newProvider(t, withPAR(baseSettings(idp), tt.mode))
			if tt.wantError {
				_, err := initAuthorize(t, context.Background(), p, "s")
				requireCode(t, err, codes.FailedPrecondition, labelPAR, "Always")
				return
			}
			requireAccount(t, signIn(t, p, idp, "alice").account)
			pushes, _ := idp.PushCounts()
			usedPAR := idp.LastAuthorize().Query.Has("request_uri")
			if usedPAR != tt.wantPAR || (pushes == 1) != tt.wantPAR {
				t.Fatalf("request_uri in URL = %v, pushes = %d; want PAR = %v", usedPAR, pushes, tt.wantPAR)
			}
			if !tt.wantPAR && !idp.LastAuthorize().Query.Has("code_challenge") {
				t.Fatal("browser-URL request lacks code_challenge")
			}
		})
	}
}

// Spec test 3: the push authenticates the client as the token endpoint does.
func TestPARClientAuthentication(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		noSecret      bool
		wantBasic     bool
		wantFormToken bool
	}{
		{name: "client_secret_basic", method: oidc.AuthMethodBasic, wantBasic: true},
		{name: "client_secret_post", method: oidc.AuthMethodPost, wantFormToken: true},
		{name: "no secret", method: oidc.AuthMethodBasic, noSecret: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := parIdP(t)
			cfg := baseSettings(idp)
			cfg.connection["token_endpoint_auth_method"] = tt.method
			idp.Set(func(idp *oidctest.IdP) { idp.AuthMethod = tt.method })
			if tt.noSecret {
				idp.Set(func(idp *oidctest.IdP) { idp.ClientSecret, idp.AuthMethod = "", "" })
				delete(cfg.connection, "client_secret")
			}
			p := newProvider(t, cfg)
			requireAccount(t, signIn(t, p, idp, "alice").account)
			push := idp.LastPush()
			if got := strings.HasPrefix(push.Authorization, "Basic "); got != tt.wantBasic {
				t.Errorf("push Basic credentials = %v (%q), want %v", got, push.Authorization, tt.wantBasic)
			}
			if got := push.Form.Has("client_secret"); got != tt.wantFormToken {
				t.Errorf("push form client_secret present = %v, want %v", got, tt.wantFormToken)
			}
			if push.Form.Get("client_id") != idp.ClientID {
				t.Errorf("push form client_id = %q", push.Form.Get("client_id"))
			}
		})
	}

	t.Run("Pocket ID ignores Basic when the form has client_id", func(t *testing.T) {
		idp := parIdP(t)
		idp.Set(func(idp *oidctest.IdP) { idp.PARIgnoreBasicWithClientID = true })
		_, err := initAuthorize(t, context.Background(), newProvider(t, baseSettings(idp)), "s")
		requireCode(t, err, codes.FailedPrecondition, "400 unknown_error", labelPAR, labelClientAuth)
		if strings.Contains(err.Error(), oidctest.PocketIDMissingCredentials) {
			t.Errorf("error %q repeats the provider's text", err.Error())
		}

		cfg := baseSettings(idp)
		cfg.connection["token_endpoint_auth_method"] = oidc.AuthMethodPost
		requireAccount(t, signIn(t, newProvider(t, cfg), idp, "alice").account)
	})
}

// Spec test 4: Always without an endpoint fails before any request.
func TestPARAlwaysWithoutEndpoint(t *testing.T) {
	idp := newIdP(t)
	p := newProvider(t, withPAR(baseSettings(idp), PARAlways))
	resp, err := initAuthorize(t, context.Background(), p, "s")
	requireCode(t, err, codes.FailedPrecondition, labelPAR, "pushed_authorization_request_endpoint")
	if resp != nil {
		t.Fatalf("response = %v, want none", resp)
	}
	if pushes, _ := idp.PushCounts(); pushes != 0 || idp.AuthorizeCount() != 0 {
		t.Fatalf("pushes = %d, authorize requests = %d; want none", pushes, idp.AuthorizeCount())
	}
}

// Spec test 5: each failed push maps as in the failure table, is not retried,
// and never falls back to a browser-URL request.
func TestPARFailuresDoNotFallBack(t *testing.T) {
	longURI := `{"request_uri":"` + oidctest.RequestURIPrefix + strings.Repeat("x", 2048) + `","expires_in":60}`
	tests := []struct {
		name     string
		knobs    func(idp *oidctest.IdP)
		deadline time.Duration
		want     codes.Code
		contains []string
	}{
		{
			name:  "invalid_client",
			knobs: func(idp *oidctest.IdP) { idp.PARStatus, idp.PARError = 401, "invalid_client" },
			want:  codes.FailedPrecondition, contains: []string{"401 invalid_client", labelPAR},
		},
		{
			name:  "429",
			knobs: func(idp *oidctest.IdP) { idp.PARStatus = 429 },
			want:  codes.Unavailable, contains: []string{"429"},
		},
		{
			name:  "500",
			knobs: func(idp *oidctest.IdP) { idp.PARStatus = 500 },
			want:  codes.Unavailable, contains: []string{"500"},
		},
		{
			name:     "delay past the deadline",
			knobs:    func(idp *oidctest.IdP) { idp.PARDelay = 5 * time.Second },
			deadline: 300 * time.Millisecond,
			want:     codes.Unavailable,
		},
		{
			name:  "201 without request_uri",
			knobs: func(idp *oidctest.IdP) { idp.OmitRequestURI = true },
			want:  codes.FailedPrecondition, contains: []string{"201", "no request_uri", labelPAR},
		},
		{
			name:  "oversized request_uri",
			knobs: func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 201, longURI },
			want:  codes.FailedPrecondition, contains: []string{"longer than 2048 bytes", labelPAR},
		},
		{
			name:  "non-JSON 400",
			knobs: func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 400, "Bad Request" },
			want:  codes.FailedPrecondition, contains: []string{"400", labelPAR},
		},
	}
	for _, mode := range []string{PARWhenSupported, PARAlways} {
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				idp := parIdP(t)
				p := newProvider(t, withPAR(baseSettings(idp), mode))
				// Load discovery first, so only the push meets the deadline.
				client, _, err := p.clientForTest()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Discovery(context.Background()); err != nil {
					t.Fatal(err)
				}
				idp.Set(tt.knobs)
				ctx := context.Background()
				if tt.deadline > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.deadline)
					defer cancel()
				}
				resp, err := initAuthorize(t, ctx, p, "s")
				requireCode(t, err, tt.want, tt.contains...)
				if resp != nil {
					t.Fatalf("response = %v; a failed push must not return a URL", resp)
				}
				if pushes, _ := idp.PushCounts(); pushes != 1 || idp.AuthorizeCount() != 0 {
					t.Fatalf("pushes = %d, authorize requests = %d; want one push and no browser request", pushes, idp.AuthorizeCount())
				}
			})
		}
	}

	t.Run("a request_uri of exactly 2048 bytes is used", func(t *testing.T) {
		idp := parIdP(t)
		uri := oidctest.RequestURIPrefix + strings.Repeat("x", 2048-len(oidctest.RequestURIPrefix))
		idp.Set(func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 200, `{"request_uri":"`+uri+`"}` })
		resp, err := initAuthorize(t, context.Background(), newProvider(t, baseSettings(idp)), "s")
		if err != nil {
			t.Fatalf("InitAuthorize: %v", err)
		}
		if got := mustQuery(t, resp.GetAuthorizeUrl()).Get("request_uri"); got != uri {
			t.Fatalf("request_uri = %q", got)
		}
	})
}

// Spec test 6: the push does not follow a redirect, so the target never sees
// the form or the credentials.
func TestPARDoesNotFollowRedirects(t *testing.T) {
	for _, method := range []string{oidc.AuthMethodBasic, oidc.AuthMethodPost} {
		t.Run(method, func(t *testing.T) {
			idp := parIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.PARRedirect = true })
			cfg := baseSettings(idp)
			cfg.connection["token_endpoint_auth_method"] = method
			_, err := initAuthorize(t, context.Background(), newProvider(t, cfg), "s")
			requireCode(t, err, codes.FailedPrecondition, "307", "redirect", labelPAR)
			if pushes, redirected := idp.PushCounts(); pushes != 1 || redirected != 0 {
				t.Fatalf("pushes = %d, redirected = %d; the redirect target must receive nothing", pushes, redirected)
			}
		})
	}
}

// Spec test 7: text from a PAR answer, which may echo the client secret or
// the state, never reaches the returned error or the log.
func TestPARErrorDoesNotEchoAnswer(t *testing.T) {
	const state = "host-state-echo-5f1c"
	for name, body := range map[string]func(secret string) string{
		"secret as the error code": func(secret string) string {
			return `{"error":"` + secret + `","error_description":"client_secret=` + secret + ` state=` + state + `"}`
		},
		"state as the error code": func(secret string) string {
			return `{"error":"` + state + `","error_description":"` + secret + `"}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			idp := parIdP(t)
			idp.Set(func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 400, body(idp.ClientSecret) })
			cfg := baseSettings(idp)
			cfg.connection["token_endpoint_auth_method"] = oidc.AuthMethodPost
			var logs bytes.Buffer
			p := newProviderWithLog(t, cfg, &logs)
			_, err := initAuthorize(t, context.Background(), p, state)
			requireCode(t, err, codes.FailedPrecondition, "400 unknown_error", labelPAR)

			resp := runTest(t, New(nil), cfg)
			var stepText []string
			for _, step := range resp.GetSteps() {
				stepText = append(stepText, step.GetMessage())
			}
			for _, leaked := range []string{idp.ClientSecret, state} {
				if strings.Contains(err.Error(), leaked) {
					t.Errorf("error %q repeats %q from the answer", err.Error(), leaked)
				}
				if strings.Contains(logs.String(), leaked) {
					t.Errorf("log repeats %q from the answer: %s", leaked, logs.String())
				}
				if strings.Contains(strings.Join(stepText, "\n"), leaked) {
					t.Errorf("connection test repeats %q from the answer", leaked)
				}
			}
		})
	}
}

// Spec test 8: an authorization endpoint with its own query keeps it.
func TestPARKeepsAuthorizationEndpointQuery(t *testing.T) {
	for _, mode := range []string{PARWhenSupported, PARNever} {
		t.Run(mode, func(t *testing.T) {
			idp := parIdP(t)
			idp.Set(func(idp *oidctest.IdP) {
				idp.MutateDiscovery = func(doc map[string]any) {
					doc["authorization_endpoint"] = doc["authorization_endpoint"].(string) + "?tenant=t1"
				}
			})
			p := newProvider(t, withPAR(baseSettings(idp), mode))
			result := signIn(t, p, idp, "alice")
			requireAccount(t, result.account)
			url := result.init.GetAuthorizeUrl()
			if got := mustQuery(t, url).Get("tenant"); got != "t1" {
				t.Fatalf("authorization URL %q lost the endpoint's query", url)
			}
			if mode == PARWhenSupported {
				if got := queryKeys(t, url); !slices.Equal(got, []string{"client_id", "request_uri", "tenant"}) {
					t.Fatalf("authorization URL query keys = %v", got)
				}
			}
		})
	}
}

// Spec test 9: a non-https PAR endpoint fails PAR sign-in starts and the
// connection test, and breaks nothing that does not push.
func TestPARInsecureEndpoint(t *testing.T) {
	idp := parIdP(t)
	idp.Set(func(idp *oidctest.IdP) {
		idp.MutateDiscovery = func(doc map[string]any) {
			doc["pushed_authorization_request_endpoint"] = strings.Replace(doc["pushed_authorization_request_endpoint"].(string), "https://", "http://", 1)
		}
	})
	_, err := initAuthorize(t, context.Background(), newProvider(t, baseSettings(idp)), "s")
	requireCode(t, err, codes.FailedPrecondition, "https")

	resp := runTest(t, New(nil), baseSettings(idp))
	if last := lastStep(resp); resp.GetOk() || last.GetId() != stepPAR || !strings.Contains(last.GetMessage(), "https") {
		t.Fatalf("connection test = %+v, want a failed par step about https", resp.GetSteps())
	}

	cfg := withPAR(baseSettings(idp), PARNever)
	cfg.connection["provider_logout"] = true
	p := newProvider(t, cfg)
	account := signIn(t, p, idp, "alice").account
	requireAccount(t, account)
	requireStatus(t, checkAccount(t, p, account), pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE)
	end, err := p.EndSessionUrl(context.Background(), &pluginv1.AuthEndSessionUrlRequest{RefreshState: account.GetRefreshState()})
	if err != nil || end.GetUrl() == "" {
		t.Fatalf("EndSessionUrl = %v, %v; want a URL", end, err)
	}
	if pushes, _ := idp.PushCounts(); pushes != 0 {
		t.Fatalf("pushes = %d, want none", pushes)
	}
}

// Spec test 10: one case per row of the connection test's par step.
func TestTestConnectionPAR(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		knobs    func(idp *oidctest.IdP)
		wantOK   bool
		contains string
	}{
		{
			name: "never, provider requires PAR", mode: PARNever,
			knobs:    func(idp *oidctest.IdP) { idp.RequirePAR = true },
			contains: "requires pushed authorization requests",
		},
		{
			name: "never, provider offers PAR", mode: PARNever,
			knobs:  func(idp *oidctest.IdP) { idp.PAR = true },
			wantOK: true, contains: "Turned off. The provider offers them",
		},
		{
			name: "never, provider does not offer PAR", mode: PARNever,
			wantOK: true, contains: "Turned off. The provider does not offer them",
		},
		{
			name: "when_supported, endpoint absent", mode: PARWhenSupported,
			wantOK: true, contains: "browser URL",
		},
		{
			name: "always, endpoint absent", mode: PARAlways,
			contains: "The setting is Always",
		},
		{
			name: "in use, usable request_uri", mode: PARWhenSupported,
			knobs: func(idp *oidctest.IdP) {
				idp.PAR = true
				idp.RedirectURIs = append(idp.RedirectURIs, probeRedirectURI)
			},
			wantOK: true, contains: "accepted a test request",
		},
		{
			name: "in use, invalid_client", mode: PARAlways,
			knobs:    func(idp *oidctest.IdP) { idp.PAR, idp.PARStatus, idp.PARError = true, 401, "invalid_client" },
			contains: "refused the client",
		},
		{
			name: "in use, unauthorized_client", mode: PARWhenSupported,
			knobs:    func(idp *oidctest.IdP) { idp.PAR, idp.PARStatus, idp.PARError = true, 400, "unauthorized_client" },
			contains: "refused the client",
		},
		{
			name: "in use, non-JSON 401", mode: PARWhenSupported,
			knobs:    func(idp *oidctest.IdP) { idp.PAR, idp.PARStatus = true, 401 },
			contains: "refused the client",
		},
		{
			name: "in use, another JSON 400 OAuth error", mode: PARWhenSupported,
			// The probe redirect URI is not registered, so the provider
			// answers 400 invalid_request.
			knobs:  func(idp *oidctest.IdP) { idp.PAR = true },
			wantOK: true, contains: "Not confirmed: the endpoint answered 400 invalid_request to a test request and did not refuse the client.",
		},
		{
			name: "in use, JSON 400 with an unrecognized error", mode: PARWhenSupported,
			knobs:  func(idp *oidctest.IdP) { idp.PAR, idp.PARStatus, idp.PARError = true, 400, "Something went wrong" },
			wantOK: true, contains: "an error Silo does not recognize",
		},
		{
			name: "in use, Pocket ID v2.9.0 under client_secret_basic", mode: PARWhenSupported,
			knobs: func(idp *oidctest.IdP) {
				idp.PAR, idp.PARIgnoreBasicWithClientID = true, true
				idp.RedirectURIs = append(idp.RedirectURIs, probeRedirectURI)
			},
			wantOK: true, contains: "try the other Client authentication method (Pocket ID v2.9.0 needs Form body)",
		},
	}
	failures := map[string]func(idp *oidctest.IdP){
		"network error": func(idp *oidctest.IdP) {
			idp.MutateDiscovery = func(doc map[string]any) { doc["pushed_authorization_request_endpoint"] = "https://127.0.0.1:1/par" }
		},
		"redirect":                func(idp *oidctest.IdP) { idp.PARRedirect = true },
		"403":                     func(idp *oidctest.IdP) { idp.PARStatus, idp.PARError = 403, "access_denied" },
		"404":                     func(idp *oidctest.IdP) { idp.PARStatus = 404 },
		"405":                     func(idp *oidctest.IdP) { idp.PARStatus = 405 },
		"413":                     func(idp *oidctest.IdP) { idp.PARStatus = 413 },
		"429":                     func(idp *oidctest.IdP) { idp.PARStatus = 429 },
		"5xx":                     func(idp *oidctest.IdP) { idp.PARStatus = 503 },
		"non-JSON 400":            func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 400, "<html>bad</html>" },
		"2xx without request_uri": func(idp *oidctest.IdP) { idp.OmitRequestURI = true },
		"oversized request_uri": func(idp *oidctest.IdP) {
			idp.PARStatus, idp.PARBody = 201, `{"request_uri":"`+strings.Repeat("x", 2049)+`"}`
		},
		"2xx with a non-JSON body": func(idp *oidctest.IdP) { idp.PARStatus, idp.PARBody = 201, "created" },
	}
	for name, knobs := range failures {
		tests = append(tests, struct {
			name     string
			mode     string
			knobs    func(idp *oidctest.IdP)
			wantOK   bool
			contains string
		}{
			name: "in use, " + name, mode: PARWhenSupported,
			knobs: func(idp *oidctest.IdP) {
				idp.PAR = true
				idp.RedirectURIs = append(idp.RedirectURIs, probeRedirectURI)
				knobs(idp)
			},
			contains: "The test request failed",
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idp := newIdP(t)
			if tt.knobs != nil {
				idp.Set(tt.knobs)
			}
			resp := runTest(t, New(nil), withPAR(baseSettings(idp), tt.mode))
			step := stepsByID(resp)[stepPAR]
			if step == nil {
				t.Fatalf("no par step: %+v", resp.GetSteps())
			}
			if step.GetOk() != tt.wantOK || resp.GetOk() != tt.wantOK {
				t.Fatalf("par step ok = %v, test ok = %v (%s); want %v", step.GetOk(), resp.GetOk(), step.GetMessage(), tt.wantOK)
			}
			if !strings.Contains(step.GetMessage(), tt.contains) {
				t.Errorf("par step message %q does not mention %q", step.GetMessage(), tt.contains)
			}
			if !tt.wantOK && lastStep(resp).GetId() != stepPAR {
				t.Errorf("steps continued after a failed par step: %v", stepIDs(resp))
			}
			for _, echoed := range []string{idp.ClientSecret, "Something went wrong", oidctest.PocketIDMissingCredentials} {
				if strings.Contains(step.GetMessage(), echoed) {
					t.Errorf("par step message %q repeats %q", step.GetMessage(), echoed)
				}
			}
		})
	}
}

// Spec test 11 (plugin side): unknown and blank values. main_test.go checks
// the manifest against PARModes.
func TestConfigPushedAuthorization(t *testing.T) {
	idp := newIdP(t)
	for value, want := range map[string]string{"": PARWhenSupported, "  always ": PARAlways, PARNever: PARNever} {
		cfg, err := ParseConfig(withPAR(baseSettings(idp), value).entries(t))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PushedAuthorization != want || len(cfg.Problems()) != 0 {
			t.Errorf("%q: mode = %q, problems = %v; want %q", value, cfg.PushedAuthorization, cfg.Problems(), want)
		}
	}
	cfg, err := ParseConfig(baseSettings(idp).entries(t))
	if err != nil || cfg.PushedAuthorization != PARWhenSupported {
		t.Fatalf("absent setting: mode = %q, err = %v; want %q", cfg.PushedAuthorization, err, PARWhenSupported)
	}

	unknown := withPAR(baseSettings(idp), "sometimes")
	cfg, err = ParseConfig(unknown.entries(t))
	if err != nil {
		t.Fatal(err)
	}
	if problems := strings.Join(cfg.Problems(), " "); !strings.Contains(problems, `Pushed authorization requests "sometimes" is not supported.`) {
		t.Fatalf("problems = %q", problems)
	}
	_, err = initAuthorize(t, context.Background(), newProvider(t, unknown), "s")
	requireCode(t, err, codes.FailedPrecondition, "sometimes")
	if last := lastStep(runTest(t, New(nil), unknown)); last.GetId() != stepSettings || last.GetOk() {
		t.Fatalf("connection test last step = %+v, want a failed settings step", last)
	}
}

// Spec test 12: pins the test provider's own request_uri handling: one used
// inside its lifetime completes, one used after it, or twice, is refused, and
// a provider that requires PAR refuses a browser-URL request.
func TestIdPRequestURILifetime(t *testing.T) {
	idp := parIdP(t)
	idp.Set(func(idp *oidctest.IdP) { idp.PARLifetime = 200 * time.Millisecond })
	p := newProvider(t, baseSettings(idp))

	requireAccount(t, signIn(t, p, idp, "alice").account)

	reused, err := initAuthorize(t, context.Background(), p, "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := idp.Login(reused.GetAuthorizeUrl(), "alice"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, _, err := idp.Login(reused.GetAuthorizeUrl(), "alice"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("second use of a request_uri: err = %v, want 400", err)
	}

	expired, err := initAuthorize(t, context.Background(), p, "s")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, _, err := idp.Login(expired.GetAuthorizeUrl(), "alice"); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expired request_uri: err = %v, want 400", err)
	}

	required := newIdP(t)
	required.Set(func(idp *oidctest.IdP) { idp.RequirePAR = true })
	plain, err := initAuthorize(t, context.Background(), newProvider(t, withPAR(baseSettings(required), PARNever)), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := required.Login(plain.GetAuthorizeUrl(), "alice"); err == nil {
		t.Fatal("a provider that requires PAR accepted a browser-URL request")
	}
	requireAccount(t, signIn(t, newProvider(t, baseSettings(required)), required, "alice").account)
}
