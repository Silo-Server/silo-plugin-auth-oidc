package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
)

// Test step IDs. They are stable; the host may key UI on them.
const (
	stepSettings   = "settings"
	stepDiscovery  = "discovery"
	stepIssuer     = "issuer"
	stepEndpoints  = "endpoints"
	stepJWKS       = "jwks"
	stepClientAuth = "client_auth"
	stepClient     = "client_credentials"
	stepPKCE       = "pkce"
	stepPAR        = "par"
	stepScopes     = "scopes"
	stepLogout     = "provider_logout"
)

// probeRedirectURI is sent with the fallback authorization-code probe and the
// test push. The code is invalid anyway, and a provider that accepts the push
// stores one unused request that expires on its own; the redirect only has to
// be a well-formed https URL.
const probeRedirectURI = "https://silo.invalid/api/v2/auth/oauth/0/callback"

// TestConnection checks the staged configuration in the request with a fresh
// client, so it neither uses nor changes the running configuration's caches.
func (p *Provider) TestConnection(ctx context.Context, req *pluginv1.AuthTestConnectionRequest) (*pluginv1.AuthTestConnectionResponse, error) {
	run := &testRun{}
	cfg, err := ParseConfig(req.GetConfig())
	if err != nil {
		run.fail(stepSettings, "Settings are valid", err.Error())
		return run.response(), nil
	}
	if problems := cfg.Problems(); len(problems) > 0 {
		run.fail(stepSettings, "Settings are valid", strings.Join(problems, " "))
		return run.response(), nil
	}
	client, err := oidc.NewClient(cfg.clientSettings())
	if err != nil {
		run.fail(stepSettings, "Settings are valid", err.Error())
		return run.response(), nil
	}
	if problems := cfg.LifetimeProblems(); len(problems) > 0 {
		// Sign-in works without the lifetimes, so the remaining steps run.
		run.fail(stepSettings, "Settings are valid", strings.Join(problems, " "))
	} else {
		run.pass(stepSettings, "Settings are valid", "Issuer, client ID and options are set.")
	}

	doc, err := client.FetchDiscovery(ctx)
	if err != nil {
		run.fail(stepDiscovery, "Discovery document reachable", fmt.Sprintf("Could not load %s: %v", oidc.DiscoveryURL(cfg.Issuer), err))
		return run.response(), nil
	}
	run.pass(stepDiscovery, "Discovery document reachable", "Loaded "+oidc.DiscoveryURL(cfg.Issuer)+".")

	if doc.Issuer != cfg.Issuer {
		message := fmt.Sprintf("The provider reports issuer %q, but the setting is %q. They must match exactly.", doc.Issuer, cfg.Issuer)
		if strings.TrimSuffix(doc.Issuer, "/") == strings.TrimSuffix(cfg.Issuer, "/") {
			message += " Only the trailing slash differs; copy the provider's value."
		}
		run.fail(stepIssuer, "Issuer matches", message)
		return run.response(), nil
	}
	run.pass(stepIssuer, "Issuer matches", "The provider reports issuer "+doc.Issuer+".")

	if err := oidc.ValidateDiscovery(doc, cfg.Issuer); err != nil {
		run.fail(stepEndpoints, "Endpoints present", err.Error())
		return run.response(), nil
	}
	endpointMessage := "Authorization, token and JWKS endpoints use https."
	if doc.UserinfoEndpoint == "" {
		endpointMessage += " The provider has no userinfo endpoint, so only ID token claims are used."
	}
	run.pass(stepEndpoints, "Endpoints present", endpointMessage)

	keys, err := client.JWKS(ctx, false)
	if err != nil {
		run.fail(stepJWKS, "Signing keys load", err.Error())
		return run.response(), nil
	}
	usable := 0
	for _, key := range keys.Keys {
		if key.Valid() && key.IsPublic() && (key.Use == "" || key.Use == "sig") {
			usable++
		}
	}
	advertised := doc.IDTokenSigningAlgValuesSupported
	acceptable := slices.ContainsFunc(advertised, client.AcceptsAlgorithm)
	// With HS256 allowed, a provider that only signs with the client secret
	// needs no public keys.
	secretSigned := cfg.AllowHS256 && slices.Contains(advertised, "HS256")
	switch {
	case len(advertised) > 0 && !acceptable:
		message := fmt.Sprintf("The provider signs ID tokens with %s, which is not accepted.", strings.Join(advertised, ", "))
		if slices.Contains(advertised, "HS256") {
			message += " Configure a signing key at the provider, or turn on \"Allow HS256\"."
		}
		run.fail(stepJWKS, "Signing keys load", message)
		return run.response(), nil
	case usable == 0 && !secretSigned:
		run.fail(stepJWKS, "Signing keys load", "The JWKS has no public signing keys.")
		return run.response(), nil
	}
	run.pass(stepJWKS, "Signing keys load", fmt.Sprintf("%d signing key(s); ID token algorithms: %s.", usable, listOrUnknown(advertised)))

	methods := doc.TokenEndpointAuthMethodsSupported
	if len(methods) == 0 {
		// The discovery default per OpenID Connect Discovery 1.0.
		methods = []string{oidc.AuthMethodBasic}
	}
	if !slices.Contains(methods, cfg.TokenAuthMethod) {
		run.fail(stepClientAuth, "Client authentication method supported",
			fmt.Sprintf("The provider supports %s, not %s.", strings.Join(methods, ", "), cfg.TokenAuthMethod))
		return run.response(), nil
	}
	run.pass(stepClientAuth, "Client authentication method supported", cfg.TokenAuthMethod+" is supported.")

	verdict, seen, probeErr := client.ProbeClientAuth(ctx, probeRedirectURI)
	switch {
	case probeErr != nil:
		run.fail(stepClient, "Client credentials accepted", "Token endpoint unreachable: "+probeErr.Error())
		return run.response(), nil
	case verdict == oidc.ProbeRejected:
		run.fail(stepClient, "Client credentials accepted", fmt.Sprintf("The provider rejected the client ID or secret (%s).", seen))
		return run.response(), nil
	case verdict == oidc.ProbeAccepted:
		run.pass(stepClient, "Client credentials accepted", "The provider accepted the client ID and secret.")
	default:
		run.pass(stepClient, "Client credentials accepted",
			fmt.Sprintf("Could not confirm the client secret: the provider answered %s to test requests. Sign in once to confirm.", seen))
	}
	if cfg.ClientSecret == "" {
		run.steps[len(run.steps)-1].Message += " No client secret is set, so the provider must treat Silo as a public client."
	}

	switch challenge := doc.CodeChallengeMethodsSupported; {
	case len(challenge) == 0:
		run.pass(stepPKCE, "PKCE S256", "The provider does not advertise PKCE methods; Silo sends S256 anyway.")
	case !slices.Contains(challenge, "S256"):
		run.fail(stepPKCE, "PKCE S256", "The provider lists code challenge methods "+strings.Join(challenge, ", ")+" without S256. Silo always sends S256.")
		return run.response(), nil
	default:
		run.pass(stepPKCE, "PKCE S256", "The provider supports S256.")
	}

	if !run.pushedAuthorization(ctx, cfg, client, doc) {
		return run.response(), nil
	}

	requested := cfg.RequestedScopes()
	scopeMessage := "Requesting " + strings.Join(requested, " ") + "."
	if len(doc.ScopesSupported) > 0 {
		var missing []string
		for _, scope := range requested {
			if !slices.Contains(doc.ScopesSupported, scope) {
				missing = append(missing, scope)
			}
		}
		if len(missing) > 0 {
			scopeMessage += fmt.Sprintf(" Not advertised by the provider: %s. Some providers refuse the sign-in for unknown scopes.", strings.Join(missing, ", "))
		}
	}
	if cfg.RequestOfflineAccess {
		scopeMessage += " Silo re-checks accounts with the refresh token when the provider grants offline_access." +
			" Its refresh-token lifetime must be longer than Silo's re-check interval plus about an hour." +
			" A refused refresh token signs the person out of Silo only while the token is known to be inside its lifetime," +
			" from the provider's refresh_expires_in, the exp of a JWT refresh token, or Refresh token lifetime;" +
			" otherwise the sessions keep an absolute age limit."
		if cfg.RefreshTokenLifetime > 0 {
			scopeMessage += fmt.Sprintf(" Refresh token lifetime is %s, so a refusal within it counts as a revocation.",
				strings.TrimSpace(cfg.lifetimeInputs[labelRefreshLifetime]))
		} else {
			scopeMessage += " Refresh token lifetime is blank, so Silo detects revocations only when the provider reports a lifetime." +
				" Keycloak reports one for offline tokens only when Offline Session Max Limited is on;" +
				" otherwise enter the realm's Offline Session Idle (30d by default)."
		}
	} else {
		scopeMessage += " Without offline access Silo does not re-check accounts at the provider; their sessions get an absolute age limit."
	}
	run.pass(stepScopes, "Scopes", scopeMessage)

	if cfg.ProviderLogout {
		if doc.EndSessionEndpoint == "" {
			run.pass(stepLogout, "Provider sign-out", "The provider has no end_session_endpoint; web sign-out ends only the Silo session.")
		} else {
			run.pass(stepLogout, "Provider sign-out", "Web sign-out also signs out at "+doc.EndSessionEndpoint+
				". Register Silo's sign-in page as a post-logout redirect URI at the provider"+
				" (Keycloak: Valid post logout redirect URIs; Zitadel: Post Logout URIs), or it refuses the sign-out.")
		}
	}
	return run.response(), nil
}

// pushedAuthorization runs the par step and reports whether the test goes on.
// When the staged settings would use PAR it pushes a test request through the
// same code sign-in uses.
func (r *testRun) pushedAuthorization(ctx context.Context, cfg Config, client *oidc.Client, doc *oidc.Discovery) bool {
	advertised := doc.PushedAuthorizationRequestEndpoint != ""
	if cfg.PushedAuthorization == PARNever {
		switch {
		case bool(doc.RequirePushedAuthorizationRequests):
			r.fail(stepPAR, labelPAR, "The provider requires pushed authorization requests, but the setting is Never, so the provider refuses every sign-in."+
				" Choose When the provider supports it or Always.")
			return false
		case advertised:
			r.pass(stepPAR, labelPAR, "Turned off. The provider offers them; Silo sends the sign-in request in the browser URL.")
		default:
			r.pass(stepPAR, labelPAR, "Turned off. The provider does not offer them either.")
		}
		return true
	}
	use, err := usePAR(cfg, doc)
	if err != nil {
		r.fail(stepPAR, labelPAR, "The setting is Always, but the provider does not offer pushed authorization requests"+
			" (its discovery document has no pushed_authorization_request_endpoint), so every sign-in fails."+
			" Choose When the provider supports it or Never.")
		return false
	}
	if !use {
		r.pass(stepPAR, labelPAR, "The provider does not offer them, so Silo sends the sign-in request in the browser URL.")
		return true
	}

	verifier, verifierErr := oidc.RandomToken(32)
	nonce, nonceErr := oidc.RandomToken(32)
	if err := errors.Join(verifierErr, nonceErr); err != nil {
		r.fail(stepPAR, labelPAR, "Could not generate a test request: "+err.Error())
		return false
	}
	_, err = client.PushAuthorization(ctx, doc, oidc.AuthRequest{
		RedirectURI:   probeRedirectURI,
		State:         "silo-connection-test",
		Nonce:         nonce,
		CodeChallenge: oidc.S256Challenge(verifier),
		Scopes:        cfg.RequestedScopes(),
		Prompt:        cfg.Prompt,
	})
	var oauthErr *oidc.OAuthError
	var answerErr *oidc.AnswerError
	switch {
	case err == nil:
		r.pass(stepPAR, labelPAR, "The provider accepted a test request, so Silo sends sign-in requests over the back channel.")
		return true
	case errors.As(err, &oauthErr) && (oauthErr.Code == "invalid_client" || oauthErr.Code == "unauthorized_client" || oauthErr.Status == http.StatusUnauthorized),
		errors.As(err, &answerErr) && answerErr.Status == http.StatusUnauthorized:
		r.fail(stepPAR, labelPAR, fmt.Sprintf("The provider refused the client at its pushed authorization request endpoint (%v)."+
			" Check the client secret and Client authentication (Pocket ID may need Form body), or choose Never to sign in without them.", err))
		return false
	case errors.As(err, &oauthErr) && oauthErr.Status == http.StatusBadRequest && oauthErr.Code == "unknown_error":
		// Pocket ID v2.9.0 answers a refused client and a refused redirect
		// URI alike, with free text as the error code.
		r.pass(stepPAR, labelPAR, "Not confirmed: the provider answered 400 with an error Silo does not recognize,"+
			" so the test could not tell a refused client from a refused test redirect URI. Sign in once to confirm."+
			" If sign-in fails, try the other Client authentication method (Pocket ID v2.9.0 needs Form body)"+
			" or set Pushed authorization requests to Never.")
		return true
	case errors.As(err, &oauthErr) && oauthErr.Status == http.StatusBadRequest:
		r.pass(stepPAR, labelPAR, fmt.Sprintf("Not confirmed: the endpoint answered %d %s to a test request and did not refuse the client."+
			" The test cannot send Silo's real redirect URI, so sign in once to confirm.", oauthErr.Status, oauthErr.Code))
		return true
	default:
		r.fail(stepPAR, labelPAR, fmt.Sprintf("The test request failed (%v), so every sign-in would fail."+
			" Choose Never to sign in without pushed authorization requests.", err))
		return false
	}
}

type testRun struct {
	steps []*pluginv1.AuthTestStep
}

func (r *testRun) pass(id, label, message string) {
	r.steps = append(r.steps, &pluginv1.AuthTestStep{Id: id, Label: label, Ok: true, Message: message})
}

func (r *testRun) fail(id, label, message string) {
	r.steps = append(r.steps, &pluginv1.AuthTestStep{Id: id, Label: label, Ok: false, Message: message})
}

func (r *testRun) response() *pluginv1.AuthTestConnectionResponse {
	ok := len(r.steps) > 0
	for _, step := range r.steps {
		ok = ok && step.GetOk()
	}
	return &pluginv1.AuthTestConnectionResponse{Steps: r.steps, Ok: ok}
}

func listOrUnknown(values []string) string {
	if len(values) == 0 {
		return "not advertised"
	}
	return strings.Join(values, ", ")
}
