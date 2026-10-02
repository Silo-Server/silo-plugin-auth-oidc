package provider

import (
	"context"
	"fmt"
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
	stepScopes     = "scopes"
	stepLogout     = "provider_logout"
)

// probeRedirectURI is sent with the fallback authorization-code probe. The
// code is invalid anyway; the redirect only has to be a well-formed https URL.
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
