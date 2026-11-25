// Package oidc is a small OpenID Connect relying-party client: discovery,
// JWKS, the authorization-code and refresh grants, ID token validation, and
// userinfo. It knows nothing about Silo accounts.
package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Token endpoint client authentication methods.
const (
	AuthMethodBasic = "client_secret_basic"
	AuthMethodPost  = "client_secret_post"
)

const (
	httpTimeout            = 15 * time.Second
	discoveryTTL           = time.Hour
	jwksMinRefresh         = 10 * time.Second
	clockSkew              = 2 * time.Minute
	maxResponseBytes       = 1 << 20
	wellKnownConfiguration = ".well-known/openid-configuration"
)

// MinHS256SecretBytes is the smallest HMAC key go-jose accepts for HS256.
const MinHS256SecretBytes = 32

// ErrUnavailable marks failures to reach the provider: network errors,
// timeouts, and 5xx answers. Callers treat them as transient.
var ErrUnavailable = errors.New("identity provider unavailable")

// ErrConfig marks settings or provider metadata that cannot work, such as an
// issuer mismatch or a missing endpoint. Retrying does not help.
var ErrConfig = errors.New("identity provider misconfigured")

// ErrInvalidToken marks an ID token or signed userinfo response that failed
// validation.
var ErrInvalidToken = errors.New("invalid token")

// ErrSubjectMismatch marks a userinfo answer for another subject than the ID
// token. It wraps ErrInvalidToken; unlike the other validation failures it
// says the provider vouched for a different person, not that a check failed.
var ErrSubjectMismatch = fmt.Errorf("%w: userinfo sub does not match the ID token sub", ErrInvalidToken)

// Endpoint names used in errors.
const (
	EndpointToken = "token endpoint"
	EndpointPAR   = "pushed authorization request endpoint"
)

// maxRequestURIBytes caps the request_uri a PAR endpoint may return, so the
// authorization URL stays a usable length.
const maxRequestURIBytes = 2048

// OAuthError is an OAuth 2.0 error response from the token endpoint or the
// pushed authorization request endpoint. Description is set only for the
// token endpoint: a PAR endpoint may echo request values in it.
type OAuthError struct {
	Endpoint    string
	Status      int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s answered %d %s: %s", e.Endpoint, e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("%s answered %d %s", e.Endpoint, e.Status, e.Code)
}

// AnswerError is an answer from the pushed authorization request endpoint
// that is neither a usable request_uri nor an OAuth error: a redirect, a
// non-JSON 4xx, or a 2xx without a usable request_uri. It wraps ErrConfig.
// Reason is fixed text; it never quotes the answer.
type AnswerError struct {
	Endpoint string
	Status   int
	Reason   string
}

func (e *AnswerError) Error() string {
	return fmt.Sprintf("%s: %s answered %d %s", ErrConfig, e.Endpoint, e.Status, e.Reason)
}

func (e *AnswerError) Unwrap() error { return ErrConfig }

// knownOAuthErrors are the error codes a PAR answer may carry, from RFC 6749,
// RFC 9126, RFC 9101, and OpenID Connect Core. Any other value is reported as
// unknown_error, so the plugin never repeats text the provider made up.
var knownOAuthErrors = []string{
	"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
	"unsupported_grant_type", "invalid_scope", "access_denied", "unsupported_response_type",
	"server_error", "temporarily_unavailable", "invalid_request_uri", "invalid_request_object",
	"request_not_supported", "request_uri_not_supported", "invalid_redirect_uri",
	"interaction_required", "login_required", "account_selection_required", "consent_required",
	"invalid_authorization_details", "invalid_dpop_proof", "use_dpop_nonce",
}

// Settings configure a Client. Issuer is compared byte for byte with the
// discovery document and the iss claim; it is never normalized.
type Settings struct {
	Issuer          string
	ClientID        string
	ClientSecret    string
	TokenAuthMethod string
	// AllowHS256 accepts ID tokens signed with HS256 using the client secret.
	AllowHS256 bool
	// CAPEM adds PEM certificates to the system roots for every request.
	CAPEM string
}

// Discovery is the subset of the OpenID Provider metadata the client uses.
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	// PushedAuthorizationRequestEndpoint and RequirePushedAuthorizationRequests
	// are the RFC 9126 metadata. ValidateDiscovery does not check them, so a
	// bad value cannot break sign-in without PAR, code exchange, re-checks, or
	// provider logout. A value of the wrong type reads as absent.
	PushedAuthorizationRequestEndpoint lenientString `json:"pushed_authorization_request_endpoint"`
	RequirePushedAuthorizationRequests lenientBool   `json:"require_pushed_authorization_requests"`
	ScopesSupported                    []string      `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported  []string      `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported   []string      `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported      []string      `json:"code_challenge_methods_supported"`
}

// TokenResponse is a successful token endpoint answer.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	// Scope is the granted scope. Providers may omit it (Zitadel does) when it
	// equals the requested scope.
	Scope lenientString `json:"scope"`
	// RefreshExpiresIn is the refresh token lifetime in seconds, a Keycloak
	// extension. Zero means unknown; Keycloak sends 0 for offline tokens that
	// do not expire.
	RefreshExpiresIn lenientSeconds `json:"refresh_expires_in"`
}

// GrantsScope reports whether the response grants scope. A response without
// a scope field grants the requested scope (RFC 6749 section 5.1), so it
// counts as granted.
func (t *TokenResponse) GrantsScope(scope string) bool {
	if t.Scope == "" {
		return true
	}
	return slices.Contains(strings.Fields(string(t.Scope)), scope)
}

// RefreshExpiry returns when the refresh token expires, from
// refresh_expires_in or the exp claim of a JWT refresh token, or the zero time
// when the provider gives no hint.
func (t *TokenResponse) RefreshExpiry(now time.Time) time.Time {
	if t.RefreshToken == "" {
		return time.Time{}
	}
	if t.RefreshExpiresIn > 0 {
		return now.Add(time.Duration(t.RefreshExpiresIn) * time.Second)
	}
	return jwtExpiry(t.RefreshToken)
}

// lenientString decodes a JSON string and ignores any other type, so an odd
// optional field cannot fail the whole token response.
type lenientString string

func (s *lenientString) UnmarshalJSON(data []byte) error {
	var value string
	if json.Unmarshal(data, &value) == nil {
		*s = lenientString(value)
	}
	return nil
}

// lenientBool decodes a JSON boolean and ignores any other type.
type lenientBool bool

func (b *lenientBool) UnmarshalJSON(data []byte) error {
	var value bool
	if json.Unmarshal(data, &value) == nil {
		*b = lenientBool(value)
	}
	return nil
}

// lenientSeconds decodes a JSON number or numeric string and ignores anything
// else.
type lenientSeconds int64

func (s *lenientSeconds) UnmarshalJSON(data []byte) error {
	var number json.Number
	if json.Unmarshal(data, &number) != nil {
		var text string
		if json.Unmarshal(data, &text) != nil {
			return nil
		}
		number = json.Number(strings.TrimSpace(text))
	}
	if value, err := number.Int64(); err == nil {
		*s = lenientSeconds(value)
	}
	return nil
}

// Client talks to one OpenID provider. It caches discovery and JWKS in
// memory; both rebuild after a process restart. It is safe for concurrent use.
type Client struct {
	settings Settings
	http     *http.Client

	mu         sync.Mutex
	doc        *Discovery
	docFetched time.Time
	keys       *jose.JSONWebKeySet
	keysForced time.Time
}

// NewClient validates settings and builds a client. It does no network I/O.
func NewClient(settings Settings) (*Client, error) {
	if strings.TrimSpace(settings.Issuer) == "" {
		return nil, fmt.Errorf("%w: issuer URL is not set", ErrConfig)
	}
	if err := requireHTTPS(settings.Issuer, "issuer URL"); err != nil {
		return nil, err
	}
	if strings.TrimSpace(settings.ClientID) == "" {
		return nil, fmt.Errorf("%w: client ID is not set", ErrConfig)
	}
	switch settings.TokenAuthMethod {
	case "":
		settings.TokenAuthMethod = AuthMethodBasic
	case AuthMethodBasic, AuthMethodPost:
	default:
		return nil, fmt.Errorf("%w: unsupported token endpoint auth method %q", ErrConfig, settings.TokenAuthMethod)
	}
	if settings.AllowHS256 && len(settings.ClientSecret) < MinHS256SecretBytes {
		return nil, fmt.Errorf("%w: HS256 needs a client secret of at least %d bytes", ErrConfig, MinHS256SecretBytes)
	}
	httpClient, err := NewHTTPClient(settings.CAPEM)
	if err != nil {
		return nil, err
	}
	return &Client{settings: settings, http: httpClient}, nil
}

// NewHTTPClient returns an HTTP client that trusts the system roots plus the
// PEM certificates in caPEM. There is deliberately no way to skip
// verification.
func NewHTTPClient(caPEM string) (*http.Client, error) {
	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport has an unexpected type")
	}
	transport = transport.Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if strings.TrimSpace(caPEM) != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, fmt.Errorf("%w: custom CA contains no PEM certificates", ErrConfig)
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Timeout:   httpTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
			}
			return nil
		},
	}, nil
}

// DiscoveryURL returns the discovery document URL for an issuer. The path is
// appended without adding a second slash, so an issuer that ends in "/"
// (authentik) keeps its exact form.
func DiscoveryURL(issuer string) string {
	if strings.HasSuffix(issuer, "/") {
		return issuer + wellKnownConfiguration
	}
	return issuer + "/" + wellKnownConfiguration
}

// Discovery returns the provider metadata, from cache when fresh.
func (c *Client) Discovery(ctx context.Context) (*Discovery, error) {
	c.mu.Lock()
	if c.doc != nil && time.Since(c.docFetched) < discoveryTTL {
		doc := c.doc
		c.mu.Unlock()
		return doc, nil
	}
	c.mu.Unlock()

	doc, err := c.FetchDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if err := ValidateDiscovery(doc, c.settings.Issuer); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.doc = doc
	c.docFetched = time.Now()
	c.mu.Unlock()
	return doc, nil
}

// FetchDiscovery downloads and decodes the discovery document without
// validating it or touching the cache.
func (c *Client) FetchDiscovery(ctx context.Context) (*Discovery, error) {
	var doc Discovery
	if err := c.getJSON(ctx, DiscoveryURL(c.settings.Issuer), &doc); err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	return &doc, nil
}

// ValidateDiscovery checks the issuer matches exactly and the endpoints the
// client needs are present and use https.
func ValidateDiscovery(doc *Discovery, issuer string) error {
	if doc.Issuer != issuer {
		return fmt.Errorf("%w: discovery issuer %q does not exactly match the configured issuer %q", ErrConfig, doc.Issuer, issuer)
	}
	required := []struct{ name, value string }{
		{"authorization_endpoint", doc.AuthorizationEndpoint},
		{"token_endpoint", doc.TokenEndpoint},
		{"jwks_uri", doc.JWKSURI},
	}
	for _, endpoint := range required {
		if endpoint.value == "" {
			return fmt.Errorf("%w: discovery has no %s", ErrConfig, endpoint.name)
		}
		if err := requireHTTPS(endpoint.value, endpoint.name); err != nil {
			return err
		}
	}
	for _, endpoint := range []struct{ name, value string }{
		{"userinfo_endpoint", doc.UserinfoEndpoint},
		{"end_session_endpoint", doc.EndSessionEndpoint},
	} {
		if endpoint.value != "" {
			if err := requireHTTPS(endpoint.value, endpoint.name); err != nil {
				return err
			}
		}
	}
	return nil
}

// JWKS returns the provider's signing keys. With force set it refetches them,
// at most once per minimum refresh interval, so tokens with made-up key IDs
// cannot make the plugin hammer the provider.
func (c *Client) JWKS(ctx context.Context, force bool) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	cached := c.keys
	if cached != nil {
		if !force || time.Since(c.keysForced) < jwksMinRefresh {
			c.mu.Unlock()
			return cached, nil
		}
		c.keysForced = time.Now()
	}
	c.mu.Unlock()
	doc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	var set jose.JSONWebKeySet
	if err := c.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	c.mu.Lock()
	c.keys = &set
	c.mu.Unlock()
	return &set, nil
}

// Prepare loads discovery and the signing keys into the cache, so the calls
// that follow do not wait on them. A caller with a deadline runs it before
// deciding whether enough time is left for a grant it cannot take back.
func (c *Client) Prepare(ctx context.Context) error {
	if _, err := c.Discovery(ctx); err != nil {
		return err
	}
	_, err := c.JWKS(ctx, false)
	return err
}

// AuthRequest holds the parameters of one authorization request.
type AuthRequest struct {
	RedirectURI   string
	State         string
	Nonce         string
	CodeChallenge string
	Scopes        []string
	Prompt        string
	LoginHint     string
}

// values returns the authorization request parameters. The browser URL and
// the pushed request both use it, so PKCE S256 and the nonce are always sent,
// whatever discovery advertises.
func (r AuthRequest) values(clientID string) url.Values {
	values := url.Values{}
	values.Set("response_type", "code")
	values.Set("client_id", clientID)
	values.Set("redirect_uri", r.RedirectURI)
	values.Set("scope", strings.Join(r.Scopes, " "))
	values.Set("state", r.State)
	values.Set("nonce", r.Nonce)
	values.Set("code_challenge", r.CodeChallenge)
	values.Set("code_challenge_method", "S256")
	if r.Prompt != "" {
		values.Set("prompt", r.Prompt)
	}
	if r.LoginHint != "" {
		values.Set("login_hint", r.LoginHint)
	}
	return values
}

// AuthCodeURL builds the authorization URL with every parameter in its query,
// keeping any query the endpoint already has.
func (c *Client) AuthCodeURL(doc *Discovery, request AuthRequest) (string, error) {
	return authorizationURL(doc, request.values(c.settings.ClientID))
}

// PushAuthorization sends the authorization request to the provider's
// pushed authorization request endpoint (RFC 9126), authenticated as the
// client, and returns the authorization URL, which carries only client_id
// and the returned request_uri. The push never follows a redirect: a 307 or
// 308 would resend the form, and with client_secret_post the secret, to
// another URL.
//
// Network errors, timeouts, 5xx and 429 answers wrap ErrUnavailable. A JSON
// OAuth error is an *OAuthError without a description. Any other answer is
// an *AnswerError. Neither repeats text from the answer.
func (c *Client) PushAuthorization(ctx context.Context, doc *Discovery, request AuthRequest) (string, error) {
	parEndpoint := string(doc.PushedAuthorizationRequestEndpoint)
	if parEndpoint == "" {
		return "", fmt.Errorf("%w: discovery has no pushed_authorization_request_endpoint", ErrConfig)
	}
	if err := requireHTTPS(parEndpoint, "pushed_authorization_request_endpoint"); err != nil {
		return "", err
	}
	if _, err := url.Parse(doc.AuthorizationEndpoint); err != nil {
		return "", fmt.Errorf("%w: authorization endpoint: %v", ErrConfig, err)
	}
	status, body, err := c.postForm(ctx, parEndpoint, EndpointPAR, request.values(c.settings.ClientID), false)
	if err != nil {
		return "", err
	}
	switch {
	case status >= 500 || status == http.StatusTooManyRequests:
		return "", fmt.Errorf("%w: %s answered %d", ErrUnavailable, EndpointPAR, status)
	case status >= 300 && status < 400:
		return "", &AnswerError{Endpoint: EndpointPAR, Status: status, Reason: "with a redirect, which Silo does not follow"}
	case status != http.StatusOK && status != http.StatusCreated:
		var oauthErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &oauthErr) != nil || oauthErr.Error == "" {
			return "", &AnswerError{Endpoint: EndpointPAR, Status: status, Reason: "with something other than a JSON OAuth error"}
		}
		code := oauthErr.Error
		if !slices.Contains(knownOAuthErrors, code) {
			code = "unknown_error"
		}
		return "", &OAuthError{Endpoint: EndpointPAR, Status: status, Code: code}
	}
	var answer struct {
		RequestURI lenientString `json:"request_uri"`
	}
	if json.Unmarshal(body, &answer) != nil {
		return "", &AnswerError{Endpoint: EndpointPAR, Status: status, Reason: "with a body that is not JSON"}
	}
	switch {
	case answer.RequestURI == "":
		return "", &AnswerError{Endpoint: EndpointPAR, Status: status, Reason: "with no request_uri"}
	case len(answer.RequestURI) > maxRequestURIBytes:
		return "", &AnswerError{Endpoint: EndpointPAR, Status: status,
			Reason: fmt.Sprintf("with a request_uri longer than %d bytes", maxRequestURIBytes)}
	}
	values := url.Values{}
	values.Set("client_id", c.settings.ClientID)
	values.Set("request_uri", string(answer.RequestURI))
	return authorizationURL(doc, values)
}

// authorizationURL adds values to the authorization endpoint's own query.
func authorizationURL(doc *Discovery, values url.Values) (string, error) {
	endpoint, err := url.Parse(doc.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("%w: authorization endpoint: %v", ErrConfig, err)
	}
	query := endpoint.Query()
	for name, value := range values {
		query[name] = value
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String(), nil
}

// Exchange redeems an authorization code with its PKCE verifier.
func (c *Client) Exchange(ctx context.Context, code, redirectURI, verifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", verifier)
	return c.token(ctx, form)
}

// Refresh redeems a refresh token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	return c.token(ctx, form)
}

// ProbeResult is the verdict of ProbeClientAuth.
type ProbeResult int

// Probe verdicts.
const (
	ProbeInconclusive ProbeResult = iota
	ProbeAccepted
	ProbeRejected
)

// ProbeClientAuth checks the client credentials without a user by sending
// grants that cannot succeed. Providers authenticate the client before they
// look at the grant, so invalid_grant means the credentials were accepted.
//
// It first sends a refresh_token grant with a made-up token: it carries no
// redirect_uri, which authentik checks before the code and answers with
// invalid_client when it is not registered. Only this probe can reject: an
// invalid_client error or an HTTP 401 (Keycloak answers 401
// unauthorized_client). When its answer is inconclusive, an
// authorization_code grant with a made-up code may still confirm the
// credentials. The returned detail names the error codes seen. An error
// means the token endpoint could not be reached.
func (c *Client) ProbeClientAuth(ctx context.Context, redirectURI string) (ProbeResult, string, error) {
	refresh := url.Values{}
	refresh.Set("grant_type", "refresh_token")
	refresh.Set("refresh_token", "silo-connection-test-invalid-refresh-token")
	_, err := c.token(ctx, refresh)
	var tokenErr *OAuthError
	switch {
	case err == nil:
		return ProbeAccepted, "", nil
	case !errors.As(err, &tokenErr):
		return ProbeInconclusive, "", err
	case tokenErr.Code == "invalid_client" || tokenErr.Status == http.StatusUnauthorized:
		return ProbeRejected, tokenErr.Code, nil
	case tokenErr.Code == "invalid_grant":
		return ProbeAccepted, tokenErr.Code, nil
	}
	first := tokenErr.Code

	code := url.Values{}
	code.Set("grant_type", "authorization_code")
	code.Set("code", "silo-connection-test-invalid-code")
	code.Set("redirect_uri", redirectURI)
	code.Set("code_verifier", strings.Repeat("A", 43))
	_, err = c.token(ctx, code)
	switch {
	case err == nil:
		return ProbeAccepted, first, nil
	case errors.As(err, &tokenErr) && tokenErr.Code == "invalid_grant":
		return ProbeAccepted, first + ", " + tokenErr.Code, nil
	case errors.As(err, &tokenErr):
		return ProbeInconclusive, first + ", " + tokenErr.Code, nil
	default:
		return ProbeInconclusive, first, nil
	}
}

func (c *Client) token(ctx context.Context, form url.Values) (*TokenResponse, error) {
	doc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	statusCode, body, err := c.postForm(ctx, doc.TokenEndpoint, EndpointToken, form, true)
	if err != nil {
		return nil, err
	}
	if statusCode >= 500 {
		return nil, fmt.Errorf("%w: token endpoint answered %d", ErrUnavailable, statusCode)
	}
	if statusCode != http.StatusOK {
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		code := oauthErr.Error
		if code == "" && statusCode == http.StatusUnauthorized {
			code = "invalid_client"
		}
		if code == "" {
			code = "unknown_error"
		}
		return nil, &OAuthError{Endpoint: EndpointToken, Status: statusCode, Code: code, Description: truncate(oauthErr.ErrorDescription, 200)}
	}
	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("%w: token response is not JSON: %v", ErrConfig, err)
	}
	return &token, nil
}

// postForm authenticates as the client and posts form to endpoint, the same
// way for the token and PAR endpoints: client_secret_basic, client_secret_post,
// or client_id alone without a secret. It returns the status and the body;
// only a failure to reach the endpoint or read the answer is an error, and it
// wraps ErrUnavailable. Without followRedirects a redirect is returned as the
// answer. name is the endpoint's name in errors.
func (c *Client) postForm(ctx context.Context, endpoint, name string, form url.Values, followRedirects bool) (int, []byte, error) {
	headers := http.Header{}
	switch c.settings.TokenAuthMethod {
	case AuthMethodPost:
		form.Set("client_id", c.settings.ClientID)
		if c.settings.ClientSecret != "" {
			form.Set("client_secret", c.settings.ClientSecret)
		}
	default:
		if c.settings.ClientSecret == "" {
			form.Set("client_id", c.settings.ClientID)
		} else {
			// RFC 6749 section 2.3.1: form-encode both parts before Basic.
			headers.Set("Authorization", "Basic "+basicAuth(
				url.QueryEscape(c.settings.ClientID), url.QueryEscape(c.settings.ClientSecret)))
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s: %v", ErrConfig, name, err)
	}
	req.Header = headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	httpClient := c.http
	if !followRedirects {
		noRedirects := *c.http
		noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		httpClient = &noRedirects
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s request: %v", ErrUnavailable, name, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s response: %v", ErrUnavailable, name, err)
	}
	return resp.StatusCode, body, nil
}

// UserInfo fetches the userinfo claims with an access token. It accepts plain
// JSON and signed (application/jwt) answers, and requires sub to equal
// expectedSubject; a different sub is ErrSubjectMismatch.
func (c *Client) UserInfo(ctx context.Context, accessToken, expectedSubject string) (map[string]any, error) {
	doc, err := c.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	if doc.UserinfoEndpoint == "" {
		return nil, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, doc.UserinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo endpoint: %v", ErrConfig, err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json, application/jwt")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo request: %v", ErrUnavailable, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: userinfo response: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: userinfo endpoint answered %d", ErrUnavailable, resp.StatusCode)
	}
	var claims map[string]any
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaType == "application/jwt" {
		claims, err = c.verifySignedUserInfo(ctx, strings.TrimSpace(string(body)))
		if err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("%w: userinfo response is not JSON: %v", ErrConfig, err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" || sub != expectedSubject {
		return nil, ErrSubjectMismatch
	}
	return claims, nil
}

func (c *Client) getJSON(ctx context.Context, rawURL string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConfig, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, redactURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("%w: %s answered %d", ErrUnavailable, rawURL, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s answered %d", ErrConfig, rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("%w: %s did not return valid JSON: %v", ErrConfig, rawURL, err)
	}
	return nil
}

func requireHTTPS(raw, name string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("%w: %s %q is not an absolute URL", ErrConfig, name, raw)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("%w: %s must use https", ErrConfig, name)
	}
	return nil
}

func redactURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
