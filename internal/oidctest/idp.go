// Package oidctest runs an in-process OpenID Connect provider for tests. It
// serves discovery, JWKS, authorize, token, userinfo, and end-session over TLS
// with keys generated at start, and exposes knobs for the quirks of real
// providers.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// User is one account at the test provider.
type User struct {
	Subject string
	// IDTokenClaims are added to the ID token.
	IDTokenClaims map[string]any
	// UserinfoClaims are returned from userinfo (sub is added).
	UserinfoClaims map[string]any
}

// Request records one call to the authorize or token endpoint.
type Request struct {
	Query         url.Values
	Form          url.Values
	Authorization string
}

type grant struct {
	user          string
	nonce         string
	challenge     string
	method        string
	redirectURI   string
	scope         string
	refreshSerial int
}

type signingKey struct {
	alg     jose.SignatureAlgorithm
	kid     string
	private any
	public  any
}

// IdP is the test provider. Change its exported knobs before the call they
// affect; they are read under its lock.
type IdP struct {
	t      testing.TB
	server *httptest.Server

	// Issuer is the exact issuer string. Set IssuerSuffix at construction to
	// add a trailing slash or path.
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURIs []string

	mu sync.Mutex
	// Users by login name.
	Users map[string]*User
	// OmitRefreshToken stops issuing refresh tokens. Otherwise a refresh token
	// is issued whether or not offline_access was requested, as Keycloak and
	// Kanidm issue refresh tokens bound to the browser session.
	OmitRefreshToken bool
	// RefuseOfflineAccess drops offline_access from the granted scope while
	// still issuing a refresh token (Kanidm, Tinyauth, a Keycloak client
	// without the offline_access scope).
	RefuseOfflineAccess bool
	// OmitScope leaves scope out of token responses, as Zitadel does.
	OmitScope bool
	// RefreshExpiresIn, when set, is sent as refresh_expires_in (Keycloak
	// with Offline Session Max Limited on).
	RefreshExpiresIn int
	// ZeroRefreshExpiresIn sends refresh_expires_in 0, as Keycloak does for
	// offline tokens while Offline Session Max Limited is off.
	ZeroRefreshExpiresIn bool
	// RotateRefreshTokens issues a new refresh token on every refresh and
	// revokes the old one.
	RotateRefreshTokens bool
	// EchoRefreshToken answers a refresh with the presented refresh token
	// instead of a new one, as providers without rotation may.
	EchoRefreshToken bool
	// LoseRefreshResponse commits a refresh, rotation included, and then
	// answers with this HTTP status instead of the tokens, or closes the
	// connection without an answer when it is -1: the provider spent the
	// token, but the client never learns the new one.
	LoseRefreshResponse int
	// OmitIDTokenOnRefresh leaves id_token out of refresh answers.
	OmitIDTokenOnRefresh bool
	// MutateIDToken edits ID token claims just before signing.
	MutateIDToken func(claims map[string]any)
	// MutateDiscovery edits the discovery document before it is served.
	MutateDiscovery func(doc map[string]any)
	// SignedUserinfo answers userinfo as an application/jwt.
	SignedUserinfo bool
	// UserinfoStatus, when set, is returned by userinfo instead of claims.
	UserinfoStatus int
	// UserinfoDelay holds each userinfo answer back, or until the client
	// gives up.
	UserinfoDelay time.Duration
	// DiscoveryDelay, JWKSDelay, and TokenDelay hold those answers back the
	// same way. A token request the client gives up on is not processed.
	DiscoveryDelay time.Duration
	JWKSDelay      time.Duration
	TokenDelay     time.Duration
	// SignWithForeignKey signs ID tokens and signed userinfo with a key the
	// JWKS never publishes, under the current kid; with HS256, with a wrong
	// secret.
	SignWithForeignKey bool
	// TokenStatus, when set, makes the token endpoint answer with this status.
	TokenStatus int
	// AuthMethod requires client_secret_basic or client_secret_post; empty
	// accepts both.
	AuthMethod string
	// HS256 signs ID tokens with the client secret.
	HS256 bool
	// CheckRedirectAsClient answers an authorization_code grant whose
	// redirect_uri is not registered with invalid_client before looking at the
	// code, as authentik does.
	CheckRedirectAsClient bool
	// BadClientStatus and BadClientError replace the answer to failed client
	// authentication (default 401 invalid_client). Keycloak answers 401
	// unauthorized_client.
	BadClientStatus int
	BadClientError  string

	keys      []*signingKey
	current   *signingKey
	foreign   *signingKey
	serial    int
	codes     map[string]*grant
	refreshes map[string]*grant
	access    map[string]*grant

	// Recorded traffic.
	Authorizes    []Request
	Tokens        []Request
	DiscoveryHits int
	JWKSFetches   int
	UserinfoHits  int
}

// Option configures New.
type Option func(*options)

type options struct {
	issuerSuffix string
	alg          jose.SignatureAlgorithm
}

// WithIssuerSuffix appends a path to the issuer, such as "/application/o/silo/".
func WithIssuerSuffix(suffix string) Option {
	return func(o *options) { o.issuerSuffix = suffix }
}

// WithAlgorithm picks the initial signing algorithm (default RS256).
func WithAlgorithm(alg jose.SignatureAlgorithm) Option {
	return func(o *options) { o.alg = alg }
}

// New starts a provider; it stops when the test ends.
func New(t testing.TB, opts ...Option) *IdP {
	t.Helper()
	o := options{alg: jose.RS256}
	for _, opt := range opts {
		opt(&o)
	}
	idp := &IdP{
		t:            t,
		ClientID:     "silo",
		ClientSecret: "test-client-secret-0123456789abcdef",
		Users:        map[string]*User{},
		codes:        map[string]*grant{},
		refreshes:    map[string]*grant{},
		access:       map[string]*grant{},
	}
	mux := http.NewServeMux()
	idp.server = httptest.NewTLSServer(mux)
	t.Cleanup(idp.server.Close)
	idp.Issuer = idp.server.URL + o.issuerSuffix
	base := strings.TrimSuffix(idp.Issuer, "/")
	prefix := strings.TrimPrefix(base, idp.server.URL)
	mux.HandleFunc(prefix+"/.well-known/openid-configuration", idp.handleDiscovery)
	mux.HandleFunc(prefix+"/authorize", idp.handleAuthorize)
	mux.HandleFunc(prefix+"/token", idp.handleToken)
	mux.HandleFunc(prefix+"/userinfo", idp.handleUserinfo)
	mux.HandleFunc(prefix+"/jwks", idp.handleJWKS)
	mux.HandleFunc(prefix+"/logout", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	idp.RotateKey(o.alg)
	return idp
}

// CAPEM returns the test server's certificate as PEM, for the custom CA
// setting.
func (idp *IdP) CAPEM() string {
	cert := idp.server.Certificate()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// URL returns the server's base URL.
func (idp *IdP) URL() string { return idp.server.URL }

func (idp *IdP) endpoint(name string) string {
	return strings.TrimSuffix(idp.Issuer, "/") + "/" + name
}

// AddUser registers a user under login name.
func (idp *IdP) AddUser(login string, user *User) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.Users[login] = user
}

// RotateKey replaces the signing key with a new one for alg under a new kid.
func (idp *IdP) RotateKey(alg jose.SignatureAlgorithm) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.serial++
	key := newSigningKey(idp.t, alg, idp.serial)
	idp.keys = []*signingKey{key}
	idp.current = key
	// A foreign key shares the current kid and algorithm.
	idp.foreign = newSigningKey(idp.t, alg, idp.serial)
}

// Revoke invalidates every refresh token issued so far.
func (idp *IdP) Revoke() {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.refreshes = map[string]*grant{}
}

// Set runs fn under the provider's lock, for changing knobs mid-test.
func (idp *IdP) Set(fn func(idp *IdP)) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	fn(idp)
}

func newSigningKey(t testing.TB, alg jose.SignatureAlgorithm, serial int) *signingKey {
	t.Helper()
	key := &signingKey{alg: alg, kid: fmt.Sprintf("key-%d-%s", serial, strings.ToLower(string(alg)))}
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512:
		private, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate RSA key: %v", err)
		}
		key.private, key.public = private, &private.PublicKey
	case jose.ES256, jose.ES384, jose.ES512:
		curve := map[jose.SignatureAlgorithm]elliptic.Curve{
			jose.ES256: elliptic.P256(), jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521(),
		}[alg]
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		key.private, key.public = private, &private.PublicKey
	case jose.EdDSA:
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate Ed25519 key: %v", err)
		}
		key.private, key.public = private, public
	default:
		t.Fatalf("unsupported test algorithm %s", alg)
	}
	return key
}

func (idp *IdP) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	if !idp.wait(r, func() time.Duration { return idp.DiscoveryDelay }) {
		return
	}
	idp.mu.Lock()
	idp.DiscoveryHits++
	algs := []string{string(idp.current.alg)}
	if idp.HS256 {
		algs = []string{"HS256"}
	}
	doc := map[string]any{
		"issuer":                                idp.Issuer,
		"authorization_endpoint":                idp.endpoint("authorize"),
		"token_endpoint":                        idp.endpoint("token"),
		"userinfo_endpoint":                     idp.endpoint("userinfo"),
		"jwks_uri":                              idp.endpoint("jwks"),
		"end_session_endpoint":                  idp.endpoint("logout"),
		"scopes_supported":                      []string{"openid", "profile", "email", "groups", "offline_access"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": algs,
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	if idp.MutateDiscovery != nil {
		idp.MutateDiscovery(doc)
	}
	idp.mu.Unlock()
	writeJSON(w, http.StatusOK, doc)
}

func (idp *IdP) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if !idp.wait(r, func() time.Duration { return idp.JWKSDelay }) {
		return
	}
	idp.mu.Lock()
	idp.JWKSFetches++
	set := jose.JSONWebKeySet{}
	for _, key := range idp.keys {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: key.public, KeyID: key.kid, Algorithm: string(key.alg), Use: "sig"})
	}
	idp.mu.Unlock()
	writeJSON(w, http.StatusOK, set)
}

// handleAuthorize logs in the user named by the test-only "test_user"
// parameter and redirects back with a code, as a browser would see it.
func (idp *IdP) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.Authorizes = append(idp.Authorizes, Request{Query: query})
	if query.Get("client_id") != idp.ClientID || query.Get("response_type") != "code" {
		http.Error(w, "bad client or response type", http.StatusBadRequest)
		return
	}
	redirectURI := query.Get("redirect_uri")
	if len(idp.RedirectURIs) > 0 && !slices.Contains(idp.RedirectURIs, redirectURI) {
		http.Error(w, "redirect_uri not registered", http.StatusBadRequest)
		return
	}
	if _, ok := idp.Users[query.Get("test_user")]; !ok {
		http.Error(w, "unknown test_user", http.StatusBadRequest)
		return
	}
	code := randomString()
	idp.codes[code] = &grant{
		user:        query.Get("test_user"),
		nonce:       query.Get("nonce"),
		challenge:   query.Get("code_challenge"),
		method:      query.Get("code_challenge_method"),
		redirectURI: redirectURI,
		scope:       query.Get("scope"),
	}
	target, _ := url.Parse(redirectURI)
	values := target.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (idp *IdP) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if !idp.wait(r, func() time.Duration { return idp.TokenDelay }) {
		return
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.Tokens = append(idp.Tokens, Request{Form: r.PostForm, Authorization: r.Header.Get("Authorization")})
	if idp.TokenStatus != 0 {
		writeJSON(w, idp.TokenStatus, map[string]string{"error": "server_error"})
		return
	}
	if !idp.clientAuthenticated(r) {
		code, errorCode := http.StatusUnauthorized, "invalid_client"
		if idp.BadClientStatus != 0 {
			code, errorCode = idp.BadClientStatus, idp.BadClientError
		}
		writeJSON(w, code, map[string]string{"error": errorCode})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		if idp.CheckRedirectAsClient && !slices.Contains(idp.RedirectURIs, r.PostForm.Get("redirect_uri")) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
			return
		}
		g, ok := idp.codes[r.PostForm.Get("code")]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		delete(idp.codes, r.PostForm.Get("code"))
		if g.redirectURI != r.PostForm.Get("redirect_uri") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
			return
		}
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if g.method != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		idp.issueTokens(w, g, true, "")
	case "refresh_token":
		g, ok := idp.refreshes[r.PostForm.Get("refresh_token")]
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "refresh token revoked"})
			return
		}
		if idp.RotateRefreshTokens {
			delete(idp.refreshes, r.PostForm.Get("refresh_token"))
		}
		presented := ""
		if idp.EchoRefreshToken {
			presented = r.PostForm.Get("refresh_token")
		}
		if idp.LoseRefreshResponse != 0 {
			idp.issueTokens(httptest.NewRecorder(), g, !idp.OmitIDTokenOnRefresh, presented)
			idp.loseResponse(w)
			return
		}
		idp.issueTokens(w, g, !idp.OmitIDTokenOnRefresh, presented)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (idp *IdP) clientAuthenticated(r *http.Request) bool {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
		if idp.AuthMethod == "client_secret_post" {
			return false
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		if idp.AuthMethod == "client_secret_basic" {
			return false
		}
	}
	return id == idp.ClientID && secret == idp.ClientSecret
}

// issueTokens answers a token request; the caller holds the lock. A
// non-empty reuseRefresh is sent back instead of a new refresh token.
func (idp *IdP) issueTokens(w http.ResponseWriter, g *grant, withIDToken bool, reuseRefresh string) {
	user := idp.Users[g.user]
	if user == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	access := "at-" + randomString()
	idp.access[access] = g
	response := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if withIDToken {
		now := time.Now()
		claims := map[string]any{
			"iss": idp.Issuer, "sub": user.Subject, "aud": idp.ClientID,
			"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(),
		}
		if g.nonce != "" {
			claims["nonce"] = g.nonce
		}
		maps.Copy(claims, user.IDTokenClaims)
		if idp.MutateIDToken != nil {
			idp.MutateIDToken(claims)
		}
		response["id_token"] = idp.sign(claims)
		// A refreshed ID token carries no nonce, per OIDC Core 12.2.
		g.nonce = ""
	}
	if !idp.OmitRefreshToken {
		refresh := reuseRefresh
		if refresh == "" {
			g.refreshSerial++
			refresh = fmt.Sprintf("rt-%d-%s", g.refreshSerial, randomString())
		}
		idp.refreshes[refresh] = g
		response["refresh_token"] = refresh
		if idp.RefreshExpiresIn != 0 || idp.ZeroRefreshExpiresIn {
			response["refresh_expires_in"] = idp.RefreshExpiresIn
		}
	}
	if !idp.OmitScope {
		granted := strings.Fields(g.scope)
		if idp.RefuseOfflineAccess {
			granted = slices.DeleteFunc(granted, func(scope string) bool { return scope == "offline_access" })
		}
		response["scope"] = strings.Join(granted, " ")
	}
	writeJSON(w, http.StatusOK, response)
}

// loseResponse answers with LoseRefreshResponse; the caller holds the lock.
func (idp *IdP) loseResponse(w http.ResponseWriter) {
	if idp.LoseRefreshResponse > 0 {
		writeJSON(w, idp.LoseRefreshResponse, map[string]string{"error": "bad_gateway"})
		return
	}
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		idp.t.Errorf("hijack the token response: %v", err)
		return
	}
	_ = conn.Close()
}

// wait holds a request back for the delay knob read under the lock, and
// reports false when the client gave up first.
func (idp *IdP) wait(r *http.Request, knob func() time.Duration) bool {
	idp.mu.Lock()
	delay := knob()
	idp.mu.Unlock()
	if delay <= 0 {
		return true
	}
	select {
	case <-time.After(delay):
		return true
	case <-r.Context().Done():
		return false
	}
}

func (idp *IdP) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	if !idp.wait(r, func() time.Duration { return idp.UserinfoDelay }) {
		return
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.UserinfoHits++
	if idp.UserinfoStatus != 0 {
		w.WriteHeader(idp.UserinfoStatus)
		return
	}
	access := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	g, ok := idp.access[access]
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	user := idp.Users[g.user]
	claims := map[string]any{"sub": user.Subject}
	maps.Copy(claims, user.UserinfoClaims)
	if idp.SignedUserinfo {
		claims["iss"] = idp.Issuer
		claims["aud"] = idp.ClientID
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(idp.sign(claims)))
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

// Sign signs claims with the current key, for tests that craft tokens.
func (idp *IdP) Sign(claims map[string]any) string {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.sign(claims)
}

func (idp *IdP) sign(claims map[string]any) string {
	var signingKey jose.SigningKey
	switch {
	case idp.HS256 && idp.SignWithForeignKey:
		signingKey = jose.SigningKey{Algorithm: jose.HS256, Key: []byte("not-the-client-secret-0123456789abcdef")}
	case idp.HS256:
		signingKey = jose.SigningKey{Algorithm: jose.HS256, Key: []byte(idp.ClientSecret)}
	default:
		key := idp.current
		if idp.SignWithForeignKey {
			key = idp.foreign
		}
		signingKey = jose.SigningKey{
			Algorithm: key.alg,
			Key:       jose.JSONWebKey{Key: key.private, KeyID: key.kid, Algorithm: string(key.alg)},
		}
	}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		idp.t.Fatalf("new signer: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		idp.t.Fatalf("marshal claims: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		idp.t.Fatalf("sign: %v", err)
	}
	token, err := object.CompactSerialize()
	if err != nil {
		idp.t.Fatalf("serialize: %v", err)
	}
	return token
}

// LastAuthorize returns the most recent authorize request.
func (idp *IdP) LastAuthorize() Request {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if len(idp.Authorizes) == 0 {
		return Request{}
	}
	return idp.Authorizes[len(idp.Authorizes)-1]
}

// LastToken returns the most recent token request.
func (idp *IdP) LastToken() Request {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	if len(idp.Tokens) == 0 {
		return Request{}
	}
	return idp.Tokens[len(idp.Tokens)-1]
}

// Counts returns the JWKS fetch and userinfo hit counters.
func (idp *IdP) Counts() (jwks, userinfo int) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.JWKSFetches, idp.UserinfoHits
}

// Login follows an authorization URL as the named user and returns the code
// and state from the redirect.
func (idp *IdP) Login(authorizeURL, login string) (code, state string, err error) {
	target, err := url.Parse(authorizeURL)
	if err != nil {
		return "", "", err
	}
	query := target.Query()
	query.Set("test_user", login)
	target.RawQuery = query.Encode()
	client := idp.server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Get(target.String())
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		return "", "", fmt.Errorf("authorize answered %d", resp.StatusCode)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return "", "", err
	}
	return location.Query().Get("code"), location.Query().Get("state"), nil
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(value)
}

func randomString() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}
