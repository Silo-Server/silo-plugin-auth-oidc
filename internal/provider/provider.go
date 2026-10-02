// Package provider implements the Silo auth_provider.v1 capability for a
// generic OpenID Connect provider. It returns typed facts about the person
// and applies the configured group rules; Silo owns accounts and sessions.
package provider

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
)

// provider_state and refresh_state field names.
const (
	stateCodeVerifier = "code_verifier"
	stateNonce        = "nonce"
	stateRedirectURI  = "redirect_uri"
	stateState        = "state"

	refreshToken     = "refresh_token"
	refreshExpiresAt = "refresh_expires_at"
	refreshIssuedAt  = "refresh_issued_at"
	refreshGrantedAt = "refresh_granted_at"
	refreshUncertain = "refresh_uncertain"
	refreshIDToken   = "id_token"
	refreshSubject   = "sub"
)

const (
	// minRefreshBudget is the least time left on the caller's deadline for
	// CheckAccount to redeem the refresh token. With less, a rotated token
	// could be spent at the provider and lost with a response the host has
	// stopped waiting for.
	minRefreshBudget = 3 * time.Second
	// responseReserve is kept free before the caller's deadline during and
	// after the refresh, so the answer carrying the rotated state, or the
	// mark that the refresh's outcome is unknown, still reaches the host.
	responseReserve = 1500 * time.Millisecond
	// refreshExpiryMargin treats a refresh token this close to its expiry as
	// expired, so a check does not race the provider's clock.
	refreshExpiryMargin = time.Minute
)

// identityClaims are the stored ID token claims a re-check may reuse when the
// refresh returns no new ID token. Profile and group claims are never reused:
// they would be stale.
var identityClaims = []string{"iss", "sub", "tid", "oid"}

// Provider serves AuthProvider and AuthProviderChecks. The zero value is not
// usable; call New.
type Provider struct {
	pluginv1.UnimplementedAuthProviderServer
	pluginv1.UnimplementedAuthProviderChecksServer

	logger *slog.Logger

	mu     sync.Mutex
	cfg    Config
	client *oidc.Client
}

var (
	_ pluginv1.AuthProviderServer       = (*Provider)(nil)
	_ pluginv1.AuthProviderChecksServer = (*Provider)(nil)
)

// New returns a provider with an empty configuration.
func New(logger *slog.Logger) *Provider {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, _ := ParseConfig(nil)
	return &Provider{logger: logger, cfg: cfg}
}

// Configure stores the settings from Runtime.Configure. It accepts empty and
// incomplete settings and does no network I/O; problems surface at sign-in
// and in TestConnection.
func (p *Provider) Configure(_ context.Context, entries []*pluginv1.ConfigEntry) error {
	cfg, err := ParseConfig(entries)
	if err != nil {
		return err
	}
	for _, problem := range cfg.LifetimeProblems() {
		p.logger.Warn("configure: " + problem)
	}
	p.mu.Lock()
	p.cfg = cfg
	p.client = nil
	p.mu.Unlock()
	return nil
}

// current returns the config and a lazily built client. The client and its
// discovery/JWKS caches live until the next Configure or process restart.
func (p *Provider) current() (Config, *oidc.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if problems := p.cfg.Problems(); len(problems) > 0 {
		return p.cfg, nil, fmt.Errorf("%w: %s", oidc.ErrConfig, strings.Join(problems, " "))
	}
	if p.client == nil {
		client, err := oidc.NewClient(p.cfg.clientSettings())
		if err != nil {
			return p.cfg, nil, err
		}
		p.client = client
	}
	return p.cfg, p.client, nil
}

// Authenticate is the password flow, which an OIDC provider does not offer.
func (p *Provider) Authenticate(context.Context, *pluginv1.AuthenticateRequest) (*pluginv1.AuthenticateResponse, error) {
	return nil, status.Error(codes.Unimplemented, "this provider signs in through the browser only")
}

// InitAuthorize builds the authorization URL with PKCE S256 and a nonce, and
// returns the verifier and nonce as provider_state for ExchangeCode.
func (p *Provider) InitAuthorize(ctx context.Context, req *pluginv1.InitAuthorizeRequest) (*pluginv1.InitAuthorizeResponse, error) {
	if req.GetRedirectUri() == "" || req.GetState() == "" {
		return nil, status.Error(codes.InvalidArgument, "redirect_uri and state are required")
	}
	cfg, client, err := p.current()
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	prompt := cfg.Prompt
	if req.GetPrompt() != "" {
		if err := validatePrompt(req.GetPrompt()); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		prompt = req.GetPrompt()
	}
	doc, err := client.Discovery(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	verifier, err := oidc.RandomToken(32)
	if err != nil {
		return nil, status.Error(codes.Internal, "generate PKCE verifier")
	}
	nonce, err := oidc.RandomToken(32)
	if err != nil {
		return nil, status.Error(codes.Internal, "generate nonce")
	}
	authorizeURL, err := client.AuthCodeURL(doc, oidc.AuthRequest{
		RedirectURI:   req.GetRedirectUri(),
		State:         req.GetState(),
		Nonce:         nonce,
		CodeChallenge: oidc.S256Challenge(verifier),
		Scopes:        cfg.RequestedScopes(),
		Prompt:        prompt,
		LoginHint:     req.GetLoginHint(),
	})
	if err != nil {
		return nil, grpcError(err)
	}
	providerState, err := structpb.NewStruct(map[string]any{
		stateCodeVerifier: verifier,
		stateNonce:        nonce,
		stateRedirectURI:  req.GetRedirectUri(),
		stateState:        req.GetState(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "encode provider state")
	}
	return &pluginv1.InitAuthorizeResponse{AuthorizeUrl: authorizeURL, ProviderState: providerState}, nil
}

// ExchangeCode redeems the code, validates the ID token, merges userinfo, and
// applies the group rules.
func (p *Provider) ExchangeCode(ctx context.Context, req *pluginv1.ExchangeCodeRequest) (*pluginv1.AuthenticateResponse, error) {
	stateFields := req.GetProviderState().GetFields()
	verifier := stateFields[stateCodeVerifier].GetStringValue()
	nonce := stateFields[stateNonce].GetStringValue()
	if verifier == "" || nonce == "" {
		return nil, status.Error(codes.InvalidArgument, "provider_state has no PKCE verifier or nonce")
	}
	redirectURI := stateFields[stateRedirectURI].GetStringValue()
	if redirectURI == "" {
		redirectURI = req.GetRedirectUri()
	} else if req.GetRedirectUri() != "" && req.GetRedirectUri() != redirectURI {
		return nil, status.Error(codes.InvalidArgument, "redirect_uri differs from the authorization request")
	}
	if expected := stateFields[stateState].GetStringValue(); expected != "" && req.GetState() != "" &&
		subtle.ConstantTimeCompare([]byte(expected), []byte(req.GetState())) != 1 {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "state does not match the authorization request"), nil
	}
	if req.GetCode() == "" {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, "the callback has no authorization code"), nil
	}

	cfg, client, err := p.current()
	if err != nil {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, err.Error()), nil
	}
	requested := time.Now()
	token, err := client.Exchange(ctx, req.GetCode(), redirectURI, verifier)
	if err != nil {
		return p.denyFor("code exchange", err), nil
	}
	idClaims, err := client.VerifyIDToken(ctx, token.IDToken, oidc.Expectations{Nonce: nonce, CheckNonce: true})
	if err != nil {
		return p.denyFor("id_token", err), nil
	}
	sub, _ := idClaims["sub"].(string)
	claims, err := p.withUserInfo(ctx, client, token.AccessToken, sub, idClaims)
	if err != nil {
		return p.denyFor("userinfo", err), nil
	}
	account, err := buildAccount(cfg, claims)
	if errors.Is(err, errNotPermitted) {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_NOT_PERMITTED, "the account is not in an allowed group"), nil
	}
	if err != nil {
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, err.Error()), nil
	}
	state := refreshFields{idToken: token.IDToken, sub: sub}
	if keepRefreshToken(cfg, token) {
		state.refresh = token.RefreshToken
		state.expiresAt = token.RefreshExpiry(time.Now())
		state.issuedAt = requested
		state.grantedAt = requested
	} else if token.RefreshToken != "" {
		p.logger.Debug("sign-in: refresh token not kept; offline access was not requested or not granted")
	}
	refreshState, err := state.toStruct()
	if err != nil {
		return nil, status.Error(codes.Internal, "encode refresh state")
	}
	account.RefreshState = refreshState
	return account, nil
}

// withUserInfo fetches userinfo when the provider has an endpoint and merges
// it over the ID token claims.
func (p *Provider) withUserInfo(ctx context.Context, client *oidc.Client, accessToken, sub string, idClaims map[string]any) (map[string]any, error) {
	doc, err := client.Discovery(ctx)
	if err != nil {
		return nil, err
	}
	if doc.UserinfoEndpoint == "" {
		return idClaims, nil
	}
	if accessToken == "" {
		return nil, fmt.Errorf("%w: the token response has no access_token for userinfo", oidc.ErrConfig)
	}
	userinfo, err := client.UserInfo(ctx, accessToken, sub)
	if err != nil {
		return nil, err
	}
	return mergeClaims(idClaims, userinfo), nil
}

// CheckAccount refreshes the stored refresh token and re-applies the group
// rules. Without a usable refresh token it answers UNSUPPORTED, so the host
// falls back to its absolute session age. A refused refresh token is
// NOT_PERMITTED only while it is known to be inside its lifetime; see
// refreshRefused.
func (p *Provider) CheckAccount(ctx context.Context, req *pluginv1.CheckAccountRequest) (*pluginv1.CheckAccountResponse, error) {
	stored := parseRefreshFields(req.GetRefreshState())
	if stored.refresh == "" {
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED, nil), nil
	}
	identity := map[string]any{}
	if stored.idToken != "" {
		if claims, err := oidc.UnverifiedClaims(stored.idToken); err == nil {
			for _, name := range identityClaims {
				if value, ok := claims[name]; ok {
					identity[name] = value
				}
			}
			if stored.sub == "" {
				stored.sub, _ = claims["sub"].(string)
			}
		}
	}
	if stored.sub == "" {
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED, nil), nil
	}
	// An expired refresh token would be refused with invalid_grant, which
	// reads as a revocation. When the provider told us the lifetime, answer
	// that the account cannot be checked instead, and drop the token so later
	// checks stop without presenting it.
	if !stored.expiresAt.IsZero() && !time.Now().Add(refreshExpiryMargin).Before(stored.expiresAt) {
		p.logger.Info("account check skipped: the stored refresh token has expired")
		return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED, nil, stored.withoutRefresh())
	}

	cfg, client, err := p.current()
	if err != nil {
		p.logger.Warn("account check skipped: configuration incomplete", "error", err)
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil), nil
	}
	// Discovery and the signing keys load before the budget check. On a cold
	// cache, after a restart or a settings change, a slow provider would
	// otherwise use up the budget before the refresh grant, and a rotated
	// token would be spent with too little time left to hand it back.
	if err := client.Prepare(ctx); err != nil {
		p.logger.Warn("account check skipped: provider metadata unavailable", "error", err)
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil), nil
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < minRefreshBudget {
		p.logger.Warn("account check skipped: too little time left to redeem the refresh token")
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil), nil
	}
	// The grant and every call after it stop early enough for the answer,
	// which may carry a rotated token, to reach the host.
	ctx, cancel := withResponseReserve(ctx)
	defer cancel()
	requested := time.Now()
	token, err := client.Refresh(ctx, stored.refresh)
	if err != nil {
		var tokenErr *oidc.TokenError
		if !errors.As(err, &tokenErr) {
			// The request may have reached the provider, which may have
			// rotated the token and lost the answer. Keep the stored token,
			// but mark it so a later refusal is not read as a revocation.
			p.logger.Warn("account check: refresh failed with an unknown outcome", "error", err)
			uncertain := stored
			uncertain.uncertain = true
			return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil, uncertain)
		}
		if tokenErr.Code == "invalid_grant" {
			// The token is dead either way. Dropping it stops later checks
			// from presenting it again and from judging the old refusal by
			// a lifetime setting entered afterwards.
			return p.checkWithState(p.refreshRefused(cfg, stored, tokenErr), nil, stored.withoutRefresh())
		}
		p.logger.Warn("account check: refresh failed", "error", err)
		return checkStatus(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil), nil
	}

	// The refresh token was redeemed. From here on every answer carries the
	// rotated state, so the host never presents a spent token again.
	state := stored
	state.uncertain = false
	if token.RefreshToken != "" {
		if token.RefreshToken != stored.refresh {
			// A token handed back unchanged keeps its original issue time,
			// so a fixed lifetime is not stretched. The grant time never
			// changes: an absolute lifetime counts from sign-in.
			state.issuedAt = requested
		}
		state.refresh = token.RefreshToken
		state.expiresAt = token.RefreshExpiry(time.Now())
	}

	claims := identity
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = cfg.Issuer
	}
	claims["sub"] = stored.sub
	freshIDToken := token.IDToken != ""
	if freshIDToken {
		verified, err := client.VerifyIDToken(ctx, token.IDToken, oidc.Expectations{Subject: stored.sub})
		if err != nil {
			p.logger.Warn("account check: refreshed id_token rejected", "error", err)
			return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil, state)
		}
		claims = verified
		state.idToken = token.IDToken
	}
	claims, err = p.withUserInfo(ctx, client, token.AccessToken, stored.sub, claims)
	if err != nil {
		if errors.Is(err, oidc.ErrSubjectMismatch) {
			p.logger.Warn("account check: userinfo subject mismatch", "error", err)
			return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED, nil, state)
		}
		p.logger.Warn("account check: userinfo failed", "error", err)
		return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil, state)
	}
	if !freshIDToken && cfg.hasGroupRules() {
		if _, ok := lookupClaim(claims, cfg.GroupsClaim); !ok {
			// Groups rode on the sign-in ID token and the refresh brought
			// neither a new one nor groups in userinfo: the rules cannot be
			// re-applied.
			p.logger.Warn("account check: the refresh returned no groups claim; group rules cannot be re-checked",
				"groups_claim", cfg.GroupsClaim)
			return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED, nil, state)
		}
	}
	account, err := buildAccount(cfg, claims)
	if errors.Is(err, errNotPermitted) {
		return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED, nil, state)
	}
	if err != nil {
		p.logger.Warn("account check: claims unusable", "error", err)
		return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNAVAILABLE, nil, state)
	}
	if want := req.GetExternalSubject(); want != "" && account.GetExternalSubject() != want {
		p.logger.Warn("account check: account key changed; was the account key setting changed?")
		return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED, nil, state)
	}
	return p.checkWithState(pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_ACTIVE, account, state)
}

// refreshRefused maps an invalid_grant answer to the refresh grant. Providers
// give that answer for an expired token and a revoked one alike, so it counts
// as a revocation only while the token is known to be inside its lifetime:
// by the provider's hint, or else by the Refresh token lifetime setting.
// Otherwise the account cannot be checked, and the host falls back to its
// absolute session age instead of signing the person out.
func (p *Provider) refreshRefused(cfg Config, stored refreshFields, tokenErr *oidc.TokenError) pluginv1.CheckAccountStatus {
	now := time.Now()
	switch {
	case stored.uncertain:
		// An earlier refresh may have spent this token at the provider.
		p.logger.Info("account check: provider refused a refresh token that an earlier, unanswered refresh may have spent; treating it as expired",
			"detail", tokenErr.Description)
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED
	case cfg.RefreshTokenMaxLifetime > 0 && !stored.grantedAt.IsZero() &&
		!now.Add(refreshExpiryMargin).Before(stored.grantedAt.Add(cfg.RefreshTokenMaxLifetime)):
		p.logger.Info("account check: provider refused a refresh token past the configured refresh token absolute lifetime; treating it as expired",
			"detail", tokenErr.Description, "absolute_lifetime", cfg.RefreshTokenMaxLifetime)
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED
	case !stored.expiresAt.IsZero():
		// CheckAccount skips tokens past the hint, so this one was still valid.
		p.logger.Info("account check: provider refused a refresh token that had not expired; treating it as revoked",
			"detail", tokenErr.Description)
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED
	case cfg.RefreshTokenLifetime > 0:
		// A state with no recorded issue time cannot be placed inside the
		// lifetime, so it counts as expired.
		if !stored.issuedAt.IsZero() && now.Add(refreshExpiryMargin).Before(stored.issuedAt.Add(cfg.RefreshTokenLifetime)) {
			p.logger.Info("account check: provider refused a refresh token inside the configured refresh token lifetime; treating it as revoked",
				"detail", tokenErr.Description, "lifetime", cfg.RefreshTokenLifetime)
			return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_NOT_PERMITTED
		}
		p.logger.Info("account check: provider refused a refresh token not known to be inside the configured refresh token lifetime; treating it as expired",
			"detail", tokenErr.Description, "lifetime", cfg.RefreshTokenLifetime)
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED
	default:
		p.logger.Warn("account check: provider refused the refresh token, but it reports no refresh-token lifetime, "+
			"so an expired token cannot be told from a revoked one and the account is not signed out; "+
			"to detect revocations, set Refresh token lifetime under Provider connection to the provider's refresh-token lifetime",
			"detail", tokenErr.Description)
		return pluginv1.CheckAccountStatus_CHECK_ACCOUNT_STATUS_UNSUPPORTED
	}
}

// withResponseReserve ends ctx responseReserve before the caller's deadline.
func withResponseReserve(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(ctx, deadline.Add(-responseReserve))
	}
	return context.WithCancel(ctx)
}

func (p *Provider) checkWithState(
	checkStatusValue pluginv1.CheckAccountStatus,
	account *pluginv1.AuthenticateResponse,
	fields refreshFields,
) (*pluginv1.CheckAccountResponse, error) {
	state, err := fields.toStruct()
	if err != nil {
		return nil, status.Error(codes.Internal, "encode refresh state")
	}
	if account == nil {
		account = &pluginv1.AuthenticateResponse{}
	}
	account.RefreshState = state
	return checkStatus(checkStatusValue, account), nil
}

// EndSessionUrl returns the provider's end_session_endpoint with
// id_token_hint and post_logout_redirect_uri, or "" when provider logout is
// off or the provider has no endpoint.
func (p *Provider) EndSessionUrl(ctx context.Context, req *pluginv1.AuthEndSessionUrlRequest) (*pluginv1.AuthEndSessionUrlResponse, error) {
	cfg, client, err := p.current()
	if err != nil || !cfg.ProviderLogout {
		return &pluginv1.AuthEndSessionUrlResponse{}, nil
	}
	doc, err := client.Discovery(ctx)
	if err != nil {
		return nil, grpcError(err)
	}
	if doc.EndSessionEndpoint == "" {
		return &pluginv1.AuthEndSessionUrlResponse{}, nil
	}
	endpoint, err := url.Parse(doc.EndSessionEndpoint)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "provider end_session_endpoint is not a URL")
	}
	query := endpoint.Query()
	query.Set("client_id", cfg.ClientID)
	if idToken := req.GetRefreshState().GetFields()[refreshIDToken].GetStringValue(); idToken != "" {
		query.Set("id_token_hint", idToken)
	}
	if redirect := req.GetPostLogoutRedirectUri(); redirect != "" {
		query.Set("post_logout_redirect_uri", redirect)
	}
	endpoint.RawQuery = query.Encode()
	return &pluginv1.AuthEndSessionUrlResponse{Url: endpoint.String()}, nil
}

// denyFor maps a protocol error to a denial and logs the detail.
func (p *Provider) denyFor(stage string, err error) *pluginv1.AuthenticateResponse {
	detail := stage + ": " + err.Error()
	var tokenErr *oidc.TokenError
	switch {
	case errors.As(err, &tokenErr) && tokenErr.Code == "invalid_grant":
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, detail)
	case errors.Is(err, oidc.ErrInvalidToken):
		p.logger.Warn("sign-in refused: token validation failed", "stage", stage, "error", err)
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_INVALID_CREDENTIALS, detail)
	default:
		p.logger.Warn("sign-in failed: provider unavailable or misconfigured", "stage", stage, "error", err)
		return deny(pluginv1.AuthDenial_AUTH_DENIAL_PROVIDER_UNAVAILABLE, detail)
	}
}

func deny(denial pluginv1.AuthDenial, detail string) *pluginv1.AuthenticateResponse {
	return &pluginv1.AuthenticateResponse{Denial: denial, DenialDetail: detail}
}

func checkStatus(value pluginv1.CheckAccountStatus, account *pluginv1.AuthenticateResponse) *pluginv1.CheckAccountResponse {
	return &pluginv1.CheckAccountResponse{Status: value, Account: account}
}

func grpcError(err error) error {
	switch {
	case errors.Is(err, oidc.ErrUnavailable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, oidc.ErrConfig):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// keepRefreshToken reports whether a sign-in's refresh token may be used for
// re-checks: only when offline access was requested and not refused. Without
// offline_access many providers (Keycloak, Kanidm) issue a refresh token tied
// to the browser session, which the provider refuses once that session ends;
// the refusal would read as a revocation.
func keepRefreshToken(cfg Config, token *oidc.TokenResponse) bool {
	return token.RefreshToken != "" && cfg.RequestOfflineAccess && token.GrantsScope("offline_access")
}

// refreshFields is the refresh_state: the refresh token, its expiry hint
// (when there is one), when it was issued, when the sign-in first granted a
// refresh token, whether an earlier refresh ended with an unknown outcome, the
// ID token for the end-session hint, and sub for checking refreshed tokens. A
// state without refresh_token replaces an older one, so CheckAccount then
// answers UNSUPPORTED instead of presenting a stale token; a refused or
// expired token is cleared that way.
type refreshFields struct {
	refresh   string
	expiresAt time.Time
	issuedAt  time.Time
	grantedAt time.Time
	uncertain bool
	idToken   string
	sub       string
}

// withoutRefresh drops the refresh token and what describes it, keeping the
// ID token for the end-session hint and sub.
func (f refreshFields) withoutRefresh() refreshFields {
	return refreshFields{idToken: f.idToken, sub: f.sub}
}

func parseRefreshFields(state *structpb.Struct) refreshFields {
	fields := state.GetFields()
	return refreshFields{
		refresh:   fields[refreshToken].GetStringValue(),
		expiresAt: unixField(fields[refreshExpiresAt]),
		issuedAt:  unixField(fields[refreshIssuedAt]),
		grantedAt: unixField(fields[refreshGrantedAt]),
		uncertain: fields[refreshUncertain].GetBoolValue(),
		idToken:   fields[refreshIDToken].GetStringValue(),
		sub:       fields[refreshSubject].GetStringValue(),
	}
}

func unixField(value *structpb.Value) time.Time {
	if seconds := value.GetNumberValue(); seconds > 0 {
		return time.Unix(int64(seconds), 0)
	}
	return time.Time{}
}

func (f refreshFields) toStruct() (*structpb.Struct, error) {
	fields := map[string]any{}
	if f.refresh != "" {
		fields[refreshToken] = f.refresh
		for name, at := range map[string]time.Time{
			refreshExpiresAt: f.expiresAt, refreshIssuedAt: f.issuedAt, refreshGrantedAt: f.grantedAt,
		} {
			if !at.IsZero() {
				fields[name] = float64(at.Unix())
			}
		}
		if f.uncertain {
			fields[refreshUncertain] = true
		}
	}
	if f.idToken != "" {
		fields[refreshIDToken] = f.idToken
	}
	if f.sub != "" {
		fields[refreshSubject] = f.sub
	}
	return structpb.NewStruct(fields)
}
