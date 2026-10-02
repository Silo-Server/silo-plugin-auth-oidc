package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// asymmetricAlgorithms are always accepted for ID tokens.
var asymmetricAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// SupportedAlgorithms lists the signature algorithms the client accepts.
func (c *Client) SupportedAlgorithms() []jose.SignatureAlgorithm {
	algorithms := slices.Clone(asymmetricAlgorithms)
	if c.settings.AllowHS256 {
		algorithms = append(algorithms, jose.HS256)
	}
	return algorithms
}

// AcceptsAlgorithm reports whether ID tokens signed with alg are accepted.
func (c *Client) AcceptsAlgorithm(alg string) bool {
	return slices.Contains(c.SupportedAlgorithms(), jose.SignatureAlgorithm(alg))
}

// Expectations are the per-token checks on top of issuer, audience and time.
type Expectations struct {
	// Nonce must match the nonce claim when CheckNonce is set.
	Nonce      string
	CheckNonce bool
	// Subject, when set, must equal the sub claim (refreshed tokens).
	Subject string
}

// VerifyIDToken checks the signature, iss, aud/azp, exp, iat, nbf, sub and,
// when asked, nonce. It returns the token's claims.
func (c *Client) VerifyIDToken(ctx context.Context, raw string, expect Expectations) (map[string]any, error) {
	if raw == "" {
		return nil, fmt.Errorf("%w: the token response has no id_token", ErrInvalidToken)
	}
	payload, err := c.verifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := c.checkClaims(claims, expect); err != nil {
		return nil, err
	}
	return claims, nil
}

// UnverifiedClaims decodes a JWT payload without checking its signature. Use
// it only for tokens this client verified earlier and stored.
func UnverifiedClaims(raw string) (map[string]any, error) {
	jws, err := jose.ParseSigned(raw, append(slices.Clone(asymmetricAlgorithms), jose.HS256))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	return decodeClaims(jws.UnsafePayloadWithoutVerification())
}

func (c *Client) verifySignedUserInfo(ctx context.Context, raw string) (map[string]any, error) {
	payload, err := c.verifySignature(ctx, raw)
	if err != nil {
		return nil, err
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return nil, err
	}
	if iss, ok := claims["iss"]; ok && iss != c.settings.Issuer {
		return nil, fmt.Errorf("%w: signed userinfo iss does not match the issuer", ErrInvalidToken)
	}
	if _, ok := claims["aud"]; ok && !audienceContains(claims["aud"], c.settings.ClientID) {
		return nil, fmt.Errorf("%w: signed userinfo aud does not include the client ID", ErrInvalidToken)
	}
	return claims, nil
}

func (c *Client) verifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, c.SupportedAlgorithms())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("%w: expected one signature, got %d", ErrInvalidToken, len(jws.Signatures))
	}
	header := jws.Signatures[0].Header
	algorithm := jose.SignatureAlgorithm(header.Algorithm)
	if algorithm == jose.HS256 {
		payload, err := jws.Verify([]byte(c.settings.ClientSecret))
		if err != nil {
			return nil, fmt.Errorf("%w: HS256 signature: %v", ErrInvalidToken, err)
		}
		return payload, nil
	}

	candidates, err := c.verificationKeys(ctx, header.KeyID, string(algorithm), false)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		// Unknown kid, or no key for the algorithm: the provider may have
		// rotated its keys. Refetch once (rate limited) and retry.
		candidates, err = c.verificationKeys(ctx, header.KeyID, string(algorithm), true)
		if err != nil {
			return nil, err
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("%w: no provider key matches kid %q and alg %s", ErrInvalidToken, header.KeyID, algorithm)
	}
	var lastErr error
	for _, key := range candidates {
		payload, err := jws.Verify(key)
		if err == nil {
			return payload, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("%w: signature: %v", ErrInvalidToken, lastErr)
}

func (c *Client) verificationKeys(ctx context.Context, kid, algorithm string, force bool) ([]jose.JSONWebKey, error) {
	set, err := c.JWKS(ctx, force)
	if err != nil {
		return nil, err
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if kid != "" && key.KeyID != kid {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != algorithm {
			continue
		}
		if !key.Valid() || !key.IsPublic() {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (c *Client) checkClaims(claims map[string]any, expect Expectations) error {
	iss, _ := claims["iss"].(string)
	if iss != c.settings.Issuer {
		return fmt.Errorf("%w: iss %q does not match the issuer", ErrInvalidToken, iss)
	}
	if !audienceContains(claims["aud"], c.settings.ClientID) {
		return fmt.Errorf("%w: aud does not include the client ID", ErrInvalidToken)
	}
	if azp, present := claims["azp"]; present {
		if value, _ := azp.(string); value != c.settings.ClientID {
			return fmt.Errorf("%w: azp is not the client ID", ErrInvalidToken)
		}
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return fmt.Errorf("%w: sub is missing", ErrInvalidToken)
	}
	if expect.Subject != "" && sub != expect.Subject {
		return fmt.Errorf("%w: sub changed", ErrInvalidToken)
	}
	now := time.Now()
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return fmt.Errorf("%w: exp is missing", ErrInvalidToken)
	}
	if !now.Before(exp.Add(clockSkew)) {
		return fmt.Errorf("%w: token expired at %s", ErrInvalidToken, exp.UTC().Format(time.RFC3339))
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return fmt.Errorf("%w: iat is missing", ErrInvalidToken)
	}
	if iat.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: iat is in the future", ErrInvalidToken)
	}
	if nbf, ok := numericDate(claims["nbf"]); ok && nbf.After(now.Add(clockSkew)) {
		return fmt.Errorf("%w: token not valid yet", ErrInvalidToken)
	}
	if expect.CheckNonce {
		nonce, _ := claims["nonce"].(string)
		if expect.Nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(expect.Nonce)) != 1 {
			return fmt.Errorf("%w: nonce does not match", ErrInvalidToken)
		}
	}
	return nil
}

// jwtExpiry reads the exp claim of a JWT without verifying it, or returns the
// zero time. It serves only as a lifetime hint for refresh tokens, which some
// providers (Keycloak) issue as JWTs; opaque tokens have no hint.
func jwtExpiry(raw string) time.Time {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return time.Time{}
	}
	exp, err := claims.Exp.Float64()
	if err != nil || exp <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(exp), 0)
}

func decodeClaims(payload []byte) (map[string]any, error) {
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims are not a JSON object", ErrInvalidToken)
	}
	return claims, nil
}

func audienceContains(aud any, clientID string) bool {
	switch value := aud.(type) {
	case string:
		return value == clientID
	case []any:
		for _, entry := range value {
			if s, ok := entry.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func numericDate(value any) (time.Time, bool) {
	switch v := value.(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	return time.Time{}, false
}

// RandomToken returns n random bytes, base64url encoded without padding.
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// S256Challenge computes the PKCE S256 code challenge for a verifier.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func basicAuth(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
