package provider

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// protectedClaims are never taken from userinfo: they describe the signed ID
// token or key the account, so only the verified token may set them.
var protectedClaims = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "azp": {}, "exp": {}, "iat": {}, "nbf": {},
	"nonce": {}, "auth_time": {}, "at_hash": {}, "c_hash": {}, "acr": {}, "amr": {},
	"sid": {}, "jti": {}, "tid": {}, "oid": {},
}

// microsoftIssuerHosts identify Entra ID issuers for the automatic account key.
var microsoftIssuerHosts = []string{
	"login.microsoftonline.com",
	"login.microsoftonline.us",
	"login.partner.microsoftonline.cn",
	"login.chinacloudapi.cn",
	"sts.windows.net",
}

// errNotPermitted is returned when the account fails the allowed-groups rule.
var errNotPermitted = errors.New("not in an allowed group")

// mergeClaims overlays userinfo on the ID token claims, except the protected
// claims, which keep the verified token's values.
func mergeClaims(idToken, userinfo map[string]any) map[string]any {
	merged := make(map[string]any, len(idToken)+len(userinfo))
	for key, value := range idToken {
		merged[key] = value
	}
	for key, value := range userinfo {
		if _, protected := protectedClaims[key]; protected {
			continue
		}
		merged[key] = value
	}
	return merged
}

// lookupClaim resolves a claim path. The whole path is tried as a claim name
// first, so names containing dots or colons (Zitadel's
// "urn:zitadel:iam:org:project:roles", URL-style names) work; otherwise dots
// walk into nested objects, as in "realm_access.roles".
func lookupClaim(claims map[string]any, path string) (any, bool) {
	if value, ok := claims[path]; ok {
		return value, true
	}
	if !strings.Contains(path, ".") {
		return nil, false
	}
	var current any = claims
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func stringClaim(claims map[string]any, path string) string {
	value, ok := lookupClaim(claims, path)
	if !ok {
		return ""
	}
	s, _ := value.(string)
	return strings.TrimSpace(s)
}

// extractGroups reads group names from the claim at path. It accepts a list of
// strings (plain names, Keycloak paths, Kanidm SPNs and UUIDs, Entra GUIDs), a
// single string, an object whose keys are the groups (Zitadel project roles),
// and a list of objects with a name field.
func extractGroups(claims map[string]any, path string) []string {
	value, ok := lookupClaim(claims, path)
	if !ok {
		return nil
	}
	var groups []string
	add := func(group string) {
		group = strings.TrimSpace(group)
		if group != "" && !slices.Contains(groups, group) {
			groups = append(groups, group)
		}
	}
	switch v := value.(type) {
	case string:
		add(v)
	case []any:
		for _, entry := range v {
			switch e := entry.(type) {
			case string:
				add(e)
			case map[string]any:
				for _, field := range []string{"name", "displayName", "display", "value"} {
					if s, ok := e[field].(string); ok && s != "" {
						add(s)
						break
					}
				}
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			add(key)
		}
	}
	return groups
}

// groupMatches compares a configured group with one the provider sent,
// ignoring ASCII case. A Keycloak path matches with or without its leading slash
// ("/silo-users" and "silo-users"), and a configured name without "@" matches
// a Kanidm SPN by its name part ("silo-users" matches "silo-users@idm.example").
func groupMatches(configured, actual string) bool {
	if asciiEqualFold(configured, actual) {
		return true
	}
	configuredPath := strings.TrimPrefix(configured, "/")
	actualPath := strings.TrimPrefix(actual, "/")
	if asciiEqualFold(configuredPath, actualPath) {
		return true
	}
	if !strings.Contains(configured, "@") {
		if name, _, found := strings.Cut(actual, "@"); found && asciiEqualFold(configuredPath, name) {
			return true
		}
	}
	return false
}

// asciiEqualFold compares strings ignoring ASCII case only. strings.EqualFold
// applies Unicode folding, which makes look-alikes such as "ſilo-admins"
// (U+017F) or a Kelvin sign (U+212A) match "silo-admins" and "k". Group names
// decide AllowedGroups and AdminGroups, so only exact or ASCII-case matches
// count. This matches silo-plugin-auth-ldap.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func memberOfAny(configured, actual []string) bool {
	for _, want := range configured {
		for _, have := range actual {
			if groupMatches(want, have) {
				return true
			}
		}
	}
	return false
}

// emailVerified passes email_verified through: nil when absent, and the
// provider's value when it is a boolean or the strings "true"/"false". In
// OpenID Connect it describes only the standard email claim, so it is nil when
// the email comes from another claim.
func emailVerified(claims map[string]any, emailClaim string) *bool {
	if emailClaim != defaultEmailClaim {
		return nil
	}
	switch v := claims["email_verified"].(type) {
	case bool:
		return &v
	case string:
		switch normalized := strings.ToLower(strings.TrimSpace(v)); normalized {
		case "true", "false":
			verified := normalized == "true"
			return &verified
		}
	}
	return nil
}

// pictureURL keeps only absolute http(s) URLs. The plugin never fetches it.
func pictureURL(claims map[string]any, path string) string {
	raw := stringClaim(claims, path)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return ""
	}
	return raw
}

func displayName(claims map[string]any, path string) string {
	if name := stringClaim(claims, path); name != "" {
		return name
	}
	given := stringClaim(claims, "given_name")
	family := stringClaim(claims, "family_name")
	return strings.TrimSpace(given + " " + family)
}

// externalSubject builds the stable account key: the exact issuer, "|", and
// sub; or, for Entra ID, tid "|" oid, because Entra's sub is pairwise per
// application.
func externalSubject(cfg Config, claims map[string]any) (string, error) {
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss == "" || sub == "" {
		return "", fmt.Errorf("token has no iss or sub")
	}
	mode := cfg.SubjectMode
	if mode == SubjectAuto {
		mode = SubjectStandard
		if isMicrosoftIssuer(iss) {
			mode = SubjectEntra
		}
	}
	if mode == SubjectEntra {
		tid, _ := claims["tid"].(string)
		oid, _ := claims["oid"].(string)
		if tid == "" || oid == "" {
			return "", fmt.Errorf("the account key is Entra tenant and object ID, but the ID token has no tid or oid claim (request the profile scope)")
		}
		return tid + "|" + oid, nil
	}
	return iss + "|" + sub, nil
}

func isMicrosoftIssuer(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return slices.Contains(microsoftIssuerHosts, strings.ToLower(parsed.Hostname()))
}

// buildAccount maps verified claims to the typed response and applies the
// group rules. It returns errNotPermitted when the allowed-groups rule fails.
func buildAccount(cfg Config, claims map[string]any) (*pluginv1.AuthenticateResponse, error) {
	subject, err := externalSubject(cfg, claims)
	if err != nil {
		return nil, err
	}
	groups := extractGroups(claims, cfg.GroupsClaim)
	if len(cfg.AllowedGroups) > 0 && !memberOfAny(cfg.AllowedGroups, groups) {
		return nil, errNotPermitted
	}
	role := pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_UNSPECIFIED
	if len(cfg.AdminGroups) > 0 {
		role = pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER
		if memberOfAny(cfg.AdminGroups, groups) {
			role = pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_ADMIN
		}
	}
	iss, _ := claims["iss"].(string)
	return &pluginv1.AuthenticateResponse{
		ExternalSubject: subject,
		Issuer:          iss,
		Username:        stringClaim(claims, cfg.UsernameClaim),
		Email:           stringClaim(claims, cfg.EmailClaim),
		EmailVerified:   emailVerified(claims, cfg.EmailClaim),
		DisplayName:     displayName(claims, cfg.DisplayNameClaim),
		Groups:          groups,
		PictureUrl:      pictureURL(claims, cfg.PictureClaim),
		ManagedRole:     role,
	}, nil
}
