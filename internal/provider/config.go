package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
)

// Global config keys and their fields. They must match manifest.json. The
// host reads the button label and icon keys itself; the plugin ignores them.
const (
	keyConnection = "connection"
	keyClaims     = "claims"
	keyAccess     = "access"
)

// Subject modes.
const (
	SubjectAuto     = "auto"
	SubjectStandard = "standard"
	SubjectEntra    = "entra"
)

// Default claim names.
const (
	defaultScopes           = "openid profile email"
	defaultUsernameClaim    = "preferred_username"
	defaultEmailClaim       = "email"
	defaultDisplayNameClaim = "name"
	defaultGroupsClaim      = "groups"
	defaultPictureClaim     = "picture"
)

// promptValues are the OIDC prompt values the plugin passes through.
var promptValues = []string{"none", "login", "consent", "select_account", "create"}

// Config is the plugin's parsed global configuration.
type Config struct {
	Issuer               string
	ClientID             string
	ClientSecret         string
	TokenAuthMethod      string
	Scopes               []string
	RequestGroupsScope   bool
	RequestOfflineAccess bool
	Prompt               string
	ProviderLogout       bool
	CAPEM                string
	AllowHS256           bool
	// RefreshTokenLifetime is the provider's per-token (sliding or idle)
	// refresh-token lifetime as the operator entered it, or zero when
	// unknown. It tells an expired refresh token from a revoked one when the
	// provider reports no lifetime.
	RefreshTokenLifetime time.Duration
	// RefreshTokenMaxLifetime is the provider's absolute cap counted from
	// sign-in, however often the token rotates, or zero when there is none
	// or it is unknown. A refusal past it counts as expiry.
	RefreshTokenMaxLifetime time.Duration
	// lifetimeInputs are the lifetime settings as entered, by label, for
	// LifetimeProblems. An unreadable lifetime counts as unknown and never
	// blocks sign-in.
	lifetimeInputs map[string]string

	UsernameClaim    string
	EmailClaim       string
	DisplayNameClaim string
	GroupsClaim      string
	PictureClaim     string
	SubjectMode      string

	AllowedGroups []string
	AdminGroups   []string
}

// ParseConfig reads Configure or TestConnection entries. Missing keys take
// their defaults; it fails only on values of the wrong type.
func ParseConfig(entries []*pluginv1.ConfigEntry) (Config, error) {
	values := make(map[string]map[string]any, len(entries))
	for _, entry := range entries {
		if entry == nil || entry.GetKey() == "" {
			continue
		}
		values[entry.GetKey()] = entry.GetValue().AsMap()
	}
	var cfg Config
	var err error
	read := func(key, field string, target *string) {
		if err != nil {
			return
		}
		*target, err = stringField(values[key], key, field)
	}
	readBool := func(key, field string, target *bool) {
		if err != nil {
			return
		}
		*target, err = boolField(values[key], key, field)
	}
	readList := func(key, field string, target *[]string) {
		if err != nil {
			return
		}
		*target, err = listField(values[key], key, field)
	}

	read(keyConnection, "issuer_url", &cfg.Issuer)
	read(keyConnection, "client_id", &cfg.ClientID)
	read(keyConnection, "client_secret", &cfg.ClientSecret)
	read(keyConnection, "token_endpoint_auth_method", &cfg.TokenAuthMethod)
	var scopes string
	read(keyConnection, "scopes", &scopes)
	readBool(keyConnection, "request_groups_scope", &cfg.RequestGroupsScope)
	readBool(keyConnection, "request_offline_access", &cfg.RequestOfflineAccess)
	read(keyConnection, "prompt", &cfg.Prompt)
	readBool(keyConnection, "provider_logout", &cfg.ProviderLogout)
	read(keyConnection, "ca_pem", &cfg.CAPEM)
	readBool(keyConnection, "allow_hs256", &cfg.AllowHS256)
	var refreshLifetime, refreshMaxLifetime string
	read(keyConnection, "refresh_token_lifetime", &refreshLifetime)
	read(keyConnection, "refresh_token_max_lifetime", &refreshMaxLifetime)

	read(keyClaims, "username", &cfg.UsernameClaim)
	read(keyClaims, "email", &cfg.EmailClaim)
	read(keyClaims, "display_name", &cfg.DisplayNameClaim)
	read(keyClaims, "groups", &cfg.GroupsClaim)
	read(keyClaims, "picture", &cfg.PictureClaim)
	read(keyClaims, "subject", &cfg.SubjectMode)

	readList(keyAccess, "allowed_groups", &cfg.AllowedGroups)
	readList(keyAccess, "admin_groups", &cfg.AdminGroups)
	if err != nil {
		return Config{}, err
	}

	// The issuer is trimmed but otherwise kept exact: it must match the
	// provider's issuer byte for byte, trailing slash included.
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.ClientSecret = strings.TrimSpace(cfg.ClientSecret)
	cfg.TokenAuthMethod = strings.TrimSpace(cfg.TokenAuthMethod)
	if cfg.TokenAuthMethod == "" {
		cfg.TokenAuthMethod = oidc.AuthMethodBasic
	}
	if strings.TrimSpace(scopes) == "" {
		scopes = defaultScopes
	}
	cfg.Scopes = strings.Fields(scopes)
	cfg.Prompt = strings.TrimSpace(cfg.Prompt)
	cfg.UsernameClaim = orDefault(cfg.UsernameClaim, defaultUsernameClaim)
	cfg.EmailClaim = orDefault(cfg.EmailClaim, defaultEmailClaim)
	cfg.DisplayNameClaim = orDefault(cfg.DisplayNameClaim, defaultDisplayNameClaim)
	cfg.GroupsClaim = orDefault(cfg.GroupsClaim, defaultGroupsClaim)
	cfg.PictureClaim = orDefault(cfg.PictureClaim, defaultPictureClaim)
	cfg.SubjectMode = orDefault(cfg.SubjectMode, SubjectAuto)
	cfg.RefreshTokenLifetime, _ = parseLifetime(refreshLifetime)
	cfg.RefreshTokenMaxLifetime, _ = parseLifetime(refreshMaxLifetime)
	cfg.lifetimeInputs = map[string]string{
		labelRefreshLifetime:    refreshLifetime,
		labelRefreshMaxLifetime: refreshMaxLifetime,
	}
	return cfg, nil
}

// Admin form labels of the lifetime settings, as problems name them.
const (
	labelRefreshLifetime    = "Refresh token lifetime"
	labelRefreshMaxLifetime = "Refresh token absolute lifetime"
)

// LifetimePattern is the grammar of the lifetime settings: blank or 0
// (unknown), whole days up to 9999d, or hours and minutes such as 12h, 90m
// or 1h30m, up to 999999h and 9999999m. manifest.json uses the same pattern
// in the admin form and the JSON schema, so the host rejects on save what
// parseLifetime cannot read. The digit limits keep every accepted value
// clear of a time.Duration overflow.
const LifetimePattern = `^\s*(0|([0-9]{1,4})d|(?:([0-9]{1,6})h)?(?:([0-9]{1,7})m)?)\s*$`

var lifetimeRE = regexp.MustCompile(LifetimePattern)

// parseLifetime reads a value matching LifetimePattern. Blank or zero means
// unknown. It reports false for anything else.
func parseLifetime(raw string) (time.Duration, bool) {
	match := lifetimeRE.FindStringSubmatch(raw)
	if match == nil {
		return 0, false
	}
	count := func(digits string, unit time.Duration) time.Duration {
		n, _ := strconv.Atoi(digits) // digits only, at most 7
		return time.Duration(n) * unit
	}
	return count(match[2], 24*time.Hour) + count(match[3], time.Hour) + count(match[4], time.Minute), true
}

// LifetimeProblems lists lifetime settings that do not parse. They count as
// unknown, so they never stop sign-in; Configure logs them and the
// connection test fails its settings step on them.
func (c Config) LifetimeProblems() []string {
	var problems []string
	for _, label := range []string{labelRefreshLifetime, labelRefreshMaxLifetime} {
		raw := c.lifetimeInputs[label]
		if _, ok := parseLifetime(raw); !ok {
			problems = append(problems, fmt.Sprintf(
				"%s %q is not a lifetime such as 90m, 12h, 1h30m or 30d (at most 9999d, 999999h or 9999999m); it is treated as unknown.",
				label, strings.TrimSpace(raw)))
		}
	}
	return problems
}

// Problems lists settings that stop sign-in from working, in operator
// language. An empty list means the config is usable.
func (c Config) Problems() []string {
	var problems []string
	if c.Issuer == "" {
		problems = append(problems, "Issuer URL is not set.")
	} else if !strings.HasPrefix(c.Issuer, "https://") {
		problems = append(problems, "Issuer URL must start with https://.")
	}
	if c.ClientID == "" {
		problems = append(problems, "Client ID is not set.")
	}
	switch c.TokenAuthMethod {
	case oidc.AuthMethodBasic, oidc.AuthMethodPost:
	default:
		problems = append(problems, fmt.Sprintf("Token endpoint authentication %q is not supported.", c.TokenAuthMethod))
	}
	if c.Prompt != "" {
		if err := validatePrompt(c.Prompt); err != nil {
			problems = append(problems, err.Error())
		}
	}
	switch c.SubjectMode {
	case SubjectAuto, SubjectStandard, SubjectEntra:
	default:
		problems = append(problems, fmt.Sprintf("Account key %q is not supported.", c.SubjectMode))
	}
	if c.AllowHS256 && c.ClientSecret == "" {
		problems = append(problems, "HS256 ID tokens need a client secret.")
	} else if c.AllowHS256 && len(c.ClientSecret) < oidc.MinHS256SecretBytes {
		problems = append(problems, fmt.Sprintf("HS256 ID tokens need a client secret of at least %d bytes.", oidc.MinHS256SecretBytes))
	}
	if strings.TrimSpace(c.CAPEM) != "" {
		if _, err := oidc.NewHTTPClient(c.CAPEM); err != nil {
			problems = append(problems, "Custom CA does not contain a PEM certificate.")
		}
	}
	return problems
}

// hasGroupRules reports whether allowed or admin groups are set.
func (c Config) hasGroupRules() bool {
	return len(c.AllowedGroups) > 0 || len(c.AdminGroups) > 0
}

// RequestedScopes returns the scopes to request: openid first, then the
// configured scopes and the optional groups and offline_access toggles.
func (c Config) RequestedScopes() []string {
	scopes := []string{"openid"}
	add := func(scope string) {
		if scope != "" && !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	for _, scope := range c.Scopes {
		add(scope)
	}
	if c.RequestGroupsScope {
		add("groups")
	}
	if c.RequestOfflineAccess {
		add("offline_access")
	}
	return scopes
}

func (c Config) clientSettings() oidc.Settings {
	return oidc.Settings{
		Issuer:          c.Issuer,
		ClientID:        c.ClientID,
		ClientSecret:    c.ClientSecret,
		TokenAuthMethod: c.TokenAuthMethod,
		AllowHS256:      c.AllowHS256,
		CAPEM:           c.CAPEM,
	}
}

func validatePrompt(prompt string) error {
	values := strings.Fields(prompt)
	for _, value := range values {
		if !slices.Contains(promptValues, value) {
			return fmt.Errorf("prompt value %q is not one of %s", value, strings.Join(promptValues, ", "))
		}
	}
	if slices.Contains(values, "none") && len(values) > 1 {
		return fmt.Errorf("prompt none cannot be combined with other values")
	}
	return nil
}

func orDefault(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func stringField(values map[string]any, key, field string) (string, error) {
	raw, ok := values[field]
	if !ok || raw == nil {
		return "", nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("config %s.%s must be a string", key, field)
	}
	return value, nil
}

func boolField(values map[string]any, key, field string) (bool, error) {
	raw, ok := values[field]
	if !ok || raw == nil {
		return false, nil
	}
	switch value := raw.(type) {
	case bool:
		return value, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true":
			return true, nil
		case "false", "":
			return false, nil
		}
	}
	return false, fmt.Errorf("config %s.%s must be a boolean", key, field)
}

// listField accepts a list of strings or one string with one entry per line,
// as the admin form's text area sends. Commas do not separate entries: group
// names such as LDAP DNs contain them.
func listField(values map[string]any, key, field string) ([]string, error) {
	raw, ok := values[field]
	if !ok || raw == nil {
		return nil, nil
	}
	var items []string
	switch value := raw.(type) {
	case string:
		items = strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' })
	case []any:
		for _, entry := range value {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("config %s.%s must list strings", key, field)
			}
			items = append(items, s)
		}
	default:
		return nil, fmt.Errorf("config %s.%s must be a list of strings", key, field)
	}
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" && !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	return out, nil
}
