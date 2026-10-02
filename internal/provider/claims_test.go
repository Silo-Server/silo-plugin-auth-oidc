package provider

import (
	"errors"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/oidc"
)

func TestGroupMatches(t *testing.T) {
	tests := []struct {
		configured, actual string
		want               bool
	}{
		{"silo-users", "silo-users", true},
		{"Silo-Users", "silo-users", true},
		{"silo-users", "/silo-users", true},            // Keycloak full path
		{"/silo-users", "silo-users", true},            // Keycloak full.path=false
		{"parent/child", "/parent/child", true},        // nested Keycloak group
		{"child", "/parent/child", false},              // a leaf name is not the path
		{"silo-users", "silo-users@idm.example", true}, // Kanidm SPN
		{"silo-users@idm.example", "silo-users@idm.example", true},
		{"silo-users@idm.example", "silo-users@other.example", false},
		{"silo-users", "silo-users-extra", false},
		{"silo", "silo-users", false},
		{"", "silo-users", false},
		// Only ASCII case folds: Unicode look-alikes do not match.
		{"silo-admins", "\u017filo-admins", false},             // LATIN SMALL LETTER LONG S
		{"silo-admins", "/\u017filo-admins", false},            // Keycloak path form
		{"silo-admins", "\u017filo-admins@idm.example", false}, // Kanidm SPN form
		{"kodi", "\u212aodi", false},                           // KELVIN SIGN
		{"Kodi", "\u212aodi", false},
		{"\u212aodi", "\u212aodi", true},
		{"KODI", "kodi", true},
	}
	for _, tt := range tests {
		if got := groupMatches(tt.configured, tt.actual); got != tt.want {
			t.Errorf("groupMatches(%q, %q) = %v, want %v", tt.configured, tt.actual, got, tt.want)
		}
	}
}

func TestExtractGroups(t *testing.T) {
	claims := map[string]any{
		"groups":       []any{"a", " b ", "a", "", 7},
		"single":       "solo",
		"zitadel":      map[string]any{"z-role": map[string]any{}, "a-role": map[string]any{}},
		"objects":      []any{map[string]any{"name": "named"}, map[string]any{"displayName": "shown"}},
		"realm_access": map[string]any{"roles": []any{"nested"}},
		"dotted.name":  []any{"literal"},
	}
	tests := []struct {
		path string
		want []string
	}{
		{"groups", []string{"a", "b"}},
		{"single", []string{"solo"}},
		{"zitadel", []string{"a-role", "z-role"}},
		{"objects", []string{"named", "shown"}},
		{"realm_access.roles", []string{"nested"}},
		{"dotted.name", []string{"literal"}},
		{"missing", nil},
		{"realm_access.missing", nil},
	}
	for _, tt := range tests {
		if got := extractGroups(claims, tt.path); !slices.Equal(got, tt.want) {
			t.Errorf("extractGroups(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPictureURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://img.example/a.png": "https://img.example/a.png",
		"http://img.example/a.png":  "http://img.example/a.png",
		"javascript:alert(1)":       "",
		"/relative.png":             "",
		"file:///etc/passwd":        "",
		"data:image/png;base64,AAA": "",
	} {
		if got := pictureURL(map[string]any{"picture": raw}, "picture"); got != want {
			t.Errorf("pictureURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestDisplayNameFallback(t *testing.T) {
	if got := displayName(map[string]any{"given_name": "Ada", "family_name": "Lovelace"}, "name"); got != "Ada Lovelace" {
		t.Errorf("displayName = %q", got)
	}
}

func TestExternalSubjectModes(t *testing.T) {
	standard := map[string]any{"iss": "https://idp.example/", "sub": "abc"}
	entra := map[string]any{"iss": "https://login.microsoftonline.com/tenant-1/v2.0", "sub": "pairwise", "tid": "tenant-1", "oid": "object-1"}
	tests := []struct {
		name   string
		mode   string
		claims map[string]any
		want   string
		err    bool
	}{
		{"standard keeps exact issuer", SubjectAuto, standard, "https://idp.example/|abc", false},
		{"auto detects Entra", SubjectAuto, entra, "tenant-1|object-1", false},
		{"forced standard on Entra", SubjectStandard, entra, "https://login.microsoftonline.com/tenant-1/v2.0|pairwise", false},
		{"entra without oid", SubjectEntra, standard, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := externalSubject(Config{SubjectMode: tt.mode}, tt.claims)
			if (err != nil) != tt.err || got != tt.want {
				t.Errorf("externalSubject = %q, %v; want %q (err %v)", got, err, tt.want, tt.err)
			}
		})
	}
}

func TestBuildAccountGates(t *testing.T) {
	claims := map[string]any{"iss": "https://idp.example", "sub": "s", "groups": []any{"users"}}
	if _, err := buildAccount(Config{SubjectMode: SubjectAuto, GroupsClaim: "groups", AllowedGroups: []string{"admins"}}, claims); !errors.Is(err, errNotPermitted) {
		t.Errorf("allowed-groups gate: err = %v", err)
	}
	account, err := buildAccount(Config{SubjectMode: SubjectAuto, GroupsClaim: "groups", AdminGroups: []string{"admins"}}, claims)
	if err != nil || account.GetManagedRole() != pluginv1.AuthManagedRole_AUTH_MANAGED_ROLE_USER {
		t.Errorf("admin groups set, not a member: role = %v, err = %v", account.GetManagedRole(), err)
	}
}

func TestMergeClaimsProtectsTokenClaims(t *testing.T) {
	merged := mergeClaims(
		map[string]any{"iss": "https://idp", "sub": "s", "email": "old@example.com"},
		map[string]any{"iss": "https://evil", "sub": "other", "email": "new@example.com", "groups": []any{"g"}, "oid": "x"},
	)
	if merged["iss"] != "https://idp" || merged["sub"] != "s" || merged["oid"] != nil {
		t.Errorf("protected claims overridden: %v", merged)
	}
	if merged["email"] != "new@example.com" || merged["groups"] == nil {
		t.Errorf("userinfo claims not merged: %v", merged)
	}
}

func TestParseConfig(t *testing.T) {
	entry := func(key string, value map[string]any) *pluginv1.ConfigEntry {
		st, err := structpb.NewStruct(value)
		if err != nil {
			t.Fatal(err)
		}
		return &pluginv1.ConfigEntry{Key: key, Value: st}
	}
	cfg, err := ParseConfig([]*pluginv1.ConfigEntry{
		// The host owns the button keys; a value the plugin would not accept
		// must not fail Configure.
		entry("display_name", map[string]any{"value": 42.0}),
		entry(keyConnection, map[string]any{
			"issuer_url": " https://auth.example/application/o/silo/ ", "client_id": "silo", "client_secret": "s3cret\n",
			"scopes": "openid email  profile", "request_groups_scope": "true", "request_offline_access": true,
		}),
		entry(keyAccess, map[string]any{
			"allowed_groups": "silo-users\r\ncn=silo-family,ou=groups,dc=example\n silo-users\n",
			"admin_groups":   []any{"silo-admins"},
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "https://auth.example/application/o/silo/" || cfg.ClientSecret != "s3cret" {
		t.Errorf("connection = %+v", cfg)
	}
	if got := cfg.RequestedScopes(); !slices.Equal(got, []string{"openid", "email", "profile", "groups", "offline_access"}) {
		t.Errorf("scopes = %v", got)
	}
	if !slices.Equal(cfg.AllowedGroups, []string{"silo-users", "cn=silo-family,ou=groups,dc=example"}) || !slices.Equal(cfg.AdminGroups, []string{"silo-admins"}) {
		t.Errorf("groups = %v / %v", cfg.AllowedGroups, cfg.AdminGroups)
	}
	if cfg.TokenAuthMethod != "client_secret_basic" || cfg.UsernameClaim != "preferred_username" || cfg.SubjectMode != SubjectAuto {
		t.Errorf("defaults = %+v", cfg)
	}
	if problems := cfg.Problems(); len(problems) != 0 {
		t.Errorf("problems = %v", problems)
	}

	if _, err := ParseConfig([]*pluginv1.ConfigEntry{entry(keyConnection, map[string]any{"issuer_url": 42.0})}); err == nil {
		t.Error("a number for issuer_url should fail")
	}
	if _, err := ParseConfig([]*pluginv1.ConfigEntry{entry(keyConnection, map[string]any{"allow_hs256": "maybe"})}); err == nil {
		t.Error("a non-boolean switch should fail")
	}
	empty, err := ParseConfig(nil)
	if err != nil || len(empty.Problems()) == 0 {
		t.Errorf("empty config: err = %v, problems = %v", err, empty.Problems())
	}
	bad := Config{Issuer: "https://x", ClientID: "c", TokenAuthMethod: "private_key_jwt", SubjectMode: "weird", Prompt: "none login", AllowHS256: true}
	if got := len(bad.Problems()); got != 4 {
		t.Errorf("problems = %v, want 4", bad.Problems())
	}
}

func TestHS256SecretLength(t *testing.T) {
	cfg := Config{Issuer: "https://x", ClientID: "c", TokenAuthMethod: "client_secret_basic", SubjectMode: SubjectAuto, AllowHS256: true}
	cfg.ClientSecret = strings.Repeat("s", oidc.MinHS256SecretBytes-1)
	if problems := cfg.Problems(); len(problems) != 1 || !strings.Contains(problems[0], "at least 32 bytes") {
		t.Errorf("short HS256 secret: problems = %v", problems)
	}
	cfg.ClientSecret = strings.Repeat("s", oidc.MinHS256SecretBytes)
	if problems := cfg.Problems(); len(problems) != 0 {
		t.Errorf("32-byte HS256 secret: problems = %v", problems)
	}
	cfg.AllowHS256 = false
	cfg.ClientSecret = "short"
	if problems := cfg.Problems(); len(problems) != 0 {
		t.Errorf("short secret without HS256: problems = %v", problems)
	}
}

func TestEmailVerifiedOnlyForTheEmailClaim(t *testing.T) {
	claims := map[string]any{
		"iss": "https://idp.example", "sub": "s",
		"email": "verified@example.com", "email_verified": true,
		"preferred_username": "editable@example.com",
	}
	account, err := buildAccount(Config{SubjectMode: SubjectAuto, EmailClaim: "preferred_username"}, claims)
	if err != nil {
		t.Fatal(err)
	}
	if account.GetEmail() != "editable@example.com" || account.EmailVerified != nil {
		t.Errorf("remapped email: email = %q, email_verified = %v; want unset", account.GetEmail(), account.EmailVerified)
	}
	account, err = buildAccount(Config{SubjectMode: SubjectAuto, EmailClaim: "email"}, claims)
	if err != nil || account.EmailVerified == nil || !account.GetEmailVerified() {
		t.Errorf("standard email: email_verified = %v, err = %v; want true", account.EmailVerified, err)
	}
}
