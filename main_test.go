package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"path"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
	publicconfig "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/config"
	publicmanifest "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/manifest"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/provider"
)

func loadManifest(t *testing.T) *pluginv1.PluginManifest {
	t.Helper()
	m, err := publicmanifest.LoadWithChecksum(manifestJSON, "0.0.0-test")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	return m
}

func TestManifestIsValid(t *testing.T) {
	m := loadManifest(t)
	if err := publicmanifest.ValidateCatalogPresentation(m, "https://github.com/Silo-Server/silo-plugin-auth-oidc"); err != nil {
		t.Errorf("catalog presentation: %v", err)
	}
	var auth, routes *pluginv1.CapabilityDescriptor
	for _, capability := range m.GetCapabilities() {
		switch capability.GetType() {
		case "auth_provider.v1":
			auth = capability
		case "http_routes.v1":
			routes = capability
		}
	}
	if auth == nil || routes == nil {
		t.Fatal("manifest needs auth_provider.v1 and http_routes.v1 capabilities")
	}
	if len(auth.GetAuthModes()) != 1 || auth.GetAuthModes()[0] != publicmanifest.AuthModeOAuth2 {
		t.Errorf("auth_modes = %v", auth.GetAuthModes())
	}
	if !publicmanifest.AuthProviderSupportsConnectionTest(auth) {
		t.Error("connection_test is not advertised")
	}
	var assetRoute *pluginv1.HttpRouteDescriptor
	for _, route := range m.GetHttpRoutes() {
		if route.GetPath() == "/assets/*" {
			assetRoute = route
		}
	}
	if assetRoute == nil || assetRoute.GetAccess() != "public" || assetRoute.GetMethod() != http.MethodGet || assetRoute.GetStaticAsset() {
		t.Errorf("asset route = %+v, want a public plugin-served GET /assets/*", assetRoute)
	}
}

func TestManifestConfigSchema(t *testing.T) {
	m := loadManifest(t)
	keys := map[string]*pluginv1.ConfigSchema{}
	for _, schema := range m.GetGlobalConfigSchema() {
		keys[schema.GetKey()] = schema
	}
	for _, key := range []string{"display_name", "icon_url_path", "connection", "claims", "access"} {
		if keys[key] == nil {
			t.Fatalf("global config key %q missing", key)
		}
	}
	// The host reads the login button from {"value": "..."} under these keys.
	for key, value := range map[string]string{"display_name": "x", "icon_url_path": "sso.svg"} {
		if err := publicconfig.ValidateManifestGlobalValue(m, key, map[string]any{"value": value}); err != nil {
			t.Errorf("%s value shape: %v", key, err)
		}
	}
	// A file the plugin does not embed fails on save instead of serving 404.
	if err := publicconfig.ValidateManifestGlobalValue(m, "icon_url_path", map[string]any{"value": "sso.jpg"}); err == nil {
		t.Error("icon_url_path accepted a file the plugin does not serve")
	}
	secret := false
	for _, field := range keys["connection"].GetAdminForm().GetFields() {
		if field.GetKey() == "client_secret" {
			secret = field.GetSecret()
		}
	}
	if !secret {
		t.Error("client_secret must be marked secret")
	}
	valid := map[string]any{
		"issuer_url": "https://idp.example", "client_id": "silo", "client_secret": "s",
		"token_endpoint_auth_method": "client_secret_basic", "scopes": "openid profile email",
		"request_groups_scope": true, "request_offline_access": false, "prompt": "",
		"provider_logout": false, "ca_pem": "", "allow_hs256": false, "refresh_token_lifetime": "30d",
	}
	if err := publicconfig.ValidateManifestGlobalValue(m, "connection", valid); err != nil {
		t.Errorf("connection value: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal([]byte(keys["connection"].GetJsonSchema()), &schema); err != nil {
		t.Fatal(err)
	}
	properties := schema["properties"].(map[string]any)
	if !properties["client_secret"].(map[string]any)["writeOnly"].(bool) {
		t.Error("client_secret json_schema must be writeOnly")
	}

	// The lifetime settings share one grammar in the admin form, the JSON
	// schema the host enforces, and the plugin's parser.
	formPatterns := map[string]string{}
	for _, field := range keys["connection"].GetAdminForm().GetFields() {
		formPatterns[field.GetKey()] = field.GetValidation().GetPattern()
	}
	for _, field := range []string{"refresh_token_lifetime", "refresh_token_max_lifetime"} {
		schemaPattern, _ := properties[field].(map[string]any)["pattern"].(string)
		if formPatterns[field] != provider.LifetimePattern || schemaPattern != provider.LifetimePattern {
			t.Errorf("%s patterns: form %q, json_schema %q; want %q", field, formPatterns[field], schemaPattern, provider.LifetimePattern)
		}
		for value, ok := range map[string]bool{"": true, "0": true, "30d": true, "1h30m": true, "36500d": false, "1.5h": false} {
			edited := map[string]any{"issuer_url": "https://idp.example", "client_id": "silo", field: value}
			if err := publicconfig.ValidateManifestGlobalValue(m, "connection", edited); (err == nil) != ok {
				t.Errorf("%s %q: validation error %v, want accepted = %v", field, value, err, ok)
			}
		}
	}
}

// Until the operator saves icon_url_path, the host shows the setting's
// default: the JSON schema's value default, else the admin form's. Both must
// name the same embedded file, or a fresh install shows a broken icon. The
// default is a PNG because the Apple apps do not draw SVG, and every file
// the setting offers must be embedded.
func TestDefaultIconIsServed(t *testing.T) {
	m := loadManifest(t)
	var schemaDefault, formDefault string
	var enum, options []string
	for _, schema := range m.GetGlobalConfigSchema() {
		if schema.GetKey() != "icon_url_path" {
			continue
		}
		var parsed struct {
			Properties struct {
				Value struct {
					Default string   `json:"default"`
					Enum    []string `json:"enum"`
				} `json:"value"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(schema.GetJsonSchema()), &parsed); err != nil {
			t.Fatal(err)
		}
		schemaDefault, enum = parsed.Properties.Value.Default, parsed.Properties.Value.Enum
		for _, field := range schema.GetAdminForm().GetFields() {
			if field.GetKey() == "value" {
				formDefault = field.GetDefaultValue().GetStringValue()
				for _, option := range field.GetOptions() {
					options = append(options, option.GetValue())
				}
			}
		}
	}
	if schemaDefault == "" || schemaDefault != formDefault {
		t.Fatalf("icon_url_path defaults: json_schema %q, admin form %q; want the same file", schemaDefault, formDefault)
	}
	if !slices.Equal(enum, options) || !slices.Contains(enum, schemaDefault) {
		t.Fatalf("icon_url_path: json_schema enum %v, admin form options %v, default %q", enum, options, schemaDefault)
	}
	for _, name := range enum {
		resp, err := (&assetRoutes{}).Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: http.MethodGet, Path: "/assets/" + name})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetStatusCode() != http.StatusOK {
			t.Fatalf("icon %q: %d", name, resp.GetStatusCode())
		}
		contentType := resp.GetHeaders()["Content-Type"]
		switch path.Ext(name) {
		case ".png":
			if contentType != "image/png" || !bytes.HasPrefix(resp.GetBody(), []byte("\x89PNG\r\n\x1a\n")) {
				t.Errorf("icon %q: %s, not a PNG", name, contentType)
			}
		case ".svg":
			if contentType != "image/svg+xml" || !strings.Contains(string(resp.GetBody()), "<svg") {
				t.Errorf("icon %q: %s, not an SVG", name, contentType)
			}
		default:
			t.Errorf("icon %q has an unexpected type", name)
		}
	}
	if path.Ext(schemaDefault) != ".png" {
		t.Errorf("default icon %q is not a PNG, which the Apple apps need", schemaDefault)
	}
}

func TestAssetRouteRejectsOtherPaths(t *testing.T) {
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/assets/"},
		{http.MethodGet, "/assets/../main.go"},
		{http.MethodGet, "/assets/missing.svg"},
		{http.MethodGet, "/manifest.json"},
		{http.MethodGet, "/assets//sso.svg"},
		{http.MethodPost, "/assets/sso.svg"},
	} {
		resp, err := (&assetRoutes{}).Handle(context.Background(), &pluginv1.HandleHTTPRequest{Method: tc.method, Path: tc.path})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetStatusCode() == http.StatusOK {
			t.Errorf("%s %s answered 200", tc.method, tc.path)
		}
	}
}
