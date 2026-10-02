// Command plugin is the Silo OpenID Connect sign-in plugin.
package main

import (
	_ "embed"
	"log/slog"
	"os"

	"github.com/Silo-Server/silo-plugin-sdk/pkg/pluginsdk/runtime"

	"github.com/Silo-Server/silo-plugin-auth-oidc/internal/provider"
)

// version is set at build time via -ldflags "-X main.version=...".
var version string

//go:embed manifest.json
var manifestJSON []byte

func main() {
	// go-plugin forwards the plugin's stderr to the host log.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	oidcProvider := provider.New(logger)
	runtime.ServeManifestWithOptions(manifestJSON, version,
		runtime.CapabilityServers{
			AuthProvider: oidcProvider,
			HttpRoutes:   &assetRoutes{},
		},
		runtime.WithAuthProviderChecks(oidcProvider),
		runtime.WithConfigure(oidcProvider.Configure),
	)
}
