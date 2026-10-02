package main

import (
	"context"
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	pluginv1 "github.com/Silo-Server/silo-plugin-sdk/pkg/pluginproto/silo/plugin/v1"
)

// Catalog installs ship only the binary, so the login-button icons are embedded
// and served from the public GET /assets/* route.
//
//go:embed assets
var assetFiles embed.FS

const assetsPrefix = "/assets/"

type assetRoutes struct {
	pluginv1.UnimplementedHttpRoutesServer
}

var _ pluginv1.HttpRoutesServer = (*assetRoutes)(nil)

func (*assetRoutes) Handle(_ context.Context, req *pluginv1.HandleHTTPRequest) (*pluginv1.HandleHTTPResponse, error) {
	if req.GetMethod() != http.MethodGet && req.GetMethod() != http.MethodHead {
		return plainResponse(http.StatusMethodNotAllowed, "method not allowed"), nil
	}
	name, ok := strings.CutPrefix(req.GetPath(), assetsPrefix)
	if !ok || name == "" || strings.Contains(name, "..") || path.Clean("/"+name) != "/"+name {
		return plainResponse(http.StatusNotFound, "not found"), nil
	}
	body, err := fs.ReadFile(assetFiles, "assets/"+name)
	if err != nil {
		return plainResponse(http.StatusNotFound, "not found"), nil
	}
	ext := path.Ext(name)
	contentType := mime.TypeByExtension(ext)
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	headers := map[string]string{
		"Content-Type":           contentType,
		"Cache-Control":          "public, max-age=86400",
		"X-Content-Type-Options": "nosniff",
	}
	if ext == ".svg" {
		headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
	}
	// Silo's plugin proxy sets nosniff on every plugin response itself but
	// does not forward the CSP above. It is sent for a host that passes it
	// on; the embedded icons contain no script.
	if req.GetMethod() == http.MethodHead {
		body = nil
	}
	return &pluginv1.HandleHTTPResponse{StatusCode: http.StatusOK, Headers: headers, Body: body}, nil
}

func plainResponse(code int, message string) *pluginv1.HandleHTTPResponse {
	return &pluginv1.HandleHTTPResponse{
		StatusCode: int32(code),
		Headers:    map[string]string{"Content-Type": "text/plain; charset=utf-8"},
		Body:       []byte(message),
	}
}
