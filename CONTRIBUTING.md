# Contributing to the OpenID Connect Sign-in Plugin

The [Silo contribution guide](https://github.com/Silo-Server/.github/blob/main/CONTRIBUTING.md)
covers project-wide coordination, focused changes, evidence, AI disclosure, and
pull request expectations. Those requirements apply here; this guide adds the
plugin-specific workflow.

## Before you start

Open an [issue](https://github.com/Silo-Server/silo-plugin-auth-oidc/issues)
before changing token validation, claim mapping, group rules, configuration
keys, or the advertised capabilities. This repository owns the OpenID Connect
protocol side of sign-in; the plugin contract belongs in
[`silo-plugin-sdk`](https://github.com/Silo-Server/silo-plugin-sdk), and
accounts, linking, roles, and sessions belong in
[`silo-server`](https://github.com/Silo-Server/silo-server).

Configuration keys are stored per installation. Renaming a key or field loses
the operator's saved value, and changing how the account key is built
disconnects existing Silo accounts. Treat both as breaking changes.

## Development setup

Use the Go version declared in `go.mod`. A local `go.work` may point at a sibling
SDK checkout while developing both repositories, but committed code and CI must
resolve released dependencies with `GOWORK=off`. Never commit client secrets,
tokens, captured provider responses with personal data, or a local filesystem
`replace` directive.

## Validate your change

```sh
GOWORK=off go test ./...
GOWORK=off go vet ./...
GOWORK=off go build ./...
GOWORK=off go run . manifest >/dev/null
gofmt -l .
golangci-lint run ./...
```

The manifest command must exit successfully and `gofmt -l .` should print
nothing. Add coverage in `internal/provider` against the test provider in
`internal/oidctest` for any change to validation, claim mapping, group rules,
refresh, or the connection test, including the failure case.

## Open the pull request

Use a Conventional Commit title, name the providers you tested against, and
paste the actual validation results. Read the
[AI-assisted contribution policy](https://github.com/Silo-Server/silo-server/blob/main/docs/ai-contributions.md)
and include its disclosure block.
