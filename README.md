# OpenID Connect Sign-in Plugin for Silo

First-party [Silo](https://github.com/Silo-Server/silo-server) plugin that lets
people sign in with an OpenID Connect provider, such as Authelia, authentik,
Pocket ID, Keycloak, Kanidm, Zitadel, or Tinyauth.

The plugin talks to the provider and returns facts about the person: a stable
account key, username, email, whether the provider verified the email, display
name, groups, picture URL, and the Silo role its group rules assign. Silo
decides what to do with them: it links or creates the account, applies the
role, and manages sessions. The plugin holds no Silo account logic.

## What it does

- Discovers the provider from its issuer and requires the discovery document's
  `issuer` to match the setting exactly. A trailing slash is significant
  (authentik's issuer has one).
- Sends PKCE S256 and a nonce on every sign-in, whatever the provider
  advertises.
- Validates the ID token: signature, `iss`, `aud` and `azp`, `exp`, `iat`,
  `nbf`, and `nonce`. It accepts RS256/384/512, PS256/384/512,
  ES256/384/512, and EdDSA. HS256 (signed with the client secret) is refused
  unless the operator turns on **Allow HS256 ID tokens**.
- Caches discovery and signing keys in memory and refetches the keys when a
  token names an unknown key ID, at most once every 10 seconds.
- Always calls userinfo when the provider has an endpoint and merges it over
  the ID token claims, because Authelia 4.39 and Zitadel put profile, email,
  and group claims only there. Userinfo never overrides `iss`, `sub`, `tid`,
  `oid`, or the other token claims.
- Keys accounts by the exact issuer, `|`, and `sub`. For Microsoft Entra ID it
  uses tenant ID `|` object ID, because Entra's `sub` differs per application.
- Passes `email_verified` through unchanged: true, false, or unset. It is
  always unset when the email claim is mapped to a claim other than `email`,
  because `email_verified` describes only the standard claim.
- Applies two group rules at every sign-in and re-check: **allowed groups**
  (people in none are refused) and **admin groups** (members get the Silo
  admin role, everyone else the user role).
- Answers Silo's account re-checks by redeeming the stored refresh token,
  then re-applies the group rules. It keeps a refresh token only when
  **Request offline access** is on and the provider granted `offline_access`.
  Without one, or once a refresh token is past its lifetime, it reports that
  it cannot check, and Silo gives the sessions an absolute age limit instead.
- Treats a refused refresh token as a revocation only while the token is
  known to be inside its lifetime, from the provider's `refresh_expires_in`,
  the `exp` of a JWT refresh token, or the **Refresh token lifetime**
  setting. Providers refuse expired and revoked tokens with the same
  `invalid_grant` error, so without a lifetime a refusal only reports that
  the account cannot be checked. A refusal at or after the **Refresh token
  absolute lifetime**, or after a refresh whose answer was lost, also counts
  as expiry. A refused or expired token is dropped from Silo, so it is never
  presented again.
- Loads the provider's discovery document and signing keys before it decides
  whether enough time is left to redeem a refresh token, so a slow provider
  cannot make it spend a rotated token it has no time to hand back.
- Builds the provider logout URL for web sign-out when the operator turns it
  on and the provider has an `end_session_endpoint`.
- Serves the login-button icon from its own public `/assets/` route.

There is no option to skip TLS verification. For a provider with a private
certificate authority, paste the CA certificate into **Custom CA certificate**.

## Setup

1. Install the plugin in Silo and open its settings.
2. At the provider, create a confidential client for Silo. Register the
   redirect URI shown on Silo's Sign-in settings page, which has the form
   `https://<silo>/api/v2/auth/oauth/<installation id>/callback`.
3. Under **Provider connection**, enter the issuer URL, client ID, and client
   secret. Run the connection test.
4. If the provider sends groups, set **Allowed groups** and **Admin groups**
   under **Access rules**.
5. To let Silo re-check accounts at the provider, turn on **Request offline
   access**. Silo keeps the refresh token only when the provider grants
   `offline_access`. Some providers (Keycloak, Kanidm) also issue refresh
   tokens without it, but those end with the browser session, and the
   provider's refusal would sign the person out of Silo. Without offline
   access, Silo does not re-check accounts and gives their sessions an
   absolute age limit.
6. Make the provider's refresh-token lifetime longer than Silo's re-check
   interval (12 hours by default) plus about an hour. Silo re-checks an
   account when its session refreshes, and an hourly task re-checks accounts
   that still have live sessions, API keys or Audiobookshelf sessions.
   Providers refuse expired and revoked refresh tokens with the same error.
   Unless the provider reports the lifetime, enter it as **Refresh token
   lifetime**; within it, a refusal signs the person out of Silo. Authelia
   never reports it. Keycloak reports it for offline tokens only when
   **Offline Session Max Limited** is on; otherwise enter the realm's
   **Offline Session Idle** (30 days by default). The setting is the
   per-token lifetime, counted from when the token was issued or last
   renewed; if several limits apply, enter the shortest. A value longer than
   the real one signs people out when their tokens merely expire. Left blank
   or set to `0`, a refusal never signs anyone out, and the plugin logs a
   warning naming this setting. If the provider also caps refresh tokens at
   a fixed age from sign-in (Zitadel's **Refresh Token Expiration**), enter
   that cap as **Refresh token absolute lifetime**, or active people are
   signed out when it ends.
7. If you turn on **Sign out at the provider**, register Silo's sign-in page
   as a post-logout redirect URI at the provider. Keycloak and Zitadel refuse
   the sign-out otherwise.

### Settings

| Group | Key | Default | Notes |
|---|---|---|---|
| Button label | `display_name.value` | Single sign-on | The provider's name, such as `authentik`. Silo shows it on the login button and in sentences such as "Connect authentik", so leave out "Sign in with". |
| Button icon | `icon_url_path.value` | `sso.png` | `sso.png` or `sso.svg`, served from the plugin's `/assets/` route. Silo uses the default until the setting is saved. The Apple apps do not draw SVG icons. |
| Provider connection | `issuer_url` | | Exact issuer, https only. |
| | `client_id`, `client_secret` | | The secret is stored encrypted by Silo. |
| | `token_endpoint_auth_method` | `client_secret_basic` | Or `client_secret_post`. |
| | `scopes` | `openid profile email` | `openid` is always sent. |
| | `request_groups_scope` | off | Adds `groups`. |
| | `request_offline_access` | off | Adds `offline_access`. Re-checks need it granted. |
| | `refresh_token_lifetime` | blank (unknown) | The provider's per-token refresh-token lifetime: whole days (`30d`, at most `9999d`), or hours and minutes (`12h`, `90m`, `1h30m`). Needed unless the provider reports it. Blank or `0` means unknown. |
| | `refresh_token_max_lifetime` | blank (none) | The provider's absolute refresh-token cap counted from sign-in, in the same format. A refusal at or after it counts as expiry. Blank or `0` means none. |
| | `prompt` | provider default | `login`, `select_account`, or `consent`. |
| | `provider_logout` | off | End the provider session on web sign-out. Register Silo's sign-in page as a post-logout redirect URI. |
| | `ca_pem` | | Extra trusted CA certificates. |
| | `allow_hs256` | off | Accept HS256 ID tokens. |
| Claim mapping | `username`, `email`, `display_name`, `groups`, `picture` | `preferred_username`, `email`, `name`, `groups`, `picture` | Claim paths; dots walk into nested objects. |
| | `subject` | `auto` | `auto`, `standard` (iss + sub), or `entra` (tid + oid). |
| Access rules | `allowed_groups`, `admin_groups` | empty | One group per line. Commas are part of the name. |

Changing the account key setting after people have signed in disconnects their
Silo accounts from the provider.

### Provider notes

| Provider | Issuer | Groups |
|---|---|---|
| Authelia | `https://auth.example` | Turn on the groups scope. Groups and email arrive only through userinfo. No logout endpoint. Refresh tokens need offline access and consent. The default refresh-token lifespan is 90 minutes, so most re-checks would find the token expired: add a custom lifespan under `identity_providers.oidc.lifespans.custom` with a longer `refresh_token`, set it as the client's `lifespan`, and enter the same value as **Refresh token lifetime**. Authelia does not report the lifetime. |
| authentik | `https://auth.example/application/o/<slug>/` (trailing slash) | Sent with the `profile` scope. `email_verified` is always false. Set a signing key on the provider, or allow HS256. |
| Pocket ID | `https://id.example` | Turn on the groups scope. |
| Keycloak | `https://kc.example/realms/<realm>` | Add a group membership mapper. Full paths such as `/silo-users` match `silo-users`. Keep `offline_access` among the client's optional scopes. Offline tokens report their lifetime only when the realm's **Offline Session Max Limited** is on; otherwise enter the realm's **Offline Session Idle** (`30d` by default) as **Refresh token lifetime**. Without it, Silo cannot tell a revoked token from an expired one, so a person removed at Keycloak keeps their Silo sessions and API keys until Silo's absolute age limit. With offline access on, Keycloak 26 does not reuse its browser session for the next sign-in and asks for the password again. For provider sign-out, add Silo's sign-in page to **Valid post logout redirect URIs**. |
| Kanidm | `https://idm.example/oauth2/openid/<client>` | Turn on the groups scope and add it to the scope map. Groups arrive as `name@domain` and UUIDs; `silo-users` matches `silo-users@domain`. Leave offline access off: Kanidm refuses scopes missing from the scope map, and the refresh tokens it issues without `offline_access` are not kept, so sessions get Silo's absolute age limit. `preferred_username` is the SPN `name@domain`; Silo uses the part before the `@` (such as `bob`) as a new account's username. |
| Zitadel | `https://zitadel.example` | Add scope `urn:zitadel:iam:org:projects:roles` and set the groups claim to `urn:zitadel:iam:org:project:roles`; role keys are the groups. Zitadel reports no refresh-token lifetime: enter its **Refresh Token Idle Expiration** (30 days by default) as **Refresh token lifetime** and its **Refresh Token Expiration** (90 days by default) as **Refresh token absolute lifetime**. The latter counts from sign-in however often the token rotates; without it, people are signed out of Silo when it ends. For provider sign-out, add Silo's sign-in page to the application's **Post Logout URIs**. |
| Tinyauth | `https://tinyauth.example` | Turn on the groups scope; groups come from its LDAP backend. No logout endpoint. `sub` is derived from the username, so renaming a user in the directory disconnects their Silo account. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant id>/v2.0` | Group object IDs. Single-tenant issuers only. |

## Dependency Model

This repository consumes `github.com/Silo-Server/silo-plugin-sdk` as a normal
Go module dependency. CI and release builds run with `GOWORK=off` and expect
the SDK version in `go.mod` to resolve from a published semver tag.

## Development

```sh
make test       # go test ./...
make vet
make lint       # golangci-lint
make build      # ./plugin
make build-all  # dist/plugin-<os>-<arch> for darwin/arm64, linux/amd64, linux/arm64
```

`internal/oidctest` runs an in-process OpenID provider over TLS for the tests.
It covers the quirks listed above: userinfo-only claims, group claim shapes,
key rotation, HS256, refresh token rotation, and missing endpoints.

To try a build against a Silo server, upload the binary on the server's plugin
page; Silo reads the manifest with `./plugin manifest`.

**Temporary:** `go.mod` requires SDK `v0.22.0`, the release that carries the
auth additions and is not tagged yet, and replaces it with a local SDK
checkout. CI rejects that replace, so remove it once `v0.22.0` is published. For other multi-repository work, use a local
`go.work` instead of a `replace`.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.
Changes to token validation, claim mapping, group rules, or the configuration
should start as an issue.

## License

`silo-plugin-auth-oidc` is licensed under `AGPL-3.0-or-later`. See
[LICENSE](LICENSE).
