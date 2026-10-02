# Agent instructions

Read [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) before working here; they define this repository's ownership, build, and validation rules.

## Security rules

This plugin decides who may sign in to Silo. Keep these invariants, and add a test when you touch them:

- The account key is the exact issuer plus `sub` (Entra: `tid` plus `oid`). Never normalize the issuer and never key on username or email.
- Every authorization sends PKCE S256 and a fresh nonce. ID tokens are checked for signature, `iss`, `aud`/`azp`, `exp`, `iat`, and `nonce`. HS256 stays behind its opt-in.
- Userinfo never overrides `iss`, `sub`, `tid`, `oid`, or other token claims, and its `sub` must match the ID token.
- No option skips TLS verification. The plugin dials only the configured issuer's endpoints and never fetches a user-supplied URL such as `picture`.
- A denial leaves `external_subject` empty. Messages, denial details, and logs never contain secrets or tokens.
- The plugin holds no Silo account logic; it returns facts and the group-rule verdicts.

## Writing

Give human-facing prose a final readability pass. Lead with the outcome, use concrete plain language and active voice, and cut filler, stock framing, repetition, and promotional claims. Preserve meaning, evidence, citations, uncertainty, and established terminology. Never rewrite exact quotations, commands, logs, identifiers, API names, or contractual language. Match the audience and use restrained formatting.

## Pull requests

- Never create a pull request unless the developer explicitly asks.
- Use a plain-language Conventional Commit title. In the body, explain the problem before the solution and end with the required AI disclosure, naming the exact model, harness, and tooling used.
- Keep one concern per pull request. If the description needs the word "also" for another change, split it.
- When babysitting a pull request, poll for checks and comments newer than the last push. Verify bot findings against the source, fix real issues, and dismiss false positives with a written reason. Stay quiet when nothing is new, and stop when the latest commit is green.
