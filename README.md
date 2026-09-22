# Keycloak Google One-Tap

Extension for [Keycloak](https://www.keycloak.org) that lets an application exchange the
Google **ID token** handed out by [Sign in with Google / One Tap](https://developers.google.com/identity/gsi/web)
for Keycloak tokens through the standard
[token exchange](https://www.keycloak.org/securing-apps/token-exchange#_external_token_to_internal_token_exchange)
endpoint.

Keycloak's built-in Google provider only accepts a Google **access token** in an external
exchange (it validates it by calling Google's user info endpoint). One Tap never issues an
access token, only an ID token, so out of the box the exchange fails with
`invalid_token` / `user info call failure`
([keycloak#20042](https://github.com/keycloak/keycloak/issues/20042)).

This fork targets Keycloak **26.2.x** (the upstream project stopped at 24/25) and adds one
more thing the built-in exchange lacks: linking to users that already exist in the realm.

## What it provides

**Identity provider `google-one-tap`** — Keycloak's Google provider plus support for
`subject_token_type=urn:ietf:params:oauth:token-type:id_token`. The ID token is verified with
Google's client library (signature against Google's published keys, issuer, expiry, audience =
the provider's client id). The token's email must be verified by Google, and when the provider
restricts the hosted domain the `hd` claim must match. Browser login, mappers and the
access-token exchange are inherited unchanged.

**Token exchange provider `google-one-tap`** — takes over only exchanges whose
`subject_issuer` is a `google-one-tap` instance. It is Keycloak's own (v1) provider with one
addition: when the realm already has a user with the verified email and that user is not yet
linked to the provider, the link is created and the user logs in. Keycloak alone answers
`User already exists` in that case, which makes One Tap unusable for an existing user base.
Linking requires **Trust Email** on the provider and unique emails in the realm.

## Installation

1. Put the jar into `/opt/keycloak/providers/` (Bitnami: `/opt/bitnami/keycloak/providers/`)
   and restart Keycloak. The jar bundles the Google client library.
2. Start Keycloak with the token exchange features enabled, e.g.
   `--features=token-exchange,admin-fine-grained-authz:v1`.
3. In the realm add an identity provider of type **Google One-Tap** (provider id
   `google-one-tap`). Client id = the Google OAuth client id your frontend passes to
   `google.accounts.id.initialize` (the ID token's audience). Enable **Trust Email**.
4. Grant your client the `token-exchange` permission on that provider
   (provider → *Permissions* → enable → `token-exchange` → client policy), exactly as for a
   built-in provider.

## Usage

```bash
curl -X POST https://<keycloak>/realms/<realm>/protocol/openid-connect/token \
  -d client_id=<client> -d client_secret=<secret> \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_issuer=<alias of the google-one-tap provider> \
  -d subject_token_type=urn:ietf:params:oauth:token-type:id_token \
  -d subject_token=<credential from One Tap>
```

Responses:

| Case | HTTP | `error` | event reason |
|------|------|---------|--------------|
| valid token, verified email | 200 | — | — |
| bad signature / audience / issuer / expired | 400 | `invalid_token` | `id token rejected` |
| email not verified by Google | 400 | `invalid_token` | `email not verified` |
| `hd` does not match the configured hosted domain | 400 | `invalid_token` | `hosted domain mismatch` |
| Google's keys unreachable | 503 | `temporarily_unavailable` | `google public keys unavailable` |

Every exchange served by this extension carries the event detail
`token_exchange_provider=google-one-tap`; a link created for an existing user is recorded as a
`FEDERATED_IDENTITY_LINK` event.

## Building

`./gradlew test shadowJar` with JDK 17, or without a local JDK:

```bash
scripts/gradlew-docker.sh test shadowJar   # → build/libs/keycloak-google-one-tap-<keycloak version>.jar
scripts/smoke.sh                           # boots Keycloak 26.2.5 in Docker and exercises both providers
```

## Compatibility

The version of this library mirrors the Keycloak version it is built against.
