---
title: Service Authentication Guide
description: Connecting services that require per-user authentication.
---

## Service Authentication

Some services need users to authenticate with their own accounts — Notion API keys, Linear OAuth tokens, Stainless credentials. MCP Front handles this after identity provider login via OAuth or manual token entry.

## User flow

When a user first accesses a service with `requiresUserToken: true`, they go through a one-time setup flow:

1. The user connects to an MCP server endpoint (e.g., `/notion/sse`) through Claude.
2. MCP Front redirects them to the identity provider for organization login.
3. After login, if any OAuth-type services have `requiresUserToken: true` and the user hasn't connected them yet, MCP Front shows an interstitial page listing those services.
4. The user clicks "Connect" and gets redirected to the service's authorization page (e.g., Stainless OAuth). After approving, they return to MCP Front automatically.
5. Once all OAuth services are connected (or the user clicks "Skip" to defer), MCP Front redirects back to Claude with the authorization code.
6. For manual token services, users manage their tokens directly at `/my/tokens` — there is no interstitial for these.

OAuth tokens refresh automatically. Manual tokens persist until the user updates or deletes them at `/my/tokens`.

## Configuration

Set `requiresUserToken: true` and add a `userAuthentication` object specifying the method.

### Type: `oauth`

For services with OAuth 2.0 support. MCP Front handles the token exchange and refresh cycle.

```json
"stainless": {
  "transportType": "stdio",
  "command": "stainless",
  "args": ["mcp"],
  "requiresUserToken": true,
  "userAuthentication": {
    "type": "oauth",
    "displayName": "Stainless",
    "clientId": {"$env": "STAINLESS_OAUTH_CLIENT_ID"},
    "clientSecret": {"$env": "STAINLESS_OAUTH_CLIENT_SECRET"},
    "authorizationUrl": "https://api.stainless.com/oauth/authorize",
    "tokenUrl": "https://api.stainless.com/oauth/token",
    "scopes": ["mcp:read", "mcp:write"]
  }
}
```

Fields: `displayName` (shown on the interstitial page), `clientId` and `clientSecret` (your OAuth app credentials), `authorizationUrl` and `tokenUrl` (service OAuth endpoints), `scopes` (permissions to request).

### Type: `manual`

For services that use user-generated API tokens.

```json
"notion": {
  "transportType": "stdio",
  "command": "notion-mcp",
  "requiresUserToken": true,
  "userAuthentication": {
    "type": "manual",
    "displayName": "Notion Integration Token",
    "instructions": "Create a new internal integration and copy the 'Internal Integration Secret'.",
    "helpUrl": "https://www.notion.so/my-integrations",
    "validation": "^secret_[a-zA-Z0-9]{43}$"
  }
}
```

Fields: `displayName` (label on the token page), `instructions` (how to obtain the token), `helpUrl` (link to the service's token page), `validation` (regex to check token format before saving).

## Injecting tokens into MCP servers

Once a user provides their token, MCP Front injects it into the MCP server process using the `$userToken` syntax. Add it to the server's `env`, `args`, `url`, or `headers` fields:

```json
"env": {
  "NOTION_TOKEN": { "$userToken": "{{token}}" }
}
```

The `{{token}}` placeholder is replaced at request time with the authenticated user's service token. You can embed it in a larger string — `{"$userToken": "Bearer {{token}}"}` adds a Bearer prefix.

### Token format

The `tokenFormat` field in `userAuthentication` transforms the raw token before injection. It defaults to `"{{token}}"` (pass through unchanged). MCP Front replaces `{{token}}` in `tokenFormat` with the raw user token, and the result becomes the value used wherever `$userToken` appears. This is useful when the raw token needs wrapping — for example, `"tokenFormat": "token={{token}}"` would turn a raw token `abc123` into `token=abc123`.

## Token storage

User tokens are encrypted at rest using AES-256-GCM with the `encryptionKey` from your auth settings. When using Firestore storage, all tokens are encrypted before being written to the database.

## Token management

Users can manage their service connections at `/my/tokens`. This page lets them connect or disconnect OAuth services, add or update manual tokens, and delete tokens they no longer need.
