---
title: Service Authentication Guide
description: Connecting services that require per-user authentication.
---

## Service Authentication

Notion, Linear, and Stainless need users to auth with their own accounts. mcp-front handles this after Google login via OAuth or manual token entry.

When users first access a service with `requiresUserToken: true`, they go through one-time setup.

## User Flow

User logs in with Google, sees an interstitial page listing services that need connection. They connect via OAuth (redirects to service, approves, returns) or manual token (enters key at `/my/tokens`). Click "Skip" or "Continue" to return to Claude. OAuth tokens refresh automatically, manual tokens persist until user updates them.

## Configuration

Set `requiresUserToken: true` and add `userAuthentication` object specifying the method.

### Type: `oauth`

Services with OAuth 2.0 support. Handles token exchange and refresh automatically.

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

Fields: `displayName` (shown to user), `clientId` and `clientSecret` (your OAuth app credentials), `authorizationUrl` and `tokenUrl` (service OAuth endpoints), `scopes` (permissions requested).

### Type: `manual`

User-generated API tokens.

```json
"notion": {
  "transportType": "stdio",
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

Fields: `displayName` (token page label), `instructions` (how to get token), `helpUrl` (link to docs), `validation` (regex for format check).

## Token Management

Visit `/my/tokens` to connect or disconnect OAuth services, or add and update manual tokens.
