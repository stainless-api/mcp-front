---
title: Identity Providers
description: Setting up OAuth with Google, Azure AD, GitHub, or any OIDC provider
---

MCP Front supports four identity providers. All work the same from the client's perspective — they differ only in setup and access control.

Every provider requires `clientId`, `clientSecret`, and `redirectUri`. The redirect URI must be `https://your-domain.com/oauth/callback` (or `http://localhost:8080/oauth/callback` for local development).

Access control requires at least one of `allowedDomains` or `idp.allowedOrgs`. When both are set, both must pass — the user's email domain must match AND they must belong to an allowed organization.

## Google

Best for teams using Google Workspace. Access control is based on email domain.

```json
{
  "idp": {
    "provider": "google",
    "clientId": { "$env": "GOOGLE_CLIENT_ID" },
    "clientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
    "redirectUri": "https://mcp.company.com/oauth/callback"
  },
  "allowedDomains": ["company.com"]
}
```

### Google Cloud Console setup

Go to the [Google Cloud Console](https://console.cloud.google.com) and create a new OAuth 2.0 Client ID. Set the application type to "Web application." Add `https://mcp.company.com/oauth/callback` as an authorized redirect URI (and `http://localhost:8080/oauth/callback` if you want to test locally).

For the OAuth consent screen, choose "Internal" if you have Google Workspace — this restricts the app to your organization automatically. Add scopes: `email`, `profile`, `openid`. If you choose "External," the `allowedDomains` setting in MCP Front handles domain restriction.

## Azure AD

Best for teams using Microsoft Entra ID (formerly Azure AD). Requires a `tenantId` to scope authentication to your tenant.

```json
{
  "idp": {
    "provider": "azure",
    "clientId": { "$env": "AZURE_CLIENT_ID" },
    "clientSecret": { "$env": "AZURE_CLIENT_SECRET" },
    "redirectUri": "https://mcp.company.com/oauth/callback",
    "tenantId": { "$env": "AZURE_TENANT_ID" }
  },
  "allowedDomains": ["company.com"]
}
```

### Azure portal setup

In the Azure portal, go to App registrations and create a new registration. Set the redirect URI to `https://mcp.company.com/oauth/callback` with platform "Web." Under Certificates & secrets, create a new client secret and save it as your `AZURE_CLIENT_SECRET`. The tenant ID is on the Overview page.

## GitHub

Best for teams organized around GitHub organizations. Access control uses organization membership via `idp.allowedOrgs` instead of (or in addition to) email domains.

```json
{
  "idp": {
    "provider": "github",
    "clientId": { "$env": "GITHUB_CLIENT_ID" },
    "clientSecret": { "$env": "GITHUB_CLIENT_SECRET" },
    "redirectUri": "https://mcp.company.com/oauth/callback",
    "allowedOrgs": ["my-github-org"]
  }
}
```

MCP Front requests `user:email` and `read:org` scopes from GitHub (hardcoded, not configurable). It fetches the user's verified email and organization list, then checks membership against your `allowedOrgs`.

### GitHub OAuth app setup

Go to your GitHub organization's Settings, then Developer settings, then OAuth Apps. Create a new OAuth App with the authorization callback URL set to `https://mcp.company.com/oauth/callback`. Note the client ID and generate a client secret.

## Generic OIDC

For any OIDC-compliant provider — Okta, Auth0, Keycloak, and others. Provide either a discovery URL (recommended) or manual endpoint configuration.

### With discovery URL

```json
{
  "idp": {
    "provider": "oidc",
    "clientId": { "$env": "OIDC_CLIENT_ID" },
    "clientSecret": { "$env": "OIDC_CLIENT_SECRET" },
    "redirectUri": "https://mcp.company.com/oauth/callback",
    "discoveryUrl": "https://your-idp.com/.well-known/openid-configuration"
  },
  "allowedDomains": ["company.com"]
}
```

### With manual endpoints

If your provider doesn't support OIDC discovery, configure the endpoints directly.

```json
{
  "idp": {
    "provider": "oidc",
    "clientId": { "$env": "OIDC_CLIENT_ID" },
    "clientSecret": { "$env": "OIDC_CLIENT_SECRET" },
    "redirectUri": "https://mcp.company.com/oauth/callback",
    "authorizationUrl": "https://your-idp.com/authorize",
    "tokenUrl": "https://your-idp.com/token",
    "userInfoUrl": "https://your-idp.com/userinfo"
  },
  "allowedDomains": ["company.com"]
}
```

### Custom scopes

The OIDC provider defaults to `openid email profile`. Override with `scopes` if your provider requires different ones.

```json
{
  "idp": {
    "provider": "oidc",
    "scopes": ["openid", "email", "profile", "groups"]
  }
}
```

Google, Azure, and GitHub use hardcoded scopes appropriate for each provider. The `scopes` field only applies to the generic OIDC provider.

## Environment variables

Set these for your chosen provider.

```bash
# JWT and encryption (required for all providers)
JWT_SECRET=$(openssl rand -base64 32)            # At least 32 bytes (this produces 44)
ENCRYPTION_KEY=$(openssl rand -base64 24)        # Exactly 32 bytes (required for Firestore)

# Google
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-secret

# Azure
AZURE_CLIENT_ID=your-azure-app-id
AZURE_CLIENT_SECRET=your-azure-secret
AZURE_TENANT_ID=your-tenant-id

# GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Generic OIDC
OIDC_CLIENT_ID=your-oidc-client-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
```

## Production requirements

For production deployments, you'll need Firestore for persistent storage, HTTPS, and appropriate token expiration settings. See the [Configuration](/mcp-front/configuration/) reference for Firestore setup, HTTPS requirements, and token TTL options.

## Troubleshooting

**"Redirect URI mismatch"** — the callback URL in your provider's console must match the `redirectUri` in your config exactly, including port and path (`/oauth/callback`).

**"Domain not allowed"** — the user's email domain isn't in `allowedDomains`. For GitHub, check that `allowedOrgs` includes an organization the user belongs to.

**"JWT secret too short"** — the JWT secret must be at least 32 bytes. Generate one with `openssl rand -base64 32`.

**"Encryption key wrong length"** — the encryption key must be exactly 32 bytes. Generate one with `openssl rand -base64 24` (base64-encoding 24 bytes produces exactly 32 bytes).
