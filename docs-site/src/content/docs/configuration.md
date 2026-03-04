---
title: Configuration
description: Config file reference
---

## Config file structure

MCP Front uses a single JSON config file.

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "baseURL": "https://mcp.company.com",
    "addr": ":8080",
    "auth": { ... }
  },
  "mcpServers": { ... }
}
```

The version string signals the config format may change in future releases.

## CLI flags

```
mcp-front -config config.json         # Run with config file (required)
mcp-front -config-init config.json    # Generate a default config file
mcp-front -config config.json -validate  # Validate config and exit
mcp-front -version                    # Print version
mcp-front -help                       # Print usage
```

The `-validate` flag checks your config for errors without starting the server. It validates structure, field types, and references without requiring environment variables to be set.

## Environment variable references

Any string value in the config can reference environment variables using `{"$env": "VAR_NAME"}`. This keeps secrets out of your config files. Values are resolved at config load time.

```json
{
  "jwtSecret": { "$env": "JWT_SECRET" },
  "url": { "$env": "DATABASE_MCP_URL" }
}
```

This syntax prevents accidental shell expansion when configs pass through scripts or CI/CD pipelines.

## User token references

For MCP servers that need per-user tokens injected at request time, use the `{"$userToken": "...{{token}}..."}` syntax. The `{{token}}` placeholder is replaced with the authenticated user's service token when a request is made.

```json
{
  "env": {
    "API_KEY": { "$userToken": "{{token}}" },
    "AUTH_HEADER": { "$userToken": "Bearer {{token}}" }
  }
}
```

This works in `env`, `args`, `url`, and `headers` fields on MCP servers. See [Service Authentication](/mcp-front/service-authentication/) for how users provide these tokens.

## Proxy configuration

### `proxy.baseURL`

Your public URL. Required. Must be HTTPS in production.

### `proxy.addr`

Listen address, typically `":8080"` for port 8080 on all interfaces.

### `proxy.name`

Used as the MCP server implementation name. Optional.

### `proxy.sessions`

Session management configuration. All fields are optional.

```json
{
  "proxy": {
    "sessions": {
      "timeout": "24h",
      "cleanupInterval": "15m",
      "maxPerUser": 5
    }
  }
}
```

`timeout` controls how long sessions last (default: `"5m"`). `cleanupInterval` is how often expired sessions are garbage collected (default: `"1m"`). `maxPerUser` limits concurrent sessions per user (default: `10`, set to `0` for unlimited).

## Authentication

Configure OAuth under `proxy.auth`.

```json
{
  "auth": {
    "kind": "oauth",
    "issuer": "https://mcp.company.com",
    "idp": {
      "provider": "google",
      "clientId": { "$env": "GOOGLE_CLIENT_ID" },
      "clientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
      "redirectUri": "https://mcp.company.com/oauth/callback"
    },
    "allowedDomains": ["company.com"],
    "allowedOrigins": ["https://claude.ai"],
    "tokenTtl": "4h",
    "storage": "memory",
    "jwtSecret": { "$env": "JWT_SECRET" },
    "encryptionKey": { "$env": "ENCRYPTION_KEY" }
  }
}
```

### `auth.kind`

Must be `"oauth"`. This is the only supported authentication kind.

### `auth.issuer`

The OAuth issuer URI. Should match your `baseURL`.

### `auth.idp`

Identity provider configuration. MCP Front supports Google, Azure AD, GitHub, and generic OIDC providers. See [Identity Providers](/mcp-front/identity-providers/) for setup details.

### `auth.allowedDomains`

Restricts access to users with email addresses from these domains. At least one of `allowedDomains` or `idp.allowedOrgs` is required.

### `auth.allowedOrigins`

CORS origin whitelist. When empty, all origins are allowed. Set to `["https://claude.ai"]` to restrict to Claude, or add additional origins for other MCP clients.

### `auth.tokenTtl`

Access token lifetime as a Go duration string. Default: `"1h"`. Examples: `"4h"`, `"30m"`, `"24h"`.

### `auth.refreshTokenTtl`

Refresh token lifetime. Default: `"720h"` (30 days).

### `auth.refreshTokenScopes`

When set, refresh tokens are only issued if the authorization request includes at least one of these scopes. Default: empty (always issue refresh tokens).

### `auth.storage`

`"memory"` (default) for development — data lost on restart. `"firestore"` for production with persistent storage.

### `auth.jwtSecret`

Secret for signing JWT tokens. Must be at least 32 bytes. Must use `{"$env": "VAR"}` syntax.

### `auth.encryptionKey`

Secret for encrypting sensitive data at rest (AES-256-GCM). Must be exactly 32 bytes. Required when using OAuth authentication. Must use `{"$env": "VAR"}` syntax.

### Firestore configuration

When `storage` is `"firestore"`:

```json
{
  "auth": {
    "storage": "firestore",
    "gcpProject": { "$env": "GOOGLE_CLOUD_PROJECT" },
    "firestoreDatabase": "(default)",
    "firestoreCollection": "mcp_front_data"
  }
}
```

`gcpProject` is your GCP project ID (required for Firestore). `firestoreDatabase` defaults to `"(default)"`. `firestoreCollection` defaults to `"mcp_front_data"`.

### `auth.dangerouslyAcceptIssuerAudience`

When `true`, allows tokens with just the base issuer as audience to access any service. This is a workaround for MCP clients that don't implement RFC 8707 resource indicators, but it defeats per-service token isolation. Default: `false`. Only enable if you understand the security implications.

## MCP server configuration

Each server needs at least a `transportType`. See [Server Types](/mcp-front/server-types/) for transport-specific documentation.

```json
{
  "mcpServers": {
    "postgres": {
      "transportType": "stdio",
      "command": "docker",
      "args": ["run", "--rm", "-i", "my-postgres-mcp"],
      "env": {
        "DATABASE_URL": { "$env": "DATABASE_URL" }
      }
    },
    "linear": {
      "transportType": "sse",
      "url": "http://linear-mcp:3000/sse"
    }
  }
}
```

### Server names

Server names must start with an alphanumeric character and contain only alphanumeric characters, underscores, and hyphens. A server named `"postgres"` is accessible at `/postgres/sse`.

### `serviceAuths`

Per-server authentication validated on incoming requests before proxying. Useful for development or non-OAuth MCP clients.

**Bearer tokens:**

```json
{
  "serviceAuths": [
    {
      "type": "bearer",
      "tokens": ["dev-token-123", "dev-token-456"]
    }
  ]
}
```

**Basic authentication:**

```json
{
  "serviceAuths": [
    {
      "type": "basic",
      "username": "admin",
      "password": { "$env": "ADMIN_PASSWORD" }
    }
  ]
}
```

Tokens for one server don't work for another — each server's `serviceAuths` are independent.

### `requiresUserToken` and `userAuthentication`

When a backend service needs individual user tokens (Notion API keys, Linear OAuth tokens), set `requiresUserToken: true` and configure `userAuthentication`. See [Service Authentication](/mcp-front/service-authentication/) for details.

### `options.toolFilter`

Filter which tools are exposed to clients.

```json
{
  "options": {
    "toolFilter": {
      "mode": "allow",
      "list": ["safe_tool_1", "safe_tool_2"]
    }
  }
}
```

`mode` is `"allow"` (only expose listed tools) or `"block"` (hide listed tools).

### Aggregate servers

Set `type` to `"aggregate"` to combine tools from multiple backends into one endpoint. See [Server Types](/mcp-front/server-types/#aggregate-servers) for details.

```json
{
  "all": {
    "type": "aggregate",
    "servers": ["postgres", "linear"],
    "discovery": {
      "timeout": "10s",
      "cacheTtl": "5m",
      "maxConnsPerUser": 10
    }
  }
}
```

## Runtime environment variables

Optional variables that control runtime behavior:

```bash
MCP_FRONT_ENV=development  # Relaxes OAuth validation for local dev (allows HTTP)
LOG_LEVEL=debug            # Options: trace, debug, info, warn, error
LOG_FORMAT=json            # Options: json (structured) or text (human-readable)
```

## Complete examples

### Production with OAuth and Firestore

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "name": "Production Proxy",
    "baseURL": "https://mcp.company.com",
    "addr": ":8080",
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.company.com",
      "idp": {
        "provider": "google",
        "clientId": { "$env": "GOOGLE_CLIENT_ID" },
        "clientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
        "redirectUri": "https://mcp.company.com/oauth/callback"
      },
      "allowedDomains": ["company.com"],
      "allowedOrigins": ["https://claude.ai"],
      "tokenTtl": "4h",
      "storage": "firestore",
      "gcpProject": { "$env": "GOOGLE_CLOUD_PROJECT" },
      "firestoreDatabase": "(default)",
      "firestoreCollection": "mcp_front_data",
      "jwtSecret": { "$env": "JWT_SECRET" },
      "encryptionKey": { "$env": "ENCRYPTION_KEY" }
    }
  },
  "mcpServers": {
    "database": {
      "transportType": "sse",
      "url": { "$env": "DATABASE_MCP_URL" }
    },
    "notion": {
      "transportType": "stdio",
      "command": "notion-mcp",
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "manual",
        "displayName": "Notion Integration Token",
        "instructions": "Create a new internal integration and copy the secret.",
        "helpUrl": "https://www.notion.so/my-integrations",
        "validation": "^secret_[a-zA-Z0-9]{43}$"
      },
      "env": {
        "NOTION_TOKEN": { "$userToken": "{{token}}" }
      }
    }
  }
}
```

### Aggregate with multiple backends

This example adds an aggregate server to the production config. OAuth configuration is omitted for brevity — see the production example above.

```json
{
  "mcpServers": {
    "postgres": {
      "transportType": "sse",
      "url": "http://postgres-mcp:3000/sse"
    },
    "linear": {
      "transportType": "stdio",
      "command": "linear-mcp",
      "args": ["serve"]
    },
    "all": {
      "type": "aggregate",
      "discovery": {
        "cacheTtl": "5m"
      }
    }
  }
}
```

Claude connects to `/all/sse` and sees namespaced tools like `postgres.query` and `linear.create_issue`.
