---
title: Configuration
description: Config file reference
---

## Configuration basics

MCP Front uses a single JSON config file. The structure is straightforward: proxy settings at the top, MCP servers at the bottom.

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "name": "My MCP Proxy",
    "baseURL": "https://mcp.company.com",
    "addr": ":8080",
    "auth": {
      /* auth config */
    }
  },
  "mcpServers": {
    /* server configs */
  }
}
```

The `version` is currently "v0.0.1-DEV_EDITION_EXPECT_CHANGES" - this signals the config format may change. The `name` shows up in logs. The `addr` is where MCP Front listens, typically ":8080" for port 8080 on all interfaces.

For OAuth, you need `baseURL` (note the camelCase) set to your public URL so Google can redirect back after login. For bearer tokens, you can skip it.

The `auth` section defines how users authenticate. The `mcpServers` section lists all the MCP servers you want to proxy.

## Authentication configuration

You have two options: bearer tokens or OAuth. Choose based on your security needs.

### Bearer tokens

Map MCP server names to lists of valid tokens. The client's token must be in that server's list.

```json
{
  "auth": {
    "kind": "bearerToken",
    "tokens": {
      "filesystem": ["dev-token-123", "prod-token-456"],
      "database": [{ "$env": "DB_TOKEN" }]
    }
  }
}
```

Each key matches an MCP server name from your `mcpServers` section. The value is an array of valid tokens. You can mix hardcoded strings and environment variables using `{"$env": "VAR_NAME"}`.

### OAuth 2.1

For production, use OAuth with Google. Claude redirects users to Google for authentication, and MCP Front validates their domain. All sensitive fields must use environment variables for security.

```json
{
  "auth": {
    "kind": "oauth",
    "issuer": "https://mcp.company.com",
    "allowedDomains": ["company.com"],
    "allowedOrigins": ["https://claude.ai"],
    "tokenTtl": "24h",
    "storage": "memory",
    "googleClientId": { "$env": "GOOGLE_CLIENT_ID" },
    "googleClientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
    "googleRedirectUri": "https://mcp.company.com/oauth/callback",
    "jwtSecret": { "$env": "JWT_SECRET" },
    "encryptionKey": { "$env": "ENCRYPTION_KEY" }
  }
}
```

The `issuer` should match your `baseURL`. `allowedDomains` restricts access to specific email domains. `allowedOrigins` controls which websites can make requests.

`tokenTtl` controls how long JWT tokens are valid. Shorter times are more secure but require more frequent logins.

Security requirements: `googleClientSecret`, `jwtSecret`, and `encryptionKey` must be environment variables. The JWT secret must be at least 32 bytes. The encryption key must be exactly 32 bytes.

For production, set `storage` to "firestore" and add `gcpProject`, `firestoreDatabase`, and `firestoreCollection` fields.

### Storage architecture

![Storage Architecture](/mcp-front/storage-architecture.svg)

MCP Front supports two storage backends:

- **Memory**: Development only, data lost on restart
- **Firestore**: Production, with encrypted secrets and persistent sessions

## MCP server configuration

All MCP servers need a `transportType` field. MCP Front supports four transport types for different use cases.

### SSE servers (existing HTTP services)

For MCP servers that already expose a Server-Sent Events endpoint:

```json
{
  "mcpServers": {
    "database": {
      "transportType": "sse",
      "url": "http://postgres-mcp:3000/sse",
      "options": {
        "authTokens": ["dev", "prod"]
      }
    }
  }
}
```

### Stdio servers (spawn processes)

Start MCP servers as subprocesses. Each user gets their own process. Isolation depends on your sandboxing setup:

```json
{
  "mcpServers": {
    "filesystem": {
      "transportType": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": {
        "DEBUG": "1"
      }
    }
  }
}
```

MCP Front just spawns processes directly. For actual isolation, use containers, systemd sandboxing, or similar tools.

### Streamable HTTP servers

For MCP servers that use HTTP with streaming responses:

```json
{
  "mcpServers": {
    "api-tools": {
      "transportType": "streamable-http",
      "url": "http://api-mcp:8080",
      "options": {
        "timeout": "30s"
      }
    }
  }
}
```

### Inline servers

For simple servers defined directly in the config (advanced use case):

```json
{
  "mcpServers": {
    "simple": {
      "transportType": "inline",
      "options": {
        "handler": "builtin-echo"
      }
    }
  }
}
```

### Server options

Additional configuration via `options` field.

#### Per-User Authentication

Services like Notion or Linear need individual user auth. Set `requiresUserToken: true` and add `userAuthentication` object.

##### Type: `manual`

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

Users enter tokens at `/my/tokens`.

##### Type: `oauth`

Services with OAuth 2.0 support. Handles flow and token refresh.

```json
"stainless": {
  "transportType": "stdio",
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

#### Other Options

You can also configure other options like `timeout`, `headers` for proxied requests, and `authTokens` for server-level bearer token validation (distinct from the main `proxy.auth` block).

```json
{
  "database": {
    "transportType": "sse",
    "url": "http://postgres-mcp:3000/sse",
    "options": {
      "authTokens": ["server-specific-token"],
      "timeout": "30s",
      "headers": {
        "X-API-Key": { "$env": "DB_API_KEY" }
      }
    }
  }
}
```

### Routing to servers

Claude can connect to specific servers using URL paths. For example, `GET /database/sse` connects to the "database" server, while `GET /filesystem/sse` connects to "filesystem".

## Environment variables

Any string value in the config can reference environment variables using `{"$env": "VAR_NAME"}`. This keeps secrets out of your config files.

```json
{
  "proxy": {
    "baseUrl": { "$env": "BASE_URL" },
    "auth": {
      "tokens": {
        "prod": { "$env": "PROD_TOKEN" }
      },
      "gcpProject": { "$env": "GOOGLE_CLOUD_PROJECT" }
    }
  },
  "mcpServers": {
    "database": {
      "url": { "$env": "DATABASE_URL" }
    }
  }
}
```

### OAuth requirements

OAuth needs these environment variables:

```bash
GOOGLE_CLIENT_ID=your-client-id
GOOGLE_CLIENT_SECRET=your-secret
JWT_SECRET=your-32-byte-jwt-secret-for-oauth!  # Must be 32+ bytes
ENCRYPTION_KEY=your-32-byte-encryption-key-here!  # Must be exactly 32 bytes
```

### Runtime options

Control MCP Front behavior with these optional variables:

```bash
MCP_FRONT_ENV=development  # Relaxes OAuth validation for local dev
LOG_LEVEL=debug           # Options: debug, info, warn, error
LOG_FORMAT=json          # Options: json (structured) or text (human-readable)
```

Set `MCP_FRONT_ENV=development` when testing OAuth locally. It allows http:// URLs and reduces security requirements.

## Complete examples

### Development with bearer tokens

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "name": "Dev Proxy",
    "addr": ":8080",
    "auth": {
      "kind": "bearerToken",
      "tokens": {
        "filesystem": ["dev-token-123"]
      }
    }
  },
  "mcpServers": {
    "filesystem": {
      "transportType": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
```

### Production with OAuth

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
      "allowedDomains": ["company.com"],
      "allowedOrigins": ["https://claude.ai"],
      "tokenTtl": "4h",
      "storage": "firestore",
      "googleClientId": { "$env": "GOOGLE_CLIENT_ID" },
      "googleClientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
      "googleRedirectUri": "https://mcp.company.com/oauth/callback",
      "jwtSecret": { "$env": "JWT_SECRET" },
      "encryptionKey": { "$env": "ENCRYPTION_KEY" },
      "gcpProject": { "$env": "GOOGLE_CLOUD_PROJECT" },
      "firestoreDatabase": "(default)",
      "firestoreCollection": "mcp_front_oauth_clients"
    }
  },
  "mcpServers": {
    "database": {
      "transportType": "sse",
      "url": { "$env": "DATABASE_MCP_URL" }
    },
    "analytics": {
      "transportType": "sse",
      "url": { "$env": "ANALYTICS_MCP_URL" }
    }
  }
}
```
