# mcp-front <img src="docs-site/src/assets/logo.svg" alt="MCP Front" width="32" height="32" style="vertical-align: middle;">

![Docker image with tag latest](https://img.shields.io/docker/image-size/dgellow/mcp-front/latest?style=flat&logo=docker&label=latest)
![Docker image with tag docker-client-latest](https://img.shields.io/docker/image-size/dgellow/mcp-front/docker-client-latest?style=flat&logo=docker&label=docker-client-latest)

> [!WARNING]
> **This project is a work in progress and should not be considered production ready.**
> 
> Though I'm fairly confident the overall architecture is sound, and I myself rely on the implementation — so it _should work :tm:_.
> But definitely alpha software.
>
> **Expect breaking changes! :)**
>
> Also, don't rely too much on the docs, they drift fairly quickly, I do not always keep them updated when doing changes or adding/removing features. They are mostly here to anchor me and help me stay focus on my initial vision.

> [!TIP]
> Looking for the easiest way to get an MCP server for your API? Check out [Stainless](https://www.stainless.com/mcp?utm=mcp-front-readme)✨. We offer best-in-class SDK and MCP generation. Build a complete MCP server and [publish it to Cloudflare and Docker Hub](https://www.stainless.com/docs/guides/generate-mcp-server-from-openapi?utm=mcp-front-readme) in a few minutes!
>
> <sub>Disclaimer: the author of mcp-front is an early Stainless employee</sub>


OAuth 2.1 proxy for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/introduction) servers. Authenticate once with Google, access all your MCP tools in [Claude.ai](https://claude.ai).

<div align="center">

![mcp-front Architecture](docs/architecture.svg)

</div>

## What is mcp-front?

mcp-front is an authentication proxy that sits between Claude.ai and your MCP servers. It provides:

- **Single sign-on** via Google OAuth for all MCP tools
- **Domain validation** to restrict access to your organization
- **Per-user authentication** for services like Notion and Stainless (via OAuth or manual tokens)
- **Session isolation** so multiple users can share infrastructure

## Why use mcp-front?

Without mcp-front, each MCP server needs its own authentication, which isn't trivial — or needs to be public.

With mcp-front:

- Users authenticate once with their Google account
- Access is restricted to your company domain
- MCP servers can run in secure environments (databases, internal APIs)
- Sessions are isolated between users
- You get a simple, unified setup to run pretty much any MCP server found on [Docker Hub](https://hub.docker.com/mcp)

## How it works

1. Claude.ai connects to `https://your-domain.com/<service>/sse`
2. mcp-front validates the user's OAuth token
3. If a service requires user authentication, `mcp-front` will guide the user through a one-time setup (via an OAuth consent screen or a manual token entry page).
4. Proxies requests to the configured MCP server
5. For stdio servers, each user gets an isolated process

## Quick start

1. Create `config.json`:

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "baseURL": "https://mcp.yourcompany.com",
    "addr": ":8080",
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.yourcompany.com",
      "allowedDomains": ["yourcompany.com"],
      "allowedOrigins": ["https://claude.ai"],
      "tokenTtl": "1h",
      "storage": "memory",
      "googleClientId": { "$env": "GOOGLE_CLIENT_ID" },
      "googleClientSecret": { "$env": "GOOGLE_CLIENT_SECRET" },
      "googleRedirectUri": "https://mcp.yourcompany.com/oauth/callback",
      "jwtSecret": { "$env": "JWT_SECRET" },
      "encryptionKey": { "$env": "ENCRYPTION_KEY" }
    }
  },
  "mcpServers": {
    "postgres": {
      "transportType": "stdio",
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "mcp/postgres:latest",
        { "$env": "DATABASE_URL" }
      ]
    }
  }
}
```

2. Set environment variables:

```bash
export GOOGLE_CLIENT_ID="your-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-oauth-client-secret"
export JWT_SECRET="your-32-byte-jwt-secret-for-oauth!"
export ENCRYPTION_KEY="your-32-byte-encryption-key-here!"
export DATABASE_URL="postgresql://user:pass@host:5432/db"
```

3. Run mcp-front:

```bash
docker run -d -p 8080:8080 \
  -e GOOGLE_CLIENT_ID -e GOOGLE_CLIENT_SECRET \
  -e JWT_SECRET -e ENCRYPTION_KEY -e DATABASE_URL \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/config.json:/app/config.json \
  dgellow/mcp-front:docker-client-latest
```

4. Add to Claude.ai: `https://mcp.yourcompany.com/postgres/sse`

## Endpoints

### MCP endpoints

- `/<service>/sse` - Server-sent events for MCP communication
- `/<service>/message` - Message handling for MCP requests

### User endpoints

- `/my/tokens` - Browser-based token management for per-user MCP server tokens

### OAuth endpoints

- `/.well-known/oauth-authorization-server` - OAuth discovery
- `/authorize` - OAuth authorization
- `/token` - Token exchange
- `/oauth/callback` - Google OAuth callback
- `/register` - Dynamic client registration

## Configuration

### Google OAuth setup

1. Create OAuth client in [Google Cloud Console](https://console.cloud.google.com/)
2. Set redirect URI: `https://your-domain.com/oauth/callback`
3. Save Client ID and Secret

### Environment variable formats

mcp-front uses explicit JSON syntax `{"$env": "VAR_NAME"}` for environment variables throughout its configuration. This deliberate choice eliminates the ambiguity and risks inherent in shell-style variable substitution. When configs pass through multiple layers of tooling and scripts, traditional `$VAR` syntax can expand unexpectedly, causing security issues and debugging nightmares. The JSON format ensures your configuration remains exactly as written until mcp-front processes it, providing predictable behavior across all deployment environments. For per-user authentication, `{"$userToken": "{{token}}"}` follows the same principle, keeping user credentials cleanly separated from system configuration.

## Service Authentication (Per-User Tokens)

Some MCP servers, like Notion or Stainless, require each user to provide their own individual API key or grant access via OAuth. `mcp-front` automates this process.

When a service is configured with `requiresUserToken: true`, `mcp-front` will guide the user through a one-time setup for that service after their initial Google login. This is handled in one of two ways, depending on the service's configuration.

### Manual Token Entry

For services that require a manually generated API key, you can configure `mcp-front` to prompt the user for it on a secure web page.

**Configuration:**
```json
{
  "notion": {
    "transportType": "stdio",
    "requiresUserToken": true,
    "userAuthentication": {
      "type": "manual",
      "displayName": "Notion Integration Token",
      "instructions": "Create an integration and copy the token",
      "helpUrl": "https://www.notion.so/my-integrations"
    },
    "command": "docker",
    "args": ["run", "--rm", "-i", "-e", "OPENAPI_MCP_HEADERS", "mcp/notion:latest"],
    "env": {
      "OPENAPI_MCP_HEADERS": {
        "$userToken": "{\"Authorization\": \"Bearer {{token}}\"}"
      }
    }
  }
}
```
After authenticating, the user will be directed to the `/my/tokens` page to enter their token.

### Service OAuth Flow

For services that support OAuth, `mcp-front` can handle the entire flow automatically. After the user logs in with Google, they will be shown an interstitial page where they can connect to each service.

**Configuration:**
```json
{
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
}
```
This provides a seamless experience for the user and enables automatic token refreshes.

### Full configuration example

See [config-oauth.json](config-oauth.json) for a complete example with multiple MCP servers.

## Security

- OAuth 2.1 with PKCE required for all flows
- Google Workspace domain validation
- Encrypted session cookies (AES-256-GCM)
- Per-user session isolation for stdio servers

⚠️ **Note**: mcp-front handles authentication only. Each MCP server is responsible for its own input validation and
security. Only use MCP servers that you trust and be careful when providing them with sensitive data.

## Storage options

- **Memory** (default): Fast, data lost on restart
- **Firestore**: Persistent storage for production

For Firestore, add to your auth config:

```json
"storage": "firestore",
"gcpProject": {"$env": "GCP_PROJECT"},
"firestoreDatabase": "(default)",
"firestoreCollection": "mcp_front_oauth_clients"
```

## Development

```bash
# Run tests
cd integration && go test -v

# Development mode (relaxed OAuth validation)
export MCP_FRONT_ENV=development
```

## License

Copyright 2025 Samuel "dgellow" El-Borai.
All rights reserved.
