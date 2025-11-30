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


An authentication gateway for [MCP (Model Context Protocol)](https://modelcontextprotocol.io/introduction) servers. Let your team use Claude with internal databases, APIs, and tools without exposing them to the internet.

<div align="center">

![mcp-front Architecture](docs/architecture.svg)

</div>

## The problem

You want your team to use Claude with internal MCP servers (databases, Linear, Notion, internal APIs). But MCP servers don't have built-in multi-user authentication. You either expose them to the public internet, build authentication yourself, or run separate instances per user. None of these are great.

## The solution

mcp-front sits between Claude and your MCP servers as an authentication gateway. Your team authenticates with Google once. When Claude connects, mcp-front validates the OAuth token, checks the user is from your organization, and proxies to the actual MCP server in your secure environment.

For stdio servers, each user gets an isolated subprocess. For services that need individual API keys (Notion, Linear), users connect them once through a web UI and mcp-front injects tokens automatically.

Organization-wide access control with per-user isolation. No modifications to your MCP servers. Nothing exposed to the internet.

## How it works

1. User adds `https://your-domain.com/<service>/sse` to Claude
2. Claude redirects to Google for login (first time only)
3. mcp-front validates the user is from your organization
4. If the service needs a user API key (Notion, Linear), user connects it through a web page
5. mcp-front proxies all MCP requests to the backend server

Each stdio server gets its own isolated subprocess per user. OAuth tokens are scoped to specific services (RFC 8707) — a token for your Postgres server won't work for Linear.

## Try it locally (5 minutes)

Test with bearer tokens before setting up OAuth:

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "addr": ":8080"
  },
  "mcpServers": {
    "filesystem": {
      "transportType": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "serviceAuths": [
        {
          "type": "bearer",
          "tokens": ["dev-token-123"]
        }
      ]
    }
  }
}
```

```bash
# Run it
docker run -p 8080:8080 -v $(pwd)/config.json:/app/config.json dgellow/mcp-front:latest

# In Claude.ai settings, add this MCP server:
# URL: http://localhost:8080/filesystem/sse
# Auth: Bearer Token
# Token: dev-token-123
```

## Production setup

For organization-wide deployment with OAuth, domain restrictions, and Firestore persistence:

**[→ Full production setup guide](https://stainless-api.github.io/mcp-front/examples/oauth-google/)**

The guide covers:
- Setting up Google OAuth (Cloud Console configuration)
- Environment variables and secret management
- Domain validation and CORS
- Firestore storage for production
- HTTPS deployment considerations
- Per-user service authentication (Notion, Linear, etc.)

## Configuration

mcp-front supports multiple transport types (stdio, SSE, streamable-http, inline). Authentication happens at three levels: user-to-proxy (OAuth), proxy-to-server (`serviceAuths`), and per-user service tokens (`userAuthentication`).

Example configs: [config-oauth.json](config-oauth.json) | [config-token.example.json](config-token.example.json)

See the [configuration reference](https://stainless-api.github.io/mcp-front/configuration/) for all options.

## Security

- OAuth 2.0 with PKCE required for all flows
- Google Workspace domain validation
- Encrypted session cookies (AES-256-GCM)
- Per-user session isolation for stdio servers
- Per-service audience claims (RFC 8707) prevent token reuse across services

⚠️ **Security boundary**: mcp-front handles authentication. MCP servers handle authorization and input validation. Only use MCP servers you trust with your data.

## Documentation

- **[Quickstart](https://stainless-api.github.io/mcp-front/quickstart/)** - Get running in 5 minutes with bearer tokens
- **[Production setup](https://stainless-api.github.io/mcp-front/examples/oauth-google/)** - OAuth with Google Workspace
- **[Configuration reference](https://stainless-api.github.io/mcp-front/configuration/)** - All config options
- **[API reference](https://stainless-api.github.io/mcp-front/api-reference/)** - HTTP endpoints
- **[Architecture](https://stainless-api.github.io/mcp-front/architecture/)** - How it works under the hood

## License

Licensed under the [Elastic License 2.0](LICENSE) with commercial exceptions for Stainless Software Ltd and the author. Using mcp-front as infrastructure for your own services (including public/commercial) is permitted; offering mcp-front itself as a hosted product is not.

Copyright 2025 Samuel "dgellow" El-Borai (sam@elborai.me)
