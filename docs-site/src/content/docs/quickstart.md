---
title: Quickstart
description: Get MCP Front running in 5 minutes
---

This guide uses bearer token authentication for simplicity. For production deployments with OAuth, see the [Identity Providers](/mcp-front/identity-providers/) guide.

## 1. Create a config file

Create `config.json`:

```json
{
  "version": "v0.0.1-DEV_EDITION_EXPECT_CHANGES",
  "proxy": {
    "baseURL": "http://localhost:8080",
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

The server name `filesystem` determines the URL path: `/filesystem/sse`.

## 2. Run MCP Front

### Option A: Install with Go

```bash
go install github.com/dgellow/mcp-front/cmd/mcp-front@main
mcp-front -config config.json
```

### Option B: Docker

```bash
docker run -p 8080:8080 \
  -v $(pwd)/config.json:/app/config.json \
  docker.io/dgellow/mcp-front:latest
```

### Option C: Build from source

```bash
git clone https://github.com/stainless-api/mcp-front
cd mcp-front
go build -o mcp-front ./cmd/mcp-front
./mcp-front -config config.json
```

## 3. Connect from Claude

In Claude.ai, go to Settings and add a new MCP server. Set the URL to `http://localhost:8080/filesystem/sse`, auth type to Bearer Token, and token to `dev-token-123`.

## 4. Test it

Ask Claude: "What MCP tools do you have available?"

You should see the filesystem tools from your MCP server.

## What's next?

Switch to [OAuth authentication](/mcp-front/identity-providers/) for production. [Add more MCP servers](/mcp-front/server-types/) to your config. Or, configure services that require per-user authentication by following the [Service Authentication](/mcp-front/service-authentication/) guide.

## Troubleshooting

### Connection refused

```bash
curl http://localhost:8080/health
```

Should return `{"status":"ok"}`. If not, verify the process is running and port 8080 isn't already in use.

### Authentication failed

The token in Claude must match one of the tokens in the `serviceAuths` array for that server. Double-check the token string is identical — no extra whitespace or encoding differences. Check logs for details (`docker logs <container-id>` for Docker, or stdout for the binary).

### No tools available

This usually means MCP Front can't start the MCP server process. Test the server directly:

```bash
npx -y @modelcontextprotocol/server-filesystem /tmp
```

If that fails, the server itself has a problem. If it works, check MCP Front logs for errors — the command might not be in PATH inside the container.
