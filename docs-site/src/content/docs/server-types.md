---
title: Server Types
description: Transport types and aggregate servers
---

MCP Front supports four transport types plus an aggregate type that combines multiple backends into a single endpoint.

## Stdio servers

Stdio servers spawn an isolated subprocess per user. MCP Front communicates with the process over stdin/stdout using MCP's JSON-RPC protocol.

```json
{
  "mcpServers": {
    "filesystem": {
      "transportType": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

The `command` must be in the system PATH. Both `args` and `env` support `{"$env": "VAR"}` for host environment variables and `{"$userToken": "...{{token}}..."}` for per-user token injection.

```json
{
  "postgres": {
    "transportType": "stdio",
    "command": "docker",
    "args": ["run", "--rm", "-i", "-e", "DATABASE_URL", "my-mcp-server"],
    "env": {
      "DATABASE_URL": { "$env": "DATABASE_URL" },
      "API_KEY": { "$userToken": "{{token}}" }
    }
  }
}
```

MCP Front spawns processes directly — for sandboxing, use containers or systemd isolation.

## SSE servers

For MCP servers that expose a Server-Sent Events endpoint. MCP Front connects to the backend and proxies bidirectional messages.

```json
{
  "mcpServers": {
    "database": {
      "transportType": "sse",
      "url": "http://postgres-mcp:3000/sse",
      "headers": {
        "X-API-Key": { "$env": "DB_API_KEY" }
      },
      "timeout": "30s"
    }
  }
}
```

Headers and URL support `{"$env": "VAR"}` and `{"$userToken": "...{{token}}..."}` syntax.

## Streamable HTTP servers

For MCP servers using HTTP with streaming responses. Configuration is identical to SSE.

```json
{
  "mcpServers": {
    "api-tools": {
      "transportType": "streamable-http",
      "url": "http://api-mcp:8080/mcp",
      "timeout": "60s"
    }
  }
}
```

## Inline servers

Inline servers define tools directly in the config file. Each tool runs a command when invoked — useful for wrapping CLI tools or scripts without building a full MCP server.

```json
{
  "mcpServers": {
    "gcloud": {
      "transportType": "inline",
      "inline": {
        "description": "Google Cloud Platform tools",
        "tools": [
          {
            "name": "list_instances",
            "description": "List all GCE instances in the project",
            "inputSchema": {
              "type": "object",
              "properties": {},
              "required": []
            },
            "command": "gcloud",
            "args": ["compute", "instances", "list", "--format=json"],
            "env": {
              "CLOUDSDK_CORE_PROJECT": { "$env": "GCP_PROJECT_ID" }
            },
            "timeout": "30s"
          }
        ]
      }
    }
  }
}
```

Each tool needs a `name`, `description`, `inputSchema` (JSON Schema), and a `command`. The `args`, `env`, and `timeout` fields are optional and support `{"$env": "VAR"}` syntax.

Inline servers cannot be referenced by aggregate servers.

## Aggregate servers

Aggregate servers combine tools from multiple backends into a single endpoint. Instead of connecting to each backend separately, expose one aggregate endpoint that presents all tools.

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
      "servers": ["postgres", "linear"]
    }
  }
}
```

Connect to `/all/sse` to see tools from both backends. Tools are namespaced as `serverName.toolName` — a tool called `query` from postgres becomes `postgres.query`.

### Default behavior

If `servers` is omitted, the aggregate includes all non-aggregate, non-inline servers in the config.

```json
{
  "mcpServers": {
    "postgres": { "transportType": "sse", "url": "..." },
    "linear": { "transportType": "stdio", "command": "..." },
    "all": { "type": "aggregate" }
  }
}
```

### Discovery configuration

Configure discovery behavior with the `discovery` field.

```json
{
  "all": {
    "type": "aggregate",
    "discovery": {
      "timeout": "10s",
      "cacheTtl": "5m",
      "maxConnsPerUser": 10
    }
  }
}
```

`timeout` is how long to wait for a backend during tool discovery (default: 10s). `cacheTtl` is how long discovered tools are cached (default: 60s). `maxConnsPerUser` limits concurrent backend connections per user (default: 0, unlimited).

### Transport type

Aggregate servers default to SSE. Set `"transportType": "streamable-http"` if your client prefers that protocol.

### Constraints

Aggregates cannot reference themselves, other aggregates, or inline servers.

## Service authentication

All server types support `serviceAuths` for connection authentication and `requiresUserToken` for per-user token injection. See [Configuration](/mcp-front/configuration/) and [Service Authentication](/mcp-front/service-authentication/).

## Tool filtering

Any server type supports filtering which tools are exposed to clients. See [Configuration](/mcp-front/configuration/#optionstoolfilter) for details and examples.
