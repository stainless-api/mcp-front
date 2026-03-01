# Aggregated MCP Endpoint

## Motivation

mcp-front was built as a transparent auth proxy — it sits in front of MCP servers, handles OAuth, and forwards connections. Each backend gets its own endpoint (`/postgres/`, `/linear/`, `/gong/`), its own OAuth token with per-service audience, and its own SSE connection from the client.

This design is correct from a security perspective (per-service token isolation, RFC 8707 compliance) but the main user feedback over the past ~6 months has been about the authentication experience: every service requires a separate login flow. When all your internal MCP servers share the same Google Workspace identity, authenticating 8 times to prove you're the same person is painful. When Claude drops your session, you re-authenticate 8 times again. When Codex spams warnings about unauthenticated MCPs at the start of every session, it's 8 warnings. The friction scales linearly with the number of services, and we keep adding services.

The MCP protocol doesn't have a concept of "these N servers share an identity provider, just auth once." Each MCP server is independent. There's no way to communicate this to the client.

The only reliable way to solve this is to stop exposing N separate MCP servers and instead expose one. Group all backends into a single MCP server, expose it as a single endpoint, and do the routing internally. One connection, one token, all tools.

This is a meaningful shift from the "transparent auth proxy" design toward mcp-front being an actual MCP server that happens to delegate to backends. The building blocks are already there — mcp-front already speaks the MCP protocol as a client to stdio backends, manages sessions, handles tool discovery, and injects user tokens. The aggregated endpoint composes these into a single surface.

## Configuration

Each server in `mcpServers` has a `type` field: `"direct"` (default) or `"aggregate"`. Direct servers proxy to a single backend. Aggregate servers combine multiple backends into one MCP endpoint. The aggregate type is opt-in — you only get it if you add it to your config.

Minimal config — aggregate all servers with defaults:

```json
{
  "mcpServers": {
    "postgres": { "transportType": "stdio", "command": "postgres-mcp" },
    "linear": { "transportType": "sse", "url": "http://localhost:9000/sse" },
    "all-tools": {
      "type": "aggregate"
    }
  }
}
```

The server name determines the path — `all-tools` gets mounted at `/all-tools/`, same as every other server.

Defaults:
- `servers`: all non-aggregate servers
- `discovery.timeout`: `"10s"` — return whatever tools have been collected after this deadline
- `discovery.cacheTTL`: `"60s"` — per-user tool cache lifetime

Fully configured:

```json
{
  "mcpServers": {
    "postgres": { "transportType": "stdio", "command": "postgres-mcp" },
    "linear": { "transportType": "sse", "url": "http://localhost:9000/sse" },
    "gong": { "transportType": "stdio", "command": "gong-mcp" },
    "dev-tools": {
      "type": "aggregate",
      "servers": ["postgres", "linear"],
      "discovery": {
        "timeout": "15s",
        "cacheTTL": "2m"
      },
      "options": {
        "toolFilter": {
          "mode": "block",
          "list": ["postgres.drop_table"]
        }
      },
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

Fields that don't apply to aggregates: `transportType`, `command`, `args`, `env`, `url`, `headers`, `timeout`, `requiresUserToken`, `userAuthentication`, `inline`. Validation rejects them if present on an aggregate.

Validation rejects self-references, references to other aggregate servers, references to nonexistent servers, and server names containing `.`.

## Design

### How it works

The aggregate server acts as an MCP server to the client and an MCP client to every backend it includes. The client connects once, sends `tools/list`, and gets back every tool from every backend. Tool names are prefixed with their service name (`postgres.query`, `linear.create_issue`) so routing is unambiguous. When the client calls `tools/call` with `postgres.query`, the aggregate strips the prefix, routes to the postgres backend, and returns the result.

### Connection lifecycle

1. Client opens SSE, receives a message endpoint URL
2. Client sends `initialize` — aggregate responds with MCP capabilities
3. Client sends `tools/list` — aggregate fans out to all backends in parallel, collects and namespaces tools, returns unified list
4. Client sends `tools/call` with `linear.create_issue` — aggregate parses the prefix, routes to linear backend, returns result

### Tool namespacing

```
Backend "postgres" tools:  query, list_tables, describe
Backend "linear" tools:    create_issue, list_issues

Aggregated response:
  postgres.query
  postgres.list_tables
  postgres.describe
  linear.create_issue
  linear.list_issues
```

The `.` separator splits on first occurrence from the left, so tool names containing `.` are preserved — `postgres` + `api.v2.call` becomes `postgres.api.v2.call`, which parses back to `postgres` + `api.v2.call`. Server names cannot contain `.`, which is validated at config load time.

### Per-user backend sessions

Each authenticated user gets their own set of backend MCP client connections. When `user@company.com` connects, the aggregate lazily creates connections to each backend, applying that user's tokens where needed. Connections are cached and reused across tool calls.

User A's tokens are never mixed with user B's.

### Discovery

Tool discovery fans out to all backends in parallel. After `discovery.timeout` (default 10s), the aggregate returns whatever tools have been collected. Backends that haven't responded are skipped — healthy backends aren't held hostage by broken ones.

Results are cached per-user for the duration of `discovery.cacheTTL` (default 60s). When the SSE connection first opens, discovery starts immediately in the background so `tools/list` is fast.

### User tokens

For backends that require per-user tokens (API keys, OAuth tokens to upstream services), the existing `UserTokenService` handles retrieval and refresh. If a user hasn't set up their token for a particular service, that service's tools still appear in the aggregated list — but calling them returns a structured error with setup instructions pointing to `/my/tokens`. Same behavior as per-service endpoints today.

### Authentication

The aggregate endpoint uses the same middleware stack as everything else: CORS, OAuth token validation, recovery. Audience validation works naturally — `ValidateTokenMiddleware` extracts the server name from the request path and checks the token's audience accordingly.

### Tool filtering

Tool filtering works at two levels. Per-backend `toolFilter` config on individual servers is respected during aggregation — if the postgres config blocks `drop_table`, it won't appear in the aggregated list. A `toolFilter` on the aggregate server itself filters the final namespaced tool list.

## What stays the same

Per-service endpoints (`/postgres/`, `/linear/`, etc.) continue to work. The aggregate endpoint is additive. Some deployments may prefer per-service connections for token isolation or when a client only needs a single service.

## Scope

**Tools only.** Prompts and resources are not aggregated. Tools are the primary use case, and namespacing resources (which have URI-based identities) is significantly more complex.

**SSE transport.** Uses the SSE + POST message pattern. Streamable HTTP can be added later.

## Future

This is the foundation for tool composition (see `tool-composition-ideas.md`). Once all tools are accessible through a single connection, composed tools that orchestrate across backends can appear alongside them in the same `tools/list` — a unified surface for both raw backend tools and higher-level workflows.
