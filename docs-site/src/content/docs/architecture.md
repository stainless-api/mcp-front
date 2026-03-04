---
title: Architecture
description: How MCP Front validates tokens with per-service audience claims
---

## Design Model

MCP Front acts as a unified OAuth authorization server for your internal MCP infrastructure. It validates tokens with per-service audience claims per RFC 8707, satisfying the MCP spec's requirement for proper audience binding.

Backend MCP servers trust the proxy implicitly — they don't validate JWT signatures or check audience claims. This keeps internal services private while providing spec-compliant OAuth to external clients.

## Token Flow

When a client connects to a specific service, it requests a token scoped to that service using RFC 8707 resource indicators. MCP Front issues a token with a matching audience claim and validates it on every request before proxying.

```
Claude → GET /authorize?resource=https://mcp.company.com/postgres
MCP Front → Issues token with aud=["https://mcp.company.com/postgres"]
Claude → GET /postgres/sse with Authorization: Bearer <token>
MCP Front → Validates aud contains "https://mcp.company.com/postgres"
MCP Front → Proxies to postgres backend
```

A postgres token cannot access linear. Each service gets its own audience-bound token, preventing lateral movement even within the trusted internal network.

## Why This Model

Making each MCP server a publicly accessible OAuth resource server would require each to implement JWT validation, key management, and security policies independently. That's brittle and error-prone.

MCP Front provides the security boundary instead. Backends run as stdio processes or internal network services. The proxy validates everything and applies per-service access control via audience claims, then forwards authenticated requests. This satisfies the spec while keeping the attack surface minimal. See [Server Types](/mcp-front/server-types/) for transport-specific details.

## No JWKs Published

MCP Front uses HMAC signing and validates its own tokens. No `jwks_uri` endpoint is published because no external service needs to validate MCP Front's tokens — backends trust the proxy. Publishing JWKs would only make sense if backends independently validated tokens, which contradicts the internal infrastructure model.

## Aggregate Servers

Aggregate servers combine tools from multiple backends into a single endpoint. They validate the token's audience against the aggregate's own service URI, then connect to each backend using internal trust. Tools are namespaced as `serverName.toolName` to avoid conflicts, and discovery results are cached with configurable TTL. See [Configuration](/mcp-front/configuration/#aggregate-servers) for setup.

## MCP Specification Support

MCP Front implements MCP specification 2025-11-25 with selective feature adoption:

**Implemented:** Per-service audience validation (RFC 8707), OAuth metadata endpoints (RFC 8414, RFC 9728), dynamic client registration (RFC 7591), and client metadata (`/clients/{client_id}`, SEP-991).

**Skipped:** Incremental scope consent (SEP-835) — audience claims already provide service isolation. Tasks (SEP-1686) — durable request tracking belongs in backend servers, not a stateless proxy.

**Pass-through:** Icon metadata, enhanced schemas, and tool naming are forwarded as-is from backends.

## Compliance

- RFC 8707 (Resource Indicators): Tokens include audience claims for specific services
- RFC 9728 (Protected Resource Metadata): Publishes metadata at `/.well-known/oauth-protected-resource`
- RFC 8414 (Authorization Server Metadata): Publishes metadata at `/.well-known/oauth-authorization-server`
- RFC 7591 (Dynamic Client Registration): Clients self-register at `/register`
- MCP Specification 2025-11-25: Per-service token validation, client metadata discovery

See the [API Reference](/mcp-front/api-reference/) for endpoint details and the [Configuration](/mcp-front/configuration/) reference for all options.
