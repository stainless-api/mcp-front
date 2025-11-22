---
title: Architecture
description: How MCP Front validates tokens with per-service audience claims
---

## Design Model

MCP Front acts as a unified OAuth authorization server for your internal MCP infrastructure. It validates tokens with per-service audience claims per RFC 8707, satisfying the MCP Specification 2025-06-18 requirement that servers validate tokens with proper audience binding.

Backend MCP servers trust the proxy implicitly. They don't validate JWT signatures or check audience claims themselves. This keeps internal services private while providing spec-compliant OAuth authentication to external clients like Claude.ai.

## Token Flow

When Claude connects to a specific service, it requests a token scoped to that service using the resource indicator pattern from RFC 8707. MCP Front issues a token with an audience claim matching the service identifier, then validates that claim on every request before proxying to the backend.

```
Claude → GET /authorize?resource=https://mcp.company.com/postgres
MCP Front → Issues token with aud=["https://mcp.company.com/postgres"]
Claude → GET /postgres/sse with Authorization: Bearer <token>
MCP Front → Validates aud contains "https://mcp.company.com/postgres"
MCP Front → Proxies to postgres backend
```

Tokens for postgres cannot be reused to access linear or gong. Each service gets its own audience-bound token, preventing lateral movement even within the trusted internal network.

## Why This Model

MCP Front centralizes authentication for internal services that shouldn't be exposed to the internet. Running postgres, linear, or gong as publicly accessible OAuth resource servers would require each to implement JWT validation, key management, and security policies. That's brittle and error-prone.

Instead, MCP Front provides the security boundary. Backend servers run as stdio processes or internal network services. They don't handle authentication. The proxy validates everything, applies per-service access control via audience claims, then forwards authenticated requests.

This satisfies the spec's requirement for per-service token validation while keeping operations simple and attack surface minimal.

## No JWKs Published

MCP Front uses HMAC signing and validates its own tokens. It doesn't publish public keys at a jwks_uri endpoint because no external service needs to validate MCP Front's tokens. Backend services trust the proxy. The proxy validates audience claims. Publishing JWKs would only make sense if backend services were independently exposed and validating tokens themselves, which contradicts the internal infrastructure model.

## Compliance

- RFC 8707 (Resource Indicators): Tokens include audience claims for specific services
- RFC 9728 (Protected Resource Metadata): Publishes metadata at `/.well-known/oauth-protected-resource`
- RFC 8414 (Authorization Server Metadata): Publishes metadata at `/.well-known/oauth-authorization-server`
- MCP Specification 2025-06-18: Per-service token validation with audience binding
