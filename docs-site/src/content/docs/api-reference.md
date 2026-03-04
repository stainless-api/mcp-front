---
title: API Reference
description: HTTP endpoints and authentication
---

## Core endpoints

### Health check

```
GET /health
```

Returns service health. Use for monitoring and load balancer health checks.

**Response:**

```json
{ "status": "ok" }
```

**Status codes:**

- `200` - Service is healthy

### SSE endpoint

```
GET /{server}/sse

Authorization: Bearer <token>
Accept: text/event-stream
```

MCP protocol communication over Server-Sent Events. The `{server}` path segment must match a server name from your config.

**Request routing:**

![Request Routing and Proxying](/mcp-front/request-routing.svg)

The request flow:

1. Claude connects via SSE to `/{server}/sse`
2. MCP Front validates auth token (OAuth or bearer)
3. MCP Front validates token audience matches requested server (RFC 8707)
4. MCP Front connects to configured MCP server
5. Bidirectional message streaming between Claude and MCP server

**Example stream:**

```
event: message
data: {"jsonrpc":"2.0","method":"tools/list","id":1}

event: message
data: {"jsonrpc":"2.0","result":{"tools":[...]},"id":1}
```

## OAuth endpoints

Only available when using OAuth auth:

### Discovery

```
GET /.well-known/oauth-authorization-server
```

Authorization Server Metadata per RFC 8414.

```
GET /.well-known/oauth-protected-resource
```

Protected Resource Metadata per RFC 9728.

```
GET /.well-known/oauth-protected-resource/{service}
```

Per-service Protected Resource Metadata (RFC 9728). Returns the resource indicator URI for a specific service, used as the `resource` parameter in authorization requests.

```
GET /clients/{client_id}
```

Client metadata for a registered OAuth client. Returns redirect URIs, grant types, response types, and authentication method.

### Authorization

```
GET /authorize?
  response_type=code&
  client_id={client_id}&
  redirect_uri={uri}&
  state={state}&
  code_challenge={challenge}&
  code_challenge_method=S256&
  resource={service_uri}
```

Initiates the OAuth authorization flow. Redirects to the configured identity provider.

The `resource` parameter (RFC 8707) is required and scopes the token to a specific service. Pass the full URI of the target service:

```
resource=https://your-domain.com/postgres
```

Tokens with audience claims only work for the specified service, preventing token reuse across services.

### Token exchange

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={code}&
redirect_uri={uri}&
client_id={client_id}&
code_verifier={verifier}
```

Returns:

```json
{
  "access_token": "jwt-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh-token"
}
```

### Client registration

```
POST /register
Content-Type: application/json

{
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Returns:

```json
{
  "client_id": "generated-id",
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

## User Service Endpoints

Browser-only endpoints for managing service connections. Require a browser SSO session.

### `GET /oauth/services`

Lists services requiring user authentication. Shown after identity provider login when services have `requiresUserToken: true`.

### `GET /my/tokens`

Token management page. Connect OAuth services, add or update manual tokens.

### `GET /oauth/connect?service={service_name}`

Initiate OAuth flow. Redirects to service.

### `POST /oauth/disconnect`

Revoke OAuth connection. Form: `service={service_name}`.

### `POST /my/tokens/set`

Save manual token. Form: `service={service_name}&token={user_token}`.

### `POST /my/tokens/delete`

Delete a manual token. Form: `service={service_name}`.

### `GET /oauth/complete`

Completes the OAuth flow after service connections. Redirects back to the MCP client with the authorization code.

### `GET /oauth/callback/{service_name}`

OAuth callback. Set as redirect URI in service OAuth config.

## Authentication

Two authentication methods are supported:

### Bearer token

```
Authorization: Bearer your-token-here
```

Per-service bearer tokens from each server's `serviceAuths` array. Useful for development and non-OAuth MCP clients.

### OAuth 2.0 with PKCE

Standard flow:

1. Register client via `/register`
2. Direct user to `/authorize` with `resource` parameter (RFC 8707)
3. Exchange code for token at `/token`
4. Use access token in Authorization header for `/{server}/sse` requests

PKCE is required for public clients. Tokens include per-service audience claims (RFC 8707).

## Errors

OAuth format with `error` and `error_description` fields. Common codes: `invalid_request` (bad parameters), `invalid_client` (unknown client), `invalid_grant` (bad auth code), `unauthorized_client` (client can't use grant type), `server_error` (internal error).
