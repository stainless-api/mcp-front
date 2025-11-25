# Execution Proxy for Code Execution Sandboxes

## Overview

The execution proxy feature allows code execution sandboxes to call external APIs without exposing real user credentials to the sandbox. This is achieved through short-lived execution tokens that are validated and swapped for real user credentials by mcp-front.

## Use Case

When a user runs code in a sandbox (e.g., Stainless code execution) that needs to call an external API (e.g., Datadog), the sandbox should not have direct access to the user's credentials. Instead:

1. User authenticates to the external service via mcp-front OAuth
2. Before code execution, request a short-lived execution token from mcp-front
3. Inject the execution token into the sandbox environment
4. Configure the SDK to use mcp-front's proxy URL with the execution token
5. mcp-front validates the token and proxies requests with the real user credentials

## Architecture

```
User → Claude → MCP Server → Code Execution Sandbox
                                      ↓
                              (SDK with execution token)
                                      ↓
                            mcp-front Proxy (/proxy/{service})
                                      ↓
                     (validates token, swaps for user credentials)
                                      ↓
                            External API (e.g., Datadog)
```

## Configuration

### Enable Proxy for a Service

Add a `proxy` section to your MCP server configuration:

```json
{
  "mcpServers": {
    "datadog": {
      "transportType": "inline",
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "oauth",
        "displayName": "Datadog",
        "clientId": {"$env": "DATADOG_CLIENT_ID"},
        "clientSecret": {"$env": "DATADOG_CLIENT_SECRET"},
        "authorizationUrl": "https://app.datadoghq.com/oauth2/v1/authorize",
        "tokenUrl": "https://app.datadoghq.com/oauth2/v1/token",
        "scopes": ["metrics_read", "logs_read"]
      },
      "proxy": {
        "enabled": true,
        "baseURL": "https://api.datadoghq.com",
        "timeout": 30,
        "defaultAllowedPaths": [
          "/api/v1/**",
          "/api/v2/metrics/**",
          "/api/v2/logs/**"
        ]
      }
    }
  }
}
```

### Configuration Fields

- **`enabled`** (required): Set to `true` to enable the proxy for this service
- **`baseURL`** (required): The base URL of the external API
- **`timeout`** (optional): Request timeout in seconds (default: 30)
- **`defaultAllowedPaths`** (optional): Default paths allowed for execution tokens

### Path Patterns

Path patterns support glob-style wildcards:

- `/api/v1/metrics` - Exact match
- `/api/v1/*` - Match any path one level deep (e.g., `/api/v1/metrics`, `/api/v1/logs`)
- `/api/**` - Match any path recursively (e.g., `/api/v1/metrics`, `/api/v1/metrics/query`)
- `/api/*/metrics` - Match with wildcard in middle (e.g., `/api/v1/metrics`, `/api/v2/metrics`)

## API Endpoints

### POST /api/execution-token

Issue a new execution token for code execution.

**Authentication:** OAuth bearer token (user must be authenticated)

**Request Body:**

```json
{
  "execution_id": "exec-abc123",
  "target_service": "datadog",
  "ttl_seconds": 300,
  "allowed_paths": ["/api/v1/metrics", "/api/v2/logs"],
  "max_requests": 1000
}
```

**Fields:**

- **`execution_id`** (required): Unique identifier for this execution
- **`target_service`** (required): Name of the service to proxy to
- **`ttl_seconds`** (optional): Token lifetime in seconds (default: 300, max: 900)
- **`allowed_paths`** (optional): Paths allowed for this token (defaults to service config)
- **`max_requests`** (optional): Maximum number of requests (not enforced in MVP)

**Response:**

```json
{
  "token": "eyJ...",
  "proxy_url": "https://mcp-front.example.com/proxy/datadog",
  "expires_at": "2025-11-25T12:35:00Z"
}
```

**Errors:**

- `401 Unauthorized` - Missing or invalid OAuth token
- `403 Forbidden` - User has not connected to target service
- `404 Not Found` - Target service not configured
- `400 Bad Request` - Invalid request or proxy not enabled for service

### ANY /proxy/{service}/{path}

Proxy requests to the target service.

**Authentication:** Execution token (Bearer in Authorization header)

**URL Format:** `/proxy/{service}/{path}`

**Example:**

```
GET /proxy/datadog/api/v1/metrics?query=avg:cpu
Authorization: Bearer eyJ...
```

The request is proxied to:

```
GET https://api.datadoghq.com/api/v1/metrics?query=avg:cpu
Authorization: Bearer <user's-real-token>
```

**Errors:**

- `401 Unauthorized` - Missing or invalid execution token
- `403 Forbidden` - Path not allowed by token
- `404 Not Found` - Service not configured
- `502 Bad Gateway` - Backend service error
- `504 Gateway Timeout` - Backend timeout

## Integration Example

### Stainless Code Execution

1. **Request execution token before running code:**

```bash
curl -X POST https://mcp-front.example.com/api/execution-token \
  -H "Authorization: Bearer ${OAUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "exec-123",
    "target_service": "datadog",
    "ttl_seconds": 300
  }'
```

Response:

```json
{
  "token": "eyJ...",
  "proxy_url": "https://mcp-front.example.com/proxy/datadog",
  "expires_at": "2025-11-25T12:35:00Z"
}
```

2. **Inject into sandbox environment:**

```typescript
// Template for code execution
const executionToken = process.env.EXECUTION_TOKEN;  // eyJ...
const proxyURL = process.env.PROXY_URL;              // https://mcp-front.example.com/proxy/datadog

// Initialize generated Datadog SDK
const datadog = new DatadogSDK({
  baseURL: proxyURL,
  auth: `Bearer ${executionToken}`,
});

// User's code runs here
const metrics = await datadog.metrics.query({
  query: "avg:cpu.usage{*}",
  from: Date.now() - 3600000,
  to: Date.now()
});

console.log(metrics);
```

3. **SDK makes proxied request:**

```
GET https://mcp-front.example.com/proxy/datadog/api/v1/metrics?query=avg:cpu.usage{*}&from=...
Authorization: Bearer eyJ...
```

4. **mcp-front validates token and proxies:**

```
GET https://api.datadoghq.com/api/v1/metrics?query=avg:cpu.usage{*}&from=...
Authorization: Bearer dd_api_key_abc123
```

## Security

### Token Properties

- **Short-lived**: Default 5 minutes, maximum 15 minutes
- **Service-scoped**: Token valid for one service only
- **Path-restricted**: Optional path allowlisting via glob patterns
- **HMAC-signed**: Same signing mechanism as browser session tokens
- **Non-replayable**: Tokens expire after TTL

### Threat Mitigation

| Threat | Mitigation |
|--------|-----------|
| Token exfiltration | Very short TTL (5-15 min) |
| Privilege escalation | Service scoping, path allowlisting |
| Token forgery | HMAC-SHA256 signing |
| Confused deputy | Service name validation in token |
| DoS via proxy | Timeout enforcement, rate limiting (future) |
| Credential leakage | Tokens never contain real credentials |

### Audit Trail

All proxy requests are logged with:

- Execution ID
- User email
- Target service
- Request method and path
- Response status
- Duration

## Testing

### Unit Tests

```bash
# Test execution token generation/validation
go test ./internal/executiontoken -v

# Test path matching
go test ./internal/proxy -v -run TestPathMatcher

# Test HTTP proxy
go test ./internal/proxy -v -run TestHTTPProxy
```

### Integration Test

```bash
# End-to-end proxy flow
go test ./integration -v -run TestExecutionProxy
```

### Manual Testing

1. Start mcp-front with proxy-enabled service configuration
2. Authenticate user via OAuth
3. Request execution token:

```bash
curl -X POST http://localhost:8080/api/execution-token \
  -H "Authorization: Bearer ${OAUTH_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "execution_id": "test-123",
    "target_service": "datadog",
    "ttl_seconds": 300
  }'
```

4. Use execution token to proxy request:

```bash
curl http://localhost:8080/proxy/datadog/api/v1/metrics \
  -H "Authorization: Bearer ${EXECUTION_TOKEN}"
```

## Monitoring

### Logs

Execution proxy logs are emitted with the `execution_proxy` prefix:

```
INFO execution_proxy: Execution token issued {user=user@example.com execution_id=exec-123 target_service=datadog ttl_seconds=300}
INFO execution_proxy: Request proxied successfully {execution_id=exec-123 user=user@example.com service=datadog method=GET path=/api/v1/metrics duration_ms=45}
```

### Metrics (Future)

- `execution_tokens_issued_total{service}` - Total tokens issued
- `execution_proxy_requests_total{service,status}` - Total proxy requests
- `execution_proxy_duration_seconds{service}` - Request duration histogram
- `execution_token_validations_total{result}` - Token validation results

## Troubleshooting

### Token validation fails

**Symptom:** `401 Unauthorized: invalid execution token`

**Causes:**
- Token expired (check TTL)
- Wrong signing key (verify JWT_SECRET)
- Token tampered with
- Service name mismatch

**Solution:** Request a new token

### Path not allowed

**Symptom:** `403 Forbidden: path /api/v3/metrics not allowed for this execution`

**Causes:**
- Path not in token's `allowed_paths`
- Path not in service's `defaultAllowedPaths`

**Solution:** Request token with correct `allowed_paths` or update service configuration

### User credentials not found

**Symptom:** `401 Unauthorized: user credentials not found for service datadog`

**Causes:**
- User has not connected to the service via OAuth
- User token expired and refresh failed

**Solution:** User must authenticate to the service via mcp-front OAuth flow

### Backend timeout

**Symptom:** `504 Gateway Timeout: Backend service unavailable`

**Causes:**
- Backend service is slow or down
- Timeout too short for operation

**Solution:** Increase `timeout` in proxy configuration

## Future Enhancements

### Phase 2 (Planned)

- Request rate limiting per execution token
- Request counting enforcement (`max_requests`)
- Token revocation API
- Execution context tracking in storage

### Phase 3 (Future)

- Response filtering/transformation
- Request/response logging to storage
- Webhook notifications for security events
- Custom path rewriting rules
- Multi-region proxy support

## See Also

- [OAuth Configuration](./docs/oauth.md)
- [MCP Server Configuration](./docs/mcp-servers.md)
- [Security Best Practices](./docs/security.md)
