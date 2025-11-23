# Integration Tests

## Run Tests

```bash
# Run all integration tests
go test -v

# Run specific test
go test -v -run TestOAuthIntegration

# With custom timeout
go test -v -timeout 2m
```

## Run Demo

```bash
./run_demo.sh
```

The demo starts:
- PostgreSQL test database on port 15432
- Mock OAuth server on port 9090
- mcp-front on port 8080

Connect Claude.ai to: `http://localhost:8080/postgres/sse`

## Test Coverage

The integration tests validate:
- End-to-end MCP communication with stdio and SSE
- Security scenarios and authentication bypass protection
- OAuth flow as used by Claude.ai
- Dynamic client registration (RFC 7591)
- CORS headers and preflight requests
- Client storage persistence
- Health check endpoint

## Files

- `integration_test.go` - End-to-end tests including OAuth flows
- `security_test.go` - Security and authentication tests
- `test_utils.go` - Test utilities and mock OAuth server
- `config/config.test.json` - Simple token auth test config
- `config/config.oauth-test.json` - OAuth test config
- `config/config.demo-token.json` - Demo config with tokens
- `config/docker-compose.test.yml` - Test database
- `fixtures/schema.sql` - Test data
- `run_demo.sh` - Demo environment