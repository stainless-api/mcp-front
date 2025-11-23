# Multi-stage build for smaller final image
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for better layer caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o mcp-front ./cmd/mcp-front

# Final stage - use alpine for Docker CLI and tools
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates docker-cli wget

# Create non-root user
RUN addgroup -g 1001 -S mcp && \
    adduser -S -D -H -u 1001 -h /app -s /sbin/nologin -G mcp -g mcp mcp

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/mcp-front .

# Copy default config
COPY config-oauth.example.json ./config.json

# Change ownership
RUN chown -R mcp:mcp /app

# Use non-root user
USER mcp

# Expose port
EXPOSE 8080

# Health check using existing /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the application
CMD ["./mcp-front", "-config", "config.json"]