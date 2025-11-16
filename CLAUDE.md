# mcp-front: Agent Instructions for OAuth 2.1 Authenticated MCP Proxy

## Project Overview

mcp-front is a Go-based OAuth 2.1 proxy server for MCP (Model Context Protocol) servers. It provides authentication and authorization for Claude.ai to access company resources.

## Critical Rules for Agents

### 🚨 Security First

- **NEVER** commit secrets or hardcode credentials
- **NEVER** update git config
- **NEVER** push to remote unless explicitly asked
- **ALWAYS** use environment variables for sensitive data
- **ALWAYS** validate JWT secrets are at least 32 bytes

### 📁 File Handling

- **NEVER** delete files as the first step when making changes
- **ALWAYS** read existing code before modifying
- **ALWAYS** prefer editing existing files over creating new ones
- **NEVER** create documentation files (\*.md) unless explicitly requested
- **ALWAYS** understand the existing code structure before making changes

### 🧪 Testing Requirements

- **ALWAYS** run tests after making changes
- **ALWAYS** run staticcheck before committing
- **ALWAYS** ensure OAuth integration tests pass
- **NEVER** assume test frameworks - check README or codebase first

### 🔧 Code Standards

- **NEVER** add comments unless explicitly requested
- **ALWAYS** follow existing code conventions in the file
- **ALWAYS** check if a library exists before importing it
- **ALWAYS** use structured logging with slog at INFO level
- **ALWAYS** handle errors properly - no ignored errors

## Technical Excellence

### 🔐 Security

- **ALWAYS** encrypt sensitive data at rest (OAuth secrets, bearer tokens)
- **NEVER** store plaintext secrets in Firestore
- **ALWAYS** use AES-256-GCM for encryption
- **NEVER** log secrets

### 🏗️ Go Idioms

- Write simple, idiomatic Go - no Java patterns
- Use interfaces, not inheritance
- Handle errors explicitly
- Prefer flat structures over nested hierarchies
- **Accept interfaces, return structs** - Fundamental Go principle
- **Define interfaces where they are used** - Not in the package that implements them
- **Avoid circular imports** - Use interface segregation in separate packages when needed
- **Dependency injection over getter methods** - Pass dependencies to constructors
- **Functional core, imperative shell** - Prefer pure functions for business logic, keep side effects (I/O, state mutations) at the boundaries. Makes code more testable and reasoning easier.
- **Upstream lifecycle control** - Manage goroutines, servers, and background processes from the application root. Library code should expose Start/Stop methods, not start things autonomously.

### 🎯 Core Development Principles (from Zig Zen)

- **Communicate intent precisely** - Clear, unambiguous code and APIs
- **Edge cases matter** - Handle all scenarios, especially error paths
- **Favor reading code over writing code** - Optimize for maintainability
- **Only one obvious way to do things** - Avoid multiple patterns for the same task
- **Runtime crashes are better than bugs** - Fail fast and visibly
- **Compile errors are better than runtime crashes** - Catch issues early
- **Incremental improvements** - Small, focused changes over rewrites
- **Avoid local maximums** - Think holistically about the architecture
- **Reduce the amount one must remember** - Make APIs intuitive and consistent
- **Focus on code rather than style** - Substance over form
- **Resource allocation may fail; resource deallocation must succeed** - Always clean up
- **Memory is a resource** - Be conscious of allocations
- **Together we serve the users** - User needs drive decisions

## Key Technical Context

### OAuth Implementation

- Uses fosite library for OAuth 2.1
- PKCE required for all flows
- Supports both public and confidential clients
- JWT secrets must be 32+ bytes for HMAC-SHA512/256
- State parameter entropy varies by environment (0 for dev, 8 for prod)

### Storage Options

1. **Memory** (default): Development only, data lost on restart
2. **Firestore**: Production, with configurable database and collection names
   - Default database: "(default)"
   - Default collection: "mcp_front_data"

### Environment Variables

```bash
# Required
GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."
JWT_SECRET="..." # Must be 32+ bytes

# Optional
MCP_FRONT_ENV="development"  # Relaxes OAuth validation
LOG_LEVEL="debug"           # debug, info, warn, error
LOG_FORMAT="text"           # json or text
```

### Common Tasks

#### Adding a new MCP server

1. Check existing servers in config
2. Add to mcpServers section
3. Configure auth tokens if using bearer auth
4. Test the SSE endpoint

#### Updating OAuth scopes

1. Check `internal/googleauth/google.go` for current scopes
2. Use standard OpenID Connect scopes (not Google-specific URLs)
3. Update tests to verify new scopes work

#### Fixing CI issues

1. Check staticcheck version in `.github/workflows/ci.yml`
2. Run `go test ./...` locally first
3. Ensure Docker tags include both `latest` and `main-<sha>`

### Project Structure

```
internal/
├── config/         # Configuration parsing and validation
├── oauth/          # OAuth 2.1 provider, JWT, middleware
├── googleauth/     # Google OAuth integration (pure functions)
├── adminauth/      # Admin authorization logic
├── browserauth/    # Browser session types (SessionCookie, AuthorizationState)
├── oauthsession/   # OAuth session types for fosite
├── servicecontext/ # Service authentication context utilities
├── server/         # HTTP server, handlers, and middleware
├── client/         # MCP client management and session handling
├── auth/           # Service OAuth client for upstream authentication
├── crypto/         # Encryption, HMAC, token signing utilities
├── storage/        # Storage abstraction (memory, Firestore)
├── inline/         # Inline MCP server implementation
├── mcpfront.go     # Main application orchestration (imperative shell)
└── [utility packages: cookie, email, envutil, json, jsonrpc, log, sse, testutil]

integration/        # Integration tests (OAuth, security, scenarios)
cmd/mcp-front/      # Main application entry point
```

### Testing Guidance

- Unit tests: `go test ./internal/...`
- Integration tests: `cd integration && go test -v`
- OAuth tests specifically: `go test ./internal/oauth -v`
- Security tests: `go test ./integration -run TestSecurity`

### Common Pitfalls to Avoid

1. Don't use `find` or `grep` commands - use Grep/Glob tools instead
2. Don't assume library availability - check go.mod first
3. Don't create new auth patterns - use existing OAuth or bearer token auth
4. Don't modify git configuration
5. Don't create README files proactively
6. **Variable shadowing package names** - `config.MCPClientConfig is not a type` means a variable named `config` is shadowing the package. Always check for variables that shadow imported package names

### When Working on Features

1. Use TodoWrite tool to plan complex tasks
2. Read relevant code thoroughly before starting
3. Check existing patterns in similar files
4. Run tests incrementally as you work
5. Verify with `go build` before committing
6. **Review git diff carefully** - Previous changes may have issues
7. **Ask questions when uncertain** - Don't assume and proceed
8. **No hacks or shortcuts** - Only clean, maintainable solutions

### Documentation Standards

**Write precise, technical language:**

- ❌ "When Claude connects to MCP Front, it includes a bearer token in the Authorization header"
- ✅ "An MCP client can connect to MCP Front with a bearer token"
- ❌ "Users log in with their Google account"
- ✅ "Claude redirects users to Google for authentication"
- ❌ "Claude establishes SSE connection"
- ✅ "Claude connects via SSE"

**Key clarifications:**

- **Claude.ai only supports OAuth** - Bearer tokens are for development/alternative clients only
- **Avoid redundant implementation details** - "bearer token" implies Authorization header
- **Use precise actors** - "MCP client" not "user" in technical contexts
- **Be specific about auth flow** - Claude handles the OAuth redirect, MCP Front validates domains

### Refactoring Guidelines

When refactoring for better design:

1. **Identify the core issue** - Don't just patch symptoms
2. **Use proper dependency injection** - Pass dependencies to constructors
3. **Test the refactoring** - Ensure all tests still pass

### Security Boundaries

- mcp-front handles OAuth authentication only
- Does NOT validate/sanitize data sent to MCP servers
- Each MCP server is responsible for its own security
- SQL injection, command injection protection is MCP server's responsibility

## Quick Reference Commands

```bash
# Build everything
make build

# Format everything
make format

# Lint everything
make lint

# Test mcp-front
go test ./internal/... -v
go test ./integration -v

# Run mcp-front locally
./mcp-front -config config.json

# Start docs dev server
make doc
```

## Documentation Site Guidelines

### Design Philosophy

The documentation site follows terse, to-the-point prose style (like early Stripe or Stainless docs):

- No bullet lists or tables in content
- Conversational yet technical tone
- Developer-to-developer communication
- OAuth-first approach with bearer tokens as collapsible fallback

### Visual Design

- **Theme**: Clean red (#FF6B6B) matching logo, with softer red (#FF9999) for dark mode
- **Logo**: Animated mascot that looks left/right/center with nose rotation and natural blinking
- **Navigation**: Simplified from 23 pages to 7 essential pages
- **Components**: Custom hero, theme switcher, and animated logo components

### Technical Implementation

**Structure** (docs-site/):

```
src/
├── components/
│   ├── AnimatedLogo.astro       # Mascot with eye movement and blinking
│   ├── CustomHero.astro         # Hero layout with logo positioning
│   └── CustomThemeSelect.astro  # Sun/moon toggle vs dropdown
├── assets/
│   ├── logo.svg                 # Dark mode version (lighter strokes)
│   └── logo-light.svg           # Light mode version (darker strokes)
└── styles/custom.css            # Theme variables and animations
```

**Key Features**:

- Starlight theme with custom components and CSS overrides
- Proper light/dark mode with automatic logo switching
- 12-second animation cycle for subtle mascot behavior
- Mobile-responsive design (needs work)

### Animation Details

The animated logo creates a face-like character:

- **Eyes**: Left/right translation (1px) with synchronized movement
- **Nose**: Subtle rotation (-1deg/+1deg) following eye direction
- **Blinking**: Vertical scale (scaleY 0.1) with step-like timing for natural effect
- **Timing**: 12-second cycle for easter egg discovery, not attention-grabbing

### Color Management

**CSS Custom Properties**:

```css
:root {
  --sl-color-accent: #ff6b6b; /* Light mode */
}

[data-theme="dark"] {
  --sl-color-accent: #ff6b6b; /* Buttons */
  --sl-color-text-accent: #333333; /* Text on red backgrounds */
}
```

**Specific Overrides**:

- GitHub icon: White in dark mode
- Sidebar selection: Readable contrast
- Anchor links: Light gray in dark mode
- Content links: Red in dark mode
- TOC current section: Red highlight

### Content Guidelines

**Configuration Examples**:

- Always use `{"$env": "VAR"}` syntax, never bash `$VAR`
- Match actual Go implementation exactly
- Use realistic service names (e.g., "linear" not "database")
- Include all required fields (version, transportType, etc.)

**Writing Style**:

- Flowing prose, not lists
- Explain the "why" not just "how"
- Assume developer audience
- Keep it concise but complete

### Pull Request Guidelines

**PR Titles**: Use clear, descriptive titles focused on the change impact, not just restating commit messages. Examples:

- ❌ "feat: add message endpoint support for SSE MCP servers"
- ✅ "Add SSE message endpoint support"
- ❌ "fix: implement session-specific tool registration for stdio clients"
- ✅ "Fix stdio session tool handler conflicts"

**PR Descriptions**: Write terse prose for humans, not documentation. Avoid bullet lists unless they add genuine value. Focus on the problem solved and solution approach:

- Explain what was broken and how it's fixed
- Use conversational, developer-to-developer tone
- Skip implementation details unless critical for review
- Keep it concise but informative

### Common Issues

1. **Theme switching breaks**: Check CSS variable inheritance
2. **Logo not animating**: Ensure component is properly imported and classes match
3. **Colors wrong in dark mode**: Verify `[data-theme='dark']` selectors
4. **Build failures**: Usually missing imports or malformed frontmatter
5. **Content not updating**: Astro dev server cache, restart required

### Deployment

- Uses GitHub Pages with workflow in `.github/workflows/`
- Build artifacts in `docs-site/dist/`
- Base path: `/mcp-front` for GitHub Pages
- Prettier formatting enforced

Remember: The mascot is an easter egg, not a distraction. Subtle movements create personality without being annoying.

### Understanding Sam's Standards

1. **Zero tolerance for workarounds** - If something is wrong, fix it properly. Don't try to work around design decisions.

2. **Config syntax is sacred** - The `{"$env": "VAR"}` syntax exists to prevent shell injection risks. NO bash syntax (`$VAR`) anywhere in configs, ever. This isn't arbitrary - it prevents real security issues when configs pass through multiple layers of tooling.

3. **Simplicity over cleverness** - When you see complex shell commands or temp file creation, the answer is usually "use the tool's native features instead." Don't preserve unnecessary complexity.

4. **Read the code first** - Don't guess how systems work. Read `ParseConfigValue` and similar functions to understand the actual implementation.

5. **High signal communication** - Expect direct feedback. "That's really bad" or "good fucking damn" are proportional to how badly you're missing the point. This isn't personal - it's clear communication about what matters.

### Common Misunderstandings to Avoid

1. **Don't confuse config parsing with runtime templating** - `{"$env": "VAR"}` is resolved during config load, not at runtime.

2. **Don't assume complexity where none exists** - This codebase favors simple, explicit solutions.

3. **Don't bring patterns from other systems** - Understand THIS system's design choices.

### When You're Stuck

- **ASK QUESTIONS** - Even "dumb" questions are better than wrong assumptions
- If tests are failing, fix the code, not the tests
- If you're working around a design choice, stop and ask why it exists
- Never hide problems - surface issues immediately
- **Do NOT simulate negative human emotions** - No "panicking", "freaking out", "frustration", etc.

Remember: Think like an experienced engineer - understand the use cases, read the docs, plan properly, then execute. But most importantly, when uncertain, ASK rather than guess.
