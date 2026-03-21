# Server Package

This package runs an MCP server over HTTP and optionally protects it with an OAuth-compatible bearer token flow.

## What It Hosts

- `POST /mcp`: MCP JSON-RPC requests (initialize and tool/resource/prompt calls)
- `GET /mcp`: MCP stream/session follow-up requests
- `DELETE /mcp`: MCP session cleanup requests
- `/.well-known/oauth-authorization-server`: OAuth metadata
- `/.well-known/oauth-protected-resource`: resource metadata for MCP clients
- `/register`: dynamic client registration
- `/authorize`: starts authorization-code + PKCE flow
- `/auth/google/callback`: Google OAuth callback
- `/token`: code exchange and refresh token rotation
- `/userinfo`: OpenID-style user profile endpoint
- `/revoke`: token revocation endpoint
- `/health`: simple liveness check

## Architecture

- HTTP transport and route wiring are in `src/index.ts`.
- OAuth/auth logic is in `src/auth-server.ts`.
- Google strategy setup is in `src/google-strategy.ts`.
- MCP tools/resources/prompts are registered in `src/mcp-server.ts`.
- Data loading, persistence, and seed setup are in `src/db.ts`.
- SQL schema is in `src/schema.sql`.

## Request Flow

1. Server startup runs `initDb()`, mounts auth routes, configures CORS, and exposes `/mcp`.
2. A client sends `initialize` to `POST /mcp` without `mcp-session-id`.
3. Server creates a `StreamableHTTPServerTransport`, stores it by session ID, and binds an MCP server instance.
4. Follow-up requests include `mcp-session-id` and are routed to the matching transport.
5. Session close removes transport state from memory.

## Authentication Model

- `AUTH_ENABLED=true` (default): `/mcp` requires bearer token (`requireBearerAuth()`).
- User identity comes from Google login (`passport-google-oauth20`).
- Token minting uses authorization-code flow with required PKCE (`S256`).
- Access tokens are JWTs signed with `JWT_SECRET`.
- Refresh tokens are random opaque values hashed before DB storage.
- Revocation removes token rows from `oauth_tokens`.

## Data Storage

- Uses `sql.js` with file persistence at `packages/data/erp.db`.
- Schema is applied on boot from `src/schema.sql`.
- Seed ERP data is inserted once when tables are empty.
- `saveDb()` is called after write operations.

## Environment Variables

See `packages/server/.env.example` for full template.

- `MCP_PORT`: HTTP port (default `3000`)
- `BASE_URL`: public base URL used in metadata and callbacks
- `AUTH_ENABLED`: set to `false` to disable bearer auth for `/mcp`
- `SESSION_SECRET`: express-session signing secret
- `JWT_SECRET`: JWT signing secret (minimum 32 chars enforced)
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `DEFAULT_SCOPE`: default OAuth scope name (optional)
- `SUPPORTED_SCOPES`: comma/space separated scope list (optional)
- `CORS_ALLOWED_ORIGINS`: comma-separated allowlist of origins (optional)

## Local Development

From repo root:

```bash
npm run dev -w @mcp-experiment/server
```

Package scripts:

- `npm run dev -w @mcp-experiment/server`
- `npm run build -w @mcp-experiment/server`
- `npm run typecheck -w @mcp-experiment/server`
- `npm run test -w @mcp-experiment/server`

## Notes

- In production, `BASE_URL` must be absolute and use `https`.
- If Google credentials are not set, login cannot complete and auth-protected flows will fail.
- With `AUTH_ENABLED=false`, CORS can allow `*`; with auth enabled, use explicit origins.
