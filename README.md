# MCP Experiment

A local MCP remote server with OAuth 2.1 (Google SSO) and SQLite storage, built with the MCP TypeScript SDK.

## Architecture

```
packages/server/          MCP + OAuth auth server (single Express app, one port)
  src/
    db.ts                sql.js (WASM SQLite) — schema + seed data
    schema.sql           Tables: users, oauth_clients, oauth_codes,
                         oauth_tokens, vendor_bills, expense_reports, sales_orders
    google-strategy.ts   Passport Google OAuth2 strategy
    auth-server.ts       OAuth 2.1 server (SDK auth router + Google bridge + JWT tokens)
    mcp-server.ts        MCP server (tools, resources, prompts)
    index.ts             Main entry — mounts auth + MCP on a single port

packages/client/         Claude Desktop connector manifest
```

## Prerequisites

- Node.js 24+
- [ngrok](https://ngrok.com) — Claude Desktop's connector flow requires a publicly accessible URL (Anthropic's servers validate the MCP URL, so `localhost` is rejected)

```bash
brew install ngrok
ngrok config add-authtoken <your-token>
```

## Quick start

### 1. Configure Google OAuth

Create credentials at https://console.cloud.google.com/apis/credentials:

- Application type: **Web application**
- Authorized redirect URI: `https://<your-ngrok-domain>/auth/google/callback`

> Use a [free static ngrok domain](https://dashboard.ngrok.com/domains) so the redirect URI doesn't change between restarts.

### 2. Configure environment

```bash
cp packages/server/.env.example packages/server/.env
```

Edit `packages/server/.env`:

```env
MCP_PORT=3000
BASE_URL=https://<your-ngrok-domain>
SESSION_SECRET=<random string>
JWT_SECRET=<random string, min 32 chars>
GOOGLE_CLIENT_ID=<from Google Cloud Console>
GOOGLE_CLIENT_SECRET=<from Google Cloud Console>
```

### 3. Start the server

```bash
npm install
npm run dev:server
```

The server starts on `http://localhost:3000` with all endpoints on a single port:

- **MCP endpoint**: `http://localhost:3000/mcp`
- **OAuth metadata**: `http://localhost:3000/.well-known/oauth-authorization-server`
- **Auth endpoints**: `/authorize`, `/token`, `/register`, `/auth/google/callback`

### 4. Start the ngrok tunnel

```bash
ngrok http http://localhost:3000
```

### 5. Connect to Claude Desktop

Settings → Connectors → Add custom connector:

- **URL**: `https://<your-ngrok-domain>/mcp`

Claude Desktop will open a browser to complete Google OAuth. After login, the connector is active.

## MCP Tools

| Tool | Description |
|------|-------------|
| `list_vendor_bills` | Query vendor bills (filter by vendor, status, date range) |
| `list_expense_reports` | Query expense reports (filter by employee, status, date) |
| `list_sales_orders` | Query sales orders (filter by customer, status, date) |
| `get_record_detail` | Fetch a single record by table + ID |

## MCP Resources

| URI | Description |
|-----|-------------|
| `erp://vendor-bills` | List of all vendor bills (JSON) |
| `erp://expense-reports` | List of all expense reports (JSON) |
| `erp://sales-orders` | List of all sales orders (JSON) |

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_PORT` | `3000` | Server port |
| `BASE_URL` | `http://localhost:3000` | Public base URL (set to ngrok URL) |
| `SESSION_SECRET` | — | Express session secret |
| `JWT_SECRET` | — | JWT signing secret (min 32 chars) |
| `GOOGLE_CLIENT_ID` | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | — | Google OAuth client secret |

## OAuth 2.1 flow (how it works)

1. Client hits `/mcp` without a token → server returns `401 + WWW-Authenticate`
2. Client fetches `/.well-known/oauth-protected-resource/mcp` → discovers auth server URL
3. Client fetches `/.well-known/oauth-authorization-server` → discovers endpoints
4. Client does Dynamic Client Registration (`POST /register`)
5. Client redirects to `/authorize` → browser opens Google SSO
6. Google redirects to `/auth/google/callback` → auth code issued
7. Client exchanges code for JWT access + refresh tokens via `POST /token`
8. Client calls `/mcp` with `Authorization: Bearer <token>`
9. Server validates JWT, extracts user identity, handles request

## Dev commands

```bash
npm run dev:server   # Start server with hot reload
npm run typecheck    # TypeScript type checking
npm run build        # Compile TypeScript
```


```
npm run dev --workspace=@mcp-experiment/server
ngrok http http://localhost:3000
```
