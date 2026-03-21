import { randomUUID, createHash } from "crypto";
import * as jose from "jose";
import express, { type Request, type Response, type NextFunction } from "express";
import session from "express-session";
import {
  InvalidGrantError,
  InvalidScopeError,
  InvalidTokenError,
  ServerError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth as sdkRequireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { getDb, saveDb } from "./db.js";
import { passport as passportAuth, setupGoogleStrategy } from "./google-strategy.js";

/**
 * OAuth 2.1 style authorization server for local MCP protection.
 * Uses:
 * - Google login for end-user authentication
 * - PKCE authorization code flow for public clients
 * - Signed JWT access tokens plus stored refresh tokens
 */
const BASE = normalizeBaseUrl(process.env.BASE_URL ?? "http://localhost:3000");
const DEFAULT_SCOPE = process.env.DEFAULT_SCOPE ?? "default";
const SUPPORTED_SCOPES = parseScopes(process.env.SUPPORTED_SCOPES, [
  "openid",
  "profile",
  "email",
  DEFAULT_SCOPE,
]);

if (!process.env.JWT_SECRET) throw new Error("JWT_SECRET env var is required — set it in packages/server/.env");
if (!process.env.SESSION_SECRET) throw new Error("SESSION_SECRET env var is required — set it in packages/server/.env");
assertSecretStrength("JWT_SECRET", process.env.JWT_SECRET, 32);
assertSecretStrength("SESSION_SECRET", process.env.SESSION_SECRET, 16);

const JWT_SECRET = new TextEncoder().encode(process.env.JWT_SECRET);

const ACCESS_TOKEN_TTL_SEC = 3600;
const REFRESH_TOKEN_TTL_SEC = 604800;
const AUTH_CODE_TTL_SEC = 600;

const oauthProvider = createOAuthProvider();

export function createAuthApp(): express.Application {
  setupGoogleStrategy();

  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(
    session({
      secret: process.env.SESSION_SECRET!,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: BASE.startsWith("https"),
        httpOnly: true,
        sameSite: "lax",
        maxAge: AUTH_CODE_TTL_SEC * 1000,
      },
    })
  );
  app.use(passportAuth.initialize());
  app.use(passportAuth.session());

  app.use(
    mcpAuthRouter({
      provider: oauthProvider,
      issuerUrl: new URL(BASE),
      baseUrl: new URL(BASE),
      resourceServerUrl: new URL(`${BASE}/mcp`),
      scopesSupported: SUPPORTED_SCOPES,
      serviceDocumentationUrl: new URL(`${BASE}/.well-known/oauth-protected-resource`),
      tokenOptions: {
        rateLimit: { windowMs: 10 * 60 * 1000, max: 30 },
      },
      authorizationOptions: {
        rateLimit: { windowMs: 10 * 60 * 1000, max: 60 },
      },
      clientRegistrationOptions: {
        rateLimit: { windowMs: 10 * 60 * 1000, max: 20 },
      },
      revocationOptions: {
        rateLimit: { windowMs: 10 * 60 * 1000, max: 30 },
      },
    })
  );

  // Backward-compatible PRM alias for existing clients that discover at root instead of /mcp path.
  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: BASE,
      authorization_servers: [BASE],
      scopes_supported: [DEFAULT_SCOPE],
      bearer_methods_supported: ["header"],
    });
  });

  app.get(
    "/auth/google/callback",
    passportAuth.authenticate("google", { failureRedirect: `${BASE}/?error=auth_failed`, keepSessionInfo: true }),
    async (req: Request, res: Response) => {
      const oauth = (req.session as unknown as Record<string, unknown>).oauth as {
        clientId: string;
        redirectUri: string;
        scope: string;
        state: string | null;
        codeChallenge: string;
      } | undefined;

      if (!oauth) {
        res.redirect(`${BASE}/?error=session_expired`);
        return;
      }

      try {
        const client = await oauthProvider.clientsStore.getClient(oauth.clientId);
        if (!client) {
          res.redirect(`${BASE}/?error=invalid_client`);
          return;
        }
        if (!client.redirect_uris.includes(oauth.redirectUri)) {
          res.redirect(`${BASE}/?error=invalid_redirect_uri`);
          return;
        }

        const user = req.user as { id: string } | undefined;
        if (!user?.id) {
          res.redirect(`${BASE}/?error=auth_failed`);
          return;
        }

        const code = randomUUID();
        const now = Math.floor(Date.now() / 1000);
        const db = getDb();
        db.run(
          `INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          [
            code,
            oauth.clientId,
            user.id,
            oauth.redirectUri,
            oauth.scope,
            oauth.codeChallenge,
            "S256",
            now + AUTH_CODE_TTL_SEC,
            0,
          ]
        );
        saveDb();

        const params = new URLSearchParams({ code });
        if (oauth.state) params.set("state", oauth.state);
        res.redirect(`${oauth.redirectUri}?${params.toString()}`);
      } catch {
        res.redirect(`${BASE}/?error=server_error`);
      }
    }
  );

  app.get("/userinfo", bearerAuth, async (req: Request, res: Response) => {
    const auth = (req as Request & { authContext?: { userId: string } }).authContext;
    if (!auth) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }

    const db = getDb();
    const rows = db.exec("SELECT id, email, name, picture FROM users WHERE id = ?", [auth.userId]);
    if (!rows.length || !rows[0].values.length) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    const [id, email, name, picture] = rows[0].values[0];
    res.json({ sub: id, email, name, picture });
  });

  // Backward-compatible revoke endpoint for callers that revoke with bearer token.
  app.post("/revoke", bearerTokenRevokeFallback, (_req, res) => {
    res.json({});
  });

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  return app;
}

export function bearerAuth(req: Request, _res: Response, next: NextFunction) {
  resolveBearerAuth(req.headers.authorization)
    .then((auth) => {
      (req as Request & { authContext?: { userId: string; jti: string } }).authContext = auth ?? undefined;
      next();
    })
    .catch(() => {
      (req as Request & { authContext?: { userId: string; jti: string } }).authContext = undefined;
      next();
    });
}

export async function verifyAccessToken(token: string): Promise<jose.JWTPayload> {
  const { payload } = await jose.jwtVerify(token, JWT_SECRET, {
    algorithms: ["HS256"],
    issuer: BASE,
    audience: BASE,
  });
  return payload;
}

export function requireBearerAuth(requiredScopes: string[] = []) {
  return sdkRequireBearerAuth({
    verifier: oauthProvider,
    requiredScopes,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(`${BASE}/mcp`)),
  });
}

function createOAuthProvider(): OAuthServerProvider {
  const clientsStore: OAuthRegisteredClientsStore = {
    async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
      const db = getDb();
      const rows = db.exec(
        "SELECT client_id, client_name, redirect_uris, grant_types, created_at, client_secret_hash FROM oauth_clients WHERE client_id = ?",
        [clientId]
      );

      if (!rows.length || !rows[0].values.length) return undefined;
      const [id, name, redirectUrisRaw, grantTypesRaw, createdAt, clientSecretHash] = rows[0].values[0] as [
        string,
        string,
        string,
        string,
        number,
        string | null,
      ];

      return {
        client_id: id,
        client_name: name,
        redirect_uris: JSON.parse(redirectUrisRaw),
        grant_types: JSON.parse(grantTypesRaw),
        token_endpoint_auth_method: clientSecretHash ? "client_secret_post" : "none",
        client_id_issued_at: createdAt,
      };
    },
    async registerClient(client): Promise<OAuthClientInformationFull> {
      const now = Math.floor(Date.now() / 1000);
      const clientId = randomUUID();
      const grantTypes = client.grant_types ?? ["authorization_code"];
      const redirectUris = client.redirect_uris ?? [];

      const db = getDb();
      db.run(
        `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          clientId,
          null,
          client.client_name ?? "MCP Client",
          JSON.stringify(redirectUris),
          JSON.stringify(grantTypes),
          now,
          now,
        ]
      );
      saveDb();

      return {
        ...client,
        client_id: clientId,
        client_id_issued_at: now,
        client_secret: undefined,
        client_secret_expires_at: undefined,
        token_endpoint_auth_method: "none",
        grant_types: grantTypes,
        redirect_uris: redirectUris,
      };
    },
  };

  return {
    clientsStore,
    async authorize(client, params, res): Promise<void> {
      if (params.scopes && params.scopes.length > 0) {
        const requested = params.scopes.filter(Boolean);
        if (!requested.every((scope) => SUPPORTED_SCOPES.includes(scope))) {
          throw new InvalidScopeError("invalid_scope");
        }
      }

      const req = res.req as Request | undefined;
      if (!req) throw new ServerError("request context unavailable");

      const state = params.state ?? null;
      const scope = (params.scopes && params.scopes.length > 0 ? params.scopes : [DEFAULT_SCOPE]).join(" ");

      (req.session as unknown as Record<string, unknown>).oauth = {
        clientId: client.client_id,
        redirectUri: params.redirectUri,
        scope,
        state,
        codeChallenge: params.codeChallenge,
      };

      if (req.user && (req.user as { id?: string }).id) {
        const user = req.user as { id: string };
        const code = randomUUID();
        const now = Math.floor(Date.now() / 1000);
        const db = getDb();

        db.run(
          `INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used)
           VALUES (?,?,?,?,?,?,?,?,?)`,
          [
            code,
            client.client_id,
            user.id,
            params.redirectUri,
            scope,
            params.codeChallenge,
            "S256",
            now + AUTH_CODE_TTL_SEC,
            0,
          ]
        );
        saveDb();

        const redirect = new URL(params.redirectUri);
        redirect.searchParams.set("code", code);
        if (state) redirect.searchParams.set("state", state);
        res.redirect(redirect.toString());
        return;
      }

      passportAuth.authenticate("google", {
        scope: ["openid", "email", "profile"],
        prompt: "select_account",
        accessType: "offline",
      })(req, res, () => {
        throw new ServerError("Google authentication failed");
      });
    },

    async challengeForAuthorizationCode(client, authorizationCode): Promise<string> {
      const db = getDb();
      const rows = db.exec(
        `SELECT client_id, code_challenge, code_challenge_method, expires_at, used
         FROM oauth_codes WHERE code = ?`,
        [authorizationCode]
      );

      if (!rows.length || !rows[0].values.length) {
        throw new InvalidGrantError("Invalid authorization code");
      }

      const [dbClientId, codeChallenge, method, expiresAt, used] = rows[0].values[0] as [
        string,
        string | null,
        string | null,
        number,
        number,
      ];

      if (dbClientId !== client.client_id) {
        throw new InvalidGrantError("Authorization code was issued to a different client");
      }
      if (used || Date.now() / 1000 > expiresAt) {
        throw new InvalidGrantError("Code expired or already used");
      }
      if (!codeChallenge || method !== "S256") {
        throw new InvalidGrantError("PKCE challenge missing on authorization code");
      }

      return codeChallenge;
    },

    async exchangeAuthorizationCode(client, authorizationCode, _codeVerifier, redirectUri): Promise<OAuthTokens> {
      const db = getDb();
      const rows = db.exec(
        `SELECT client_id, user_id, redirect_uri, scope, expires_at, used
         FROM oauth_codes WHERE code = ?`,
        [authorizationCode]
      );

      if (!rows.length || !rows[0].values.length) {
        throw new InvalidGrantError("Invalid authorization code");
      }

      const [dbClientId, userId, dbRedirectUri, scope, expiresAt, used] = rows[0].values[0] as [
        string,
        string,
        string,
        string | null,
        number,
        number,
      ];

      if (dbClientId !== client.client_id) {
        throw new InvalidGrantError("Authorization code was issued to a different client");
      }
      if (used || Date.now() / 1000 > expiresAt) {
        throw new InvalidGrantError("Code expired or already used");
      }
      if (redirectUri && dbRedirectUri !== redirectUri) {
        throw new InvalidGrantError("redirect_uri mismatch");
      }

      db.run("UPDATE oauth_codes SET used = 1 WHERE code = ?", [authorizationCode]);

      const jti = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const issuedScope = scope ?? DEFAULT_SCOPE;
      const accessToken = await createAccessToken(jti, client.client_id, userId);
      const refreshToken = randomUUID();
      const refreshExp = now + REFRESH_TOKEN_TTL_SEC;

      db.run(
        `INSERT INTO oauth_tokens (jti, client_id, user_id, scope, access_token_hash, refresh_token_hash, expires_at, refresh_token_expires_at, issued_at)
         VALUES (?,?,?,?,?,?,?,?,?)`,
        [
          jti,
          client.client_id,
          userId,
          issuedScope,
          hashToken(accessToken),
          hashToken(refreshToken),
          now + ACCESS_TOKEN_TTL_SEC,
          refreshExp,
          now,
        ]
      );
      saveDb();

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SEC,
        refresh_token: refreshToken,
        scope: issuedScope,
      };
    },

    async exchangeRefreshToken(client, refreshToken, scopes): Promise<OAuthTokens> {
      const db = getDb();
      const tokenRows = db.exec(
        `SELECT jti, user_id, scope, refresh_token_expires_at FROM oauth_tokens WHERE refresh_token_hash = ? AND client_id = ?`,
        [hashToken(refreshToken), client.client_id]
      );

      if (!tokenRows.length || !tokenRows[0].values.length) {
        throw new InvalidGrantError("Invalid refresh token");
      }

      const [oldJti, userId, existingScope, refreshTokenExpiresAt] = tokenRows[0].values[0] as [
        string,
        string,
        string | null,
        number,
      ];

      if (Date.now() / 1000 > refreshTokenExpiresAt) {
        throw new InvalidGrantError("Refresh token expired");
      }

      const existingScopes = (existingScope ?? DEFAULT_SCOPE).split(/\s+/).filter(Boolean);
      const requestedScopes = scopes?.filter(Boolean);
      if (requestedScopes?.length && !requestedScopes.every((scope) => existingScopes.includes(scope))) {
        throw new InvalidScopeError("Requested scope exceeds originally granted scope");
      }

      const issuedScope = requestedScopes?.length ? requestedScopes.join(" ") : existingScopes.join(" ");

      db.run("DELETE FROM oauth_tokens WHERE jti = ?", [oldJti]);

      const jti = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await createAccessToken(jti, client.client_id, userId);
      const newRefreshToken = randomUUID();
      const newRefreshExp = now + REFRESH_TOKEN_TTL_SEC;

      db.run(
        `INSERT INTO oauth_tokens (jti, client_id, user_id, scope, access_token_hash, refresh_token_hash, expires_at, refresh_token_expires_at, issued_at)
         VALUES (?,?,?,?,?,?,?,?,?)`,
        [
          jti,
          client.client_id,
          userId,
          issuedScope,
          hashToken(accessToken),
          hashToken(newRefreshToken),
          now + ACCESS_TOKEN_TTL_SEC,
          newRefreshExp,
          now,
        ]
      );
      saveDb();

      return {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SEC,
        refresh_token: newRefreshToken,
        scope: issuedScope,
      };
    },

    async verifyAccessToken(token: string): Promise<AuthInfo> {
      const payload = await verifyAccessToken(token);
      const jti = payload.jti as string | undefined;
      const userId = payload.sub as string | undefined;
      const clientId = payload.client_id as string | undefined;
      const exp = payload.exp as number | undefined;

      if (!jti || !userId || !clientId || !exp) {
        throw new InvalidTokenError("Token missing required claims");
      }

      const db = getDb();
      const rows = db.exec("SELECT scope, expires_at FROM oauth_tokens WHERE jti = ?", [jti]);
      if (!rows.length || !rows[0].values.length) {
        throw new InvalidTokenError("Token revoked or unknown");
      }

      const [scope, expiresAt] = rows[0].values[0] as [string | null, number];
      if (Date.now() / 1000 > expiresAt) {
        throw new InvalidTokenError("Token expired");
      }

      return {
        token,
        clientId,
        scopes: (scope ?? DEFAULT_SCOPE).split(/\s+/).filter(Boolean),
        expiresAt,
        extra: { userId, jti },
      };
    },

  };
}

async function createAccessToken(jti: string, clientId: string, userId: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new jose.SignJWT({ sub: userId, jti, client_id: clientId, aud: BASE })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_TTL_SEC)
    .setIssuer(BASE)
    .sign(JWT_SECRET);
}

async function resolveBearerAuth(authorization?: string): Promise<{ userId: string; jti: string } | null> {
  if (!authorization?.startsWith("Bearer ")) {
    return null;
  }

  const token = authorization.slice(7);
  const authInfo = await oauthProvider.verifyAccessToken(token);
  const userId = authInfo.extra?.userId;
  const jti = authInfo.extra?.jti;

  if (typeof userId !== "string" || typeof jti !== "string") {
    return null;
  }

  return { userId, jti };
}

function bearerTokenRevokeFallback(req: Request, res: Response, next: NextFunction) {
  if (!req.headers.authorization?.startsWith("Bearer ")) {
    next();
    return;
  }

  bearerAuth(req, res, () => {
    const auth = (req as Request & { authContext?: { jti: string } }).authContext;
    if (auth?.jti) {
      const db = getDb();
      db.run("DELETE FROM oauth_tokens WHERE jti = ?", [auth.jti]);
      saveDb();
    }
    next();
  });
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function normalizeBaseUrl(raw: string): string {
  let parsed: URL;
  if (raw.startsWith("/")) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(`BASE_URL must be absolute in production, received: ${raw}`);
    }
    parsed = new URL(raw, "http://localhost:3000");
  } else {
    try {
      parsed = new URL(raw);
    } catch {
      throw new Error(`BASE_URL must be an absolute URL, received: ${raw}`);
    }
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`BASE_URL must use http or https, received protocol: ${parsed.protocol}`);
  }
  if (process.env.NODE_ENV === "production" && parsed.protocol !== "https:") {
    throw new Error("BASE_URL must use HTTPS in production");
  }
  return parsed.toString().replace(/\/$/, "");
}

function parseScopes(raw: string | undefined, fallback: string[]): string[] {
  const parsed = raw?.split(/[,\s]+/).map((s) => s.trim()).filter(Boolean) ?? fallback;
  const deduped = Array.from(new Set(parsed));
  if (!deduped.includes(DEFAULT_SCOPE)) deduped.push(DEFAULT_SCOPE);
  return deduped;
}

function assertSecretStrength(name: string, value: string | undefined, minLength: number): void {
  if (!value) {
    throw new Error(`${name} env var is required`);
  }
  if (value.length < minLength) {
    throw new Error(`${name} must be at least ${minLength} characters long`);
  }
}
