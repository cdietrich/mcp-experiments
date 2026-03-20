import { randomUUID, createHash } from "crypto";
import * as jose from "jose";
import express, { type Request, type Response, type NextFunction } from "express";
import session from "express-session";
import passport from "passport";
import { getDb, saveDb } from "./db.js";
import { passport as passportAuth, setupGoogleStrategy } from "./google-strategy.js";

const BASE = process.env.BASE_URL ?? "http://localhost:3000";

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET ?? "dev-secret-change-in-production-min-32-chars"
);

const ACCESS_TOKEN_TTL_SEC = 3600;
const REFRESH_TOKEN_TTL_SEC = 604800;
const AUTH_CODE_TTL_SEC = 600;

export function createAuthApp(): express.Application {
  setupGoogleStrategy();
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(
    session({
      secret: process.env.SESSION_SECRET ?? "dev-session-secret-change-in-production",
      resave: false,
      saveUninitialized: false,
      cookie: { secure: false, httpOnly: true, maxAge: AUTH_CODE_TTL_SEC * 1000 },
    })
  );
  app.use(passportAuth.initialize());
  app.use(passportAuth.session());

  app.get("/.well-known/oauth-authorization-server", (_req, res) => {
    res.json({
      issuer: BASE,
      authorization_endpoint: `${BASE}/authorize`,
      token_endpoint: `${BASE}/token`,
      userinfo_endpoint: `${BASE}/userinfo`,
      registration_endpoint: `${BASE}/register`,
      scopes_supported: ["openid", "profile", "email", "default"],
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
      revocation_endpoint: `${BASE}/revoke`,
      service_documentation: `${BASE}/.well-known/oauth-protected-resource`,
    });
  });

  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({
      resource: BASE,
      authorization_servers: [BASE],
      scopes_supported: ["default"],
      bearer_methods_supported: ["header"],
    });
  });

  app.post("/register", (req, res) => {
    const {
      client_name,
      redirect_uris,
      grant_types = ["authorization_code"],
    } = req.body as {
      client_name?: string;
      redirect_uris?: string | string[];
      grant_types?: string[];
    };

    if (!client_name || !redirect_uris) {
      res.status(400).json({ error: "invalid_request", error_description: "client_name and redirect_uris are required" });
      return;
    }

    const uris = Array.isArray(redirect_uris) ? redirect_uris : [redirect_uris];
    const clientId = randomUUID();
    const clientSecret = randomUUID();

    const db = getDb();
    db.run(
      `INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        clientId,
        hashToken(clientSecret),
        client_name,
        JSON.stringify(uris),
        JSON.stringify(grant_types),
        Math.floor(Date.now() / 1000),
        Math.floor(Date.now() / 1000),
      ]
    );
    saveDb();

    res.json({
      client_id: clientId,
      client_secret: clientSecret,
      client_name,
      redirect_uris: uris,
      grant_types,
    });
  });

  app.get("/authorize", (req, res, next) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
    } = req.query as Record<string, string>;

    if (response_type !== "code") {
      res.status(400).json({ error: "unsupported_response_type" });
      return;
    }

    if (!client_id || !redirect_uri) {
      res.status(400).json({ error: "invalid_request" });
      return;
    }

    if (code_challenge_method && code_challenge_method !== "S256") {
      res.status(400).json({ error: "invalid_request", error_description: "code_challenge_method must be S256" });
      return;
    }

    (req.session as unknown as Record<string, unknown>).oauth = {
      clientId: client_id,
      redirectUri: redirect_uri,
      scope: scope ?? "default",
      state: state ?? null,
      codeChallenge: code_challenge ?? null,
      codeChallengeMethod: code_challenge_method ?? null,
    };

    passportAuth.authenticate("google", {
      scope: ["openid", "email", "profile"],
      prompt: "select_account",
      accessType: "offline",
    })(req, res, next);
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
        codeChallenge: string | null;
        codeChallengeMethod: string | null;
      } | undefined;

      if (!oauth) {
        res.redirect(`${BASE}/?error=session_expired`);
        return;
      }

      const db = getDb();
      const clientRows = db.exec(
        "SELECT redirect_uris FROM oauth_clients WHERE client_id = ?",
        [oauth.clientId]
      );
      if (!clientRows.length || !clientRows[0].values.length) {
        res.redirect(`${oauth.redirectUri}?error=invalid_client`);
        return;
      }

      const allowedUris: string[] = JSON.parse(clientRows[0].values[0][0] as string);
      if (!allowedUris.includes(oauth.redirectUri)) {
        res.redirect(`${oauth.redirectUri}?error=invalid_redirect_uri`);
        return;
      }

      const user = req.user as { id: string };
      const code = randomUUID();
      const now = Math.floor(Date.now() / 1000);

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
          oauth.codeChallengeMethod,
          now + AUTH_CODE_TTL_SEC,
          0,
        ]
      );
      saveDb();

      const params = new URLSearchParams({ code });
      if (oauth.state) params.set("state", oauth.state);
      res.redirect(`${oauth.redirectUri}?${params.toString()}`);
    }
  );

  app.post("/token", async (req: Request, res: Response) => {
    const {
      grant_type,
      code,
      client_id,
      client_secret,
      redirect_uri,
      code_verifier,
      refresh_token,
    } = req.body as Record<string, string | undefined>;

    const db = getDb();

    if (grant_type === "authorization_code") {
      if (!code || !client_id || !redirect_uri) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }

      const codeRows = db.exec(
        `SELECT client_id, user_id, redirect_uri, code_challenge, code_challenge_method, expires_at, used
         FROM oauth_codes WHERE code = ?`,
        [code]
      );

      if (!codeRows.length || !codeRows[0].values.length) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }

      const row = codeRows[0].values[0];
      const [dbClientId, userId, dbRedirectUri, dbCodeChallenge, dbCodeChallengeMethod, expiresAt, used] = row as [
        string, string, string, string | null, string | null, number, number
      ];

      if (used || Date.now() / 1000 > expiresAt) {
        res.status(400).json({ error: "invalid_grant", error_description: "Code expired or already used" });
        return;
      }
      if (dbClientId !== client_id) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
      if (dbRedirectUri !== redirect_uri) {
        res.status(400).json({ error: "invalid_grant", error_description: "redirect_uri mismatch" });
        return;
      }

      if (dbCodeChallenge && dbCodeChallengeMethod === "S256") {
        if (!code_verifier) {
          res.status(400).json({ error: "invalid_request", error_description: "code_verifier required for PKCE" });
          return;
        }
        const expected = base64urlEncode(createHash("sha256").update(code_verifier).digest());
        if (expected !== dbCodeChallenge) {
          res.status(400).json({ error: "invalid_grant", error_description: "code_verifier mismatch" });
          return;
        }
      }

      db.run("UPDATE oauth_codes SET used = 1 WHERE code = ?", [code]);

      const jti = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await createAccessToken(jti, client_id, userId);
      const refreshToken = randomUUID();
      const refreshExp = now + REFRESH_TOKEN_TTL_SEC;

      db.run(
        `INSERT INTO oauth_tokens (jti, client_id, user_id, scope, access_token_hash, refresh_token_hash, expires_at, issued_at)
         VALUES (?,?,?,?,?,?,?,?)`,
        [jti, client_id, userId, "default", hashToken(accessToken), hashToken(refreshToken), now + ACCESS_TOKEN_TTL_SEC, now]
      );
      saveDb();

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SEC,
        refresh_token: refreshToken,
        scope: "default",
      });
      return;
    }

    if (grant_type === "refresh_token") {
      if (!refresh_token || !client_id) {
        res.status(400).json({ error: "invalid_request" });
        return;
      }
      const refreshHash = hashToken(refresh_token);
      const tokenRows = db.exec(
        `SELECT jti, user_id FROM oauth_tokens WHERE refresh_token_hash = ? AND client_id = ?`,
        [refreshHash, client_id]
      );
      if (!tokenRows.length || !tokenRows[0].values.length) {
        res.status(400).json({ error: "invalid_grant" });
        return;
      }
      const [oldJti, userId] = tokenRows[0].values[0] as [string, string];

      db.run("DELETE FROM oauth_tokens WHERE jti = ?", [oldJti]);

      const jti = randomUUID();
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await createAccessToken(jti, client_id, userId);
      const newRefreshToken = randomUUID();

      db.run(
        `INSERT INTO oauth_tokens (jti, client_id, user_id, scope, access_token_hash, refresh_token_hash, expires_at, issued_at)
         VALUES (?,?,?,?,?,?,?,?)`,
        [jti, client_id, userId, "default", hashToken(accessToken), hashToken(newRefreshToken), now + ACCESS_TOKEN_TTL_SEC, now]
      );
      saveDb();

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL_SEC,
        refresh_token: newRefreshToken,
        scope: "default",
      });
      return;
    }

    res.status(400).json({ error: "unsupported_grant_type" });
  });

  app.get("/userinfo", bearerAuth, async (req: Request, res: Response) => {
    const auth = (req as Request & { auth?: { userId: string } }).auth;
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

  app.post("/revoke", bearerAuth, (req: Request, res: Response) => {
    const auth = (req as Request & { auth?: { jti: string } }).auth;
    if (auth?.jti) {
      const db = getDb();
      db.run("DELETE FROM oauth_tokens WHERE jti = ?", [auth.jti]);
      saveDb();
    }
    res.json({});
  });

  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  return app;
}

export function bearerAuth(req: Request, _res: Response, next: NextFunction) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    (req as Request & { auth?: null }).auth = null;
    next();
    return;
  }

  const token = auth.slice(7);
  verifyAccessToken(token)
    .then((payload) => {
      (req as Request & { auth?: { userId: string; jti: string } }).auth = {
        userId: payload.sub as string,
        jti: payload.jti as string,
      };
      next();
    })
    .catch(() => {
      (req as Request & { auth?: null }).auth = null;
      next();
    });
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

export async function verifyAccessToken(token: string): Promise<jose.JWTPayload> {
  const { payload } = await jose.jwtVerify(token, JWT_SECRET, {
    issuer: BASE,
    audience: BASE,
  });
  return payload;
}

export function requireBearerAuth(requiredScopes: string[] = []) {
  return (req: Request, res: Response, next: NextFunction) => {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
      res.setHeader("WWW-Authenticate", `Bearer realm="${BASE}", authorization-server="${BASE}/.well-known/oauth-authorization-server"`);
      res.status(401).json({
        error: " unauthorized",
        error_description: "Bearer token required",
      });
      return;
    }
    verifyAccessToken(auth.slice(7))
      .then((payload) => {
        (req as Request & { auth?: { userId: string; jti: string } }).auth = {
          userId: payload.sub as string,
          jti: payload.jti as string,
        };
        next();
      })
      .catch(() => {
        res.setHeader("WWW-Authenticate", `Bearer realm="${BASE}", authorization-server="${BASE}/.well-known/oauth-authorization-server"`);
        res.status(401).json({ error: "invalid_token" });
      });
  };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function base64urlEncode(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
