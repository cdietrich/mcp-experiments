import { randomUUID } from "node:crypto";
import * as jose from "jose";
import request from "supertest";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

type DbModule = typeof import("../src/db.js");
type AuthModule = typeof import("../src/auth-server.js");

let dbModule: DbModule;
let authModule: AuthModule;
let app: ReturnType<AuthModule["createAuthApp"]>;

const created = {
  users: new Set<string>(),
  clients: new Set<string>(),
  codes: new Set<string>(),
  tokens: new Set<string>(),
};

function nowSec(): number {
  return Math.floor(Date.now() / 1000);
}

async function signAccessToken(jti: string, clientId: string, userId: string): Promise<string> {
  const now = nowSec();
  const secret = new TextEncoder().encode(process.env.JWT_SECRET!);
  const base = process.env.BASE_URL!;

  return new jose.SignJWT({ sub: userId, jti, client_id: clientId, aud: base })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .setIssuer(base)
    .sign(secret);
}

beforeAll(async () => {
  dbModule = await import("../src/db.js");
  await dbModule.initDb();
  authModule = await import("../src/auth-server.js");
  app = authModule.createAuthApp();
});

afterEach(() => {
  const db = dbModule.getDb();

  for (const jti of created.tokens) db.run("DELETE FROM oauth_tokens WHERE jti = ?", [jti]);
  for (const code of created.codes) db.run("DELETE FROM oauth_codes WHERE code = ?", [code]);
  for (const clientId of created.clients) db.run("DELETE FROM oauth_clients WHERE client_id = ?", [clientId]);
  for (const userId of created.users) db.run("DELETE FROM users WHERE id = ?", [userId]);

  created.tokens.clear();
  created.codes.clear();
  created.clients.clear();
  created.users.clear();
  dbModule.saveDb();
});

describe("auth server regressions", () => {
  it("advertises SDK-supported token endpoint auth methods", async () => {
    const response = await request(app).get("/.well-known/oauth-authorization-server").expect(200);
    expect(response.body.token_endpoint_auth_methods_supported).toEqual(["client_secret_post", "none"]);
  });

  it("registers public clients without issuing a client_secret", async () => {
    const response = await request(app)
      .post("/register")
      .send({
        client_name: "Test DCR Client",
        redirect_uris: ["https://client.example/callback"],
        token_endpoint_auth_method: "none",
      })
      .expect(201);

    expect(response.body.client_id).toBeTypeOf("string");
    expect(response.body.token_endpoint_auth_method).toBe("none");
    expect(response.body.client_secret).toBeUndefined();

    created.clients.add(response.body.client_id as string);
  });

  it("requires PKCE params on /authorize", async () => {
    const db = dbModule.getDb();
    const clientId = `test-client-${randomUUID()}`;
    const redirectUri = "https://client.example/callback";
    const now = nowSec();
    db.run(
      "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
      [clientId, null, "Authorize Test Client", JSON.stringify([redirectUri]), JSON.stringify(["authorization_code"]), now, now]
    );
    created.clients.add(clientId);
    dbModule.saveDb();

    const response = await request(app)
      .get("/authorize")
      .query({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
      })
      .expect(302);

    const redirect = new URL(response.headers.location as string);
    expect(redirect.searchParams.get("error")).toBe("invalid_request");
    expect(redirect.searchParams.get("error_description")).toContain("code_challenge");
  });

  it("rejects authorization codes that do not carry PKCE metadata", async () => {
    const db = dbModule.getDb();
    const userId = `test-user-${randomUUID()}`;
    const clientId = `test-client-${randomUUID()}`;
    const code = `test-code-${randomUUID()}`;
    const redirectUri = "https://client.example/callback";
    const now = nowSec();

    db.run("INSERT INTO users (id, google_id, email, name, picture, created_at) VALUES (?,?,?,?,?,?)", [
      userId,
      `google-${randomUUID()}`,
      `${randomUUID()}@example.com`,
      "PKCE Test User",
      null,
      now,
    ]);
    created.users.add(userId);

    db.run(
      "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
      [clientId, null, "Test Client", JSON.stringify([redirectUri]), JSON.stringify(["authorization_code"]), now, now]
    );
    created.clients.add(clientId);

    db.run(
      "INSERT INTO oauth_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used) VALUES (?,?,?,?,?,?,?,?,?)",
      [code, clientId, userId, redirectUri, "default", null, null, now + 300, 0]
    );
    created.codes.add(code);
    dbModule.saveDb();

    const response = await request(app)
      .post("/token")
      .send({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: redirectUri,
        code_verifier: "verifier-value",
      })
      .expect(400);

    expect(response.body.error).toBe("invalid_grant");
    expect(response.body.error_description).toContain("PKCE challenge missing");
  });

  it("invalidates revoked access tokens immediately", async () => {
    const db = dbModule.getDb();
    const userId = `test-user-${randomUUID()}`;
    const clientId = `test-client-${randomUUID()}`;
    const jti = `test-jti-${randomUUID()}`;
    const now = nowSec();

    db.run("INSERT INTO users (id, google_id, email, name, picture, created_at) VALUES (?,?,?,?,?,?)", [
      userId,
      `google-${randomUUID()}`,
      `${randomUUID()}@example.com`,
      "Revocation Test User",
      null,
      now,
    ]);
    created.users.add(userId);

    db.run(
      "INSERT INTO oauth_clients (client_id, client_secret_hash, client_name, redirect_uris, grant_types, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
      [clientId, null, "Test Client", JSON.stringify(["https://client.example/callback"]), JSON.stringify(["authorization_code"]), now, now]
    );
    created.clients.add(clientId);

    const token = await signAccessToken(jti, clientId, userId);
    db.run(
      "INSERT INTO oauth_tokens (jti, client_id, user_id, scope, access_token_hash, refresh_token_hash, expires_at, refresh_token_expires_at, issued_at) VALUES (?,?,?,?,?,?,?,?,?)",
      [jti, clientId, userId, "default", "not-used-by-validation", null, now + 3600, now + 86400, now]
    );
    created.tokens.add(jti);
    dbModule.saveDb();

    await request(app).get("/userinfo").set("Authorization", `Bearer ${token}`).expect(200);
    await request(app).post("/revoke").set("Authorization", `Bearer ${token}`).expect(200);
    await request(app).get("/userinfo").set("Authorization", `Bearer ${token}`).expect(401);
  });
});
