import express from "express";
import cors from "cors";
import morgan from "morgan";
import { randomUUID } from "node:crypto";
import { initDb } from "./db.js";
import { createMcpServer } from "./mcp-server.js";
import { createAuthApp, requireBearerAuth } from "./auth-server.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

/**
 * HTTP entrypoint that hosts:
 * - OAuth metadata and token routes (mounted from auth-server.ts)
 * - Streamable HTTP MCP endpoint at /mcp
 *
 * Each MCP session gets its own transport instance keyed by `mcp-session-id`.
 */
const PORT = Number(process.env.MCP_PORT ?? 3000);
const BASE = normalizeBaseUrl(process.env.BASE_URL ?? `http://localhost:${PORT}`);
const CORS_ALLOWED_ORIGINS = resolveAllowedOrigins(process.env.CORS_ALLOWED_ORIGINS, BASE);

const transports: Map<string, StreamableHTTPServerTransport> = new Map();

async function main() {
  console.log("Initializing database...");
  await initDb();
  console.log("Database ready.");

  const app = express();
  app.set("trust proxy", 1);

  app.use(morgan("dev"));

  // Mount auth app first (brings in session, passport, and all auth routes)
  app.use(createAuthApp());

  app.use(
    cors({
      exposedHeaders: ["WWW-Authenticate", "Mcp-Session-Id", "Last-Event-Id", "Mcp-Protocol-Version"],
      credentials: false,
      origin: (origin, callback) => {
        if (!origin) {
          callback(null, true);
          return;
        }
        if (CORS_ALLOWED_ORIGINS.includes("*")) {
          callback(null, true);
          return;
        }
        if (CORS_ALLOWED_ORIGINS.includes(origin)) {
          callback(null, true);
          return;
        }
        callback(new Error("CORS origin denied"));
      },
    })
  );
  app.use(express.json());

  // Log 401s with client IP
  app.use((req, res, next) => {
    const originalSend = res.send;
    res.send = function (body) {
      if (res.statusCode === 401) {
        const clientIp = req.ip || req.socket.remoteAddress || "unknown";
        console.warn(`[401] ${req.method} ${req.path} - IP: ${clientIp} - Auth: ${req.headers.authorization ? "Bearer provided" : "No bearer"}`);
      }
      return originalSend.call(this, body);
    };
    next();
  });

  const mcpPostHandler = async (req: express.Request, res: express.Response) => {
    // Existing session: route request to the live transport.
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    if (sessionId && transports.has(sessionId)) {
      await transports.get(sessionId)!.handleRequest(req, res, req.body);
      return;
    }

    if (sessionId && !transports.has(sessionId)) {
      res.status(404).json({
        jsonrpc: "2.0",
        error: { code: -32001, message: "Session not found — please reinitialize" },
        id: null,
      });
      return;
    }

    if (!sessionId && isInitializeRequest(req.body)) {
      // New initialize request: create a transport and bind it to this session.
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid: string) => {
          console.log(`[MCP] Session initialized: ${sid}`);
          transports.set(sid, transport);
        },
      });

      transport.onclose = () => {
        const sid = transport.sessionId;
        if (sid) {
          console.log(`[MCP] Session closed: ${sid}`);
          transports.delete(sid);
        }
      };

      const server = createMcpServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
      return;
    }

    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Bad Request: No valid session ID provided" },
      id: null,
    });
  };

  const mcpSessionHandler = async (req: express.Request, res: express.Response) => {
    // GET/DELETE requests must target an existing MCP session.
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId) {
      res.status(400).send("Missing session ID");
      return;
    }
    if (!transports.has(sessionId)) {
      res.status(404).send("Session not found — please reinitialize");
      return;
    }
    await transports.get(sessionId)!.handleRequest(req, res);
  };

  app.post("/mcp", requireBearerAuth(), mcpPostHandler);
  app.get("/mcp", requireBearerAuth(), mcpSessionHandler);
  app.delete("/mcp", requireBearerAuth(), mcpSessionHandler);
  console.log("Auth: ENABLED (OAuth 2.1 Bearer token required)");

  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
    console.log(`  MCP endpoint:     ${BASE}/mcp`);
    console.log(`  Auth metadata:    ${BASE}/.well-known/oauth-authorization-server`);
    console.log(`  Resource metadata:${BASE}/.well-known/oauth-protected-resource`);
  });

  process.on("SIGINT", async () => {
    console.log("\nShutting down...");
    for (const [sid, transport] of transports) {
      await transport.close();
      transports.delete(sid);
    }
    process.exit(0);
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});

function normalizeBaseUrl(raw: string): string {
  // Supports absolute URL in all environments, and relative only in local development.
  let parsed: URL;
  if (raw.startsWith("/")) {
    if (process.env.NODE_ENV === "production") {
      throw new Error(`BASE_URL must be absolute in production, received: ${raw}`);
    }
    parsed = new URL(raw, `http://localhost:${PORT}`);
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

function resolveAllowedOrigins(raw: string | undefined, base: string): string[] {
  // If unset, allow same-origin only.
  if (!raw) {
    return [new URL(base).origin];
  }

  const values = raw
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);

  return Array.from(new Set(values.map((value) => {
    if (value === "*") return value;
    const parsed = new URL(value);
    return parsed.origin;
  })));
}
