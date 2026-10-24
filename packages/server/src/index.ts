import express from "express";
import cors from "cors";
import morgan from "morgan";
import { randomUUID } from "node:crypto";
import { initDb } from "./db.js";
import { createMcpServer } from "./mcp-server.js";
import { createAuthApp, requireBearerAuth } from "./auth-server.js";
import { createMcpHandler, isInitializeRequest, isLegacyRequest } from "@modelcontextprotocol/server";
import {
  NodeStreamableHTTPServerTransport,
  toNodeHandler,
  toWebRequest,
} from "@modelcontextprotocol/node";

/**
 * HTTP entrypoint that hosts:
 * - OAuth metadata and token routes (mounted from auth-server.ts)
 * - Streamable HTTP MCP endpoint at /mcp
 *
 * Serves both protocol eras:
 * - 2025-era (sessionful): `initialize` + `Mcp-Session-Id`, one transport per
 *   session, for clients that predate the 2026-07-28 revision.
 * - 2026-07-28 (modern): stateless per-request serving via `createMcpHandler`,
 *   with the `_meta` request envelope and `server/discover`.
 *
 * `isLegacyRequest` runs the SDK's own classification, so the two legs can
 * never disagree about which era a request belongs to.
 */
const PORT = Number(process.env.MCP_PORT ?? 3000);
const BASE = normalizeBaseUrl(process.env.BASE_URL ?? `http://localhost:${PORT}`);
const CORS_ALLOWED_ORIGINS = resolveAllowedOrigins(process.env.CORS_ALLOWED_ORIGINS, BASE);

const transports: Map<string, NodeStreamableHTTPServerTransport> = new Map();

// Simulate a slow tools/list response. Set MCP_SLOW_TOOLS_LIST_MS to enable (e.g. 60000).
const SLOW_TOOLS_LIST_MS = process.env.MCP_SLOW_TOOLS_LIST_MS
  ? Number(process.env.MCP_SLOW_TOOLS_LIST_MS)
  : 0;
let slowToolsListDone = false;

async function maybeSlowToolsList(req: express.Request): Promise<void> {
  if (!SLOW_TOOLS_LIST_MS || slowToolsListDone || req.body?.method !== "tools/list") return;
  slowToolsListDone = true;
  console.log(`[MCP] Simulating slow tools/list — delaying ${SLOW_TOOLS_LIST_MS}ms`);
  await new Promise((resolve) => setTimeout(resolve, SLOW_TOOLS_LIST_MS));
  console.log(`[MCP] Slow tools/list delay complete`);
}

// Simulate slow MCP startup: non-probe MCP requests return 503 Retry-After for 60s after first hit.
// initialize, ping (2025-era), and server/discover (2026-07-28) are probes and pass through.
const MCP_PROBE_METHODS = new Set(["initialize", "ping", "server/discover"]);
let mcpStartupReady = false;
let mcpStartupTimerStarted = false;

function simulateSlowStartup(req: express.Request, res: express.Response): boolean {
  const method = req.body?.method as string | undefined;
  if (mcpStartupReady || !method || MCP_PROBE_METHODS.has(method)) return false;
  if (!mcpStartupTimerStarted) {
    mcpStartupTimerStarted = true;
    console.log("[MCP] Simulating slow startup — server will be ready in 60s");
    setTimeout(() => {
      mcpStartupReady = true;
      console.log("[MCP] Startup complete, accepting requests");
    }, 60_000);
  }
  console.log(`[MCP] Not ready yet, rejecting '${method}' with 503 Retry-After: 60`);
  res.status(503).set("Retry-After", "60").json({
    jsonrpc: "2.0",
    error: {
      code: -32000,
      message: "Server is warming up, please retry in 60 seconds.",
      data: { type: "warming_up", retryable: true, retry_after_ms: 60_000 },
    },
    id: req.body?.id ?? null,
  });
  return true;
}

async function main() {
  console.log("Initializing database...");
  await initDb();
  console.log("Database ready.");

  // Modern (2026-07-28) leg: stateless, one server instance per request.
  // `legacy: "reject"` because 2025-era traffic is routed to the sessionful
  // transport in user land below.
  const modernHandler = createMcpHandler(() => createMcpServer(), {
    legacy: "reject",
    onerror: (error) => console.error("[MCP] Modern handler error:", error),
  });
  const modernNodeHandler = toNodeHandler(modernHandler, {
    onerror: (error) => console.error("[MCP] Modern adapter error:", error),
  });

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

  const legacyPostHandler = async (req: express.Request, res: express.Response) => {
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
      const transport = new NodeStreamableHTTPServerTransport({
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

  const legacySessionHandler = async (req: express.Request, res: express.Response) => {
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

  const legacyHandler = async (req: express.Request, res: express.Response) => {
    if (req.method === "POST") {
      await legacyPostHandler(req, res);
      return;
    }
    if (req.method === "GET" || req.method === "DELETE") {
      await legacySessionHandler(req, res);
      return;
    }
    res.status(405).set("Allow", "GET, POST, DELETE").json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  };

  app.all("/mcp", requireBearerAuth(), async (req, res, next) => {
    try {
      //if (simulateSlowStartup(req, res)) return;

      if (req.method === "POST") {
        await maybeSlowToolsList(req);
      }

      // Behind express.json() the Node stream is drained, so build the probe
      // from the parsed body and hand the same value to the classifier.
      const probe = await toWebRequest(req, req.body);
      const legacy = await isLegacyRequest(probe, req.body);

      if (legacy) {
        await legacyHandler(req, res);
        return;
      }

      // `toNodeHandler` forwards `req.auth` (set by requireBearerAuth) as the
      // handler's authInfo, so both eras see the same verified token.
      await modernNodeHandler(req, res, req.body);
    } catch (error) {
      if ((error as { status?: number }).status === 413) {
        res.status(413).json({
          jsonrpc: "2.0",
          error: { code: -32600, message: "Request body too large" },
          id: null,
        });
        return;
      }
      next(error);
    }
  });
  console.log("Auth: ENABLED (OAuth 2.1 Bearer token required)");
  console.log("MCP eras: 2025-era sessionful + 2026-07-28 stateless");

  const httpServer = app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
    console.log(`  MCP endpoint:     ${BASE}/mcp`);
    console.log(`  Auth metadata:    ${BASE}/.well-known/oauth-authorization-server`);
    console.log(`  Resource metadata:${BASE}/.well-known/oauth-protected-resource`);
  });

  const shutdown = async () => {
    console.log("\nShutting down...");
    httpServer.close();
    for (const [sid, transport] of transports) {
      await transport.close();
      transports.delete(sid);
    }
    await modernHandler.close();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
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
