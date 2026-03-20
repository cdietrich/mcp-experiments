import express from "express";
import cors from "cors";
import morgan from "morgan";
import { randomUUID } from "node:crypto";
import { initDb } from "./db.js";
import { createMcpServer } from "./mcp-server.js";
import { createAuthApp, requireBearerAuth } from "./auth-server.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";

const PORT = Number(process.env.MCP_PORT ?? 3000);
const BASE = process.env.BASE_URL ?? `http://localhost:${PORT}`;

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

  app.use(cors({
    exposedHeaders: ["WWW-Authenticate", "Mcp-Session-Id", "Last-Event-Id", "Mcp-Protocol-Version"],
    origin: "*",
  }));
  app.use(express.json());

  const mcpPostHandler = async (req: express.Request, res: express.Response) => {
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

  if (process.env.AUTH_ENABLED !== "false") {
    app.post("/mcp", requireBearerAuth(), mcpPostHandler);
    app.get("/mcp", requireBearerAuth(), mcpSessionHandler);
    app.delete("/mcp", requireBearerAuth(), mcpSessionHandler);
    console.log("Auth: ENABLED (OAuth 2.1 Bearer token required)");
  } else {
    app.post("/mcp", mcpPostHandler);
    app.get("/mcp", mcpSessionHandler);
    app.delete("/mcp", mcpSessionHandler);
    console.log("Auth: DISABLED");
  }

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
