import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  createMcpHandler,
  isLegacyRequest,
  WebStandardStreamableHTTPServerTransport,
  type McpHttpHandler,
} from "@modelcontextprotocol/server";
import { createMcpServer } from "../src/mcp-server.js";
import { initDb } from "../src/db.js";

/**
 * Protocol-era coverage:
 * - 2026-07-28 (modern): per-request stateless serving via `createMcpHandler`,
 *   the `_meta` envelope, `server/discover`, `resultType` and cache fields.
 * - 2025-era (legacy): sessionful `initialize` + `Mcp-Session-Id` handshake.
 * - `isLegacyRequest` is the routing predicate production uses, so it is
 *   asserted directly rather than through a copy of the routing logic.
 */

const MODERN_VERSION = "2026-07-28";
const MCP_URL = "http://localhost:3000/mcp";

function envelope(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    _meta: {
      "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
      "io.modelcontextprotocol/clientCapabilities": {},
    },
    ...extra,
  };
}

function modernRequest(
  method: string,
  params: Record<string, unknown> = {},
  id: number | string = 1
): Request {
  // 2026-07-28 HTTP binding: every modern request POST carries
  // MCP-Protocol-Version and Mcp-Method; methods mirroring params.name /
  // params.uri / params.taskId also carry Mcp-Name.
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": MODERN_VERSION,
    "mcp-method": method,
  };
  const name = params.name ?? params.uri ?? params.taskId;
  if (typeof name === "string") headers["mcp-name"] = name;

  return new Request(MCP_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: envelope(params),
    }),
  });
}

function legacyRequest(body: unknown, headers: Record<string, string> = {}): Request {
  return new Request(MCP_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...headers,
    },
    body: JSON.stringify(body),
  });
}

/** Read a JSON-RPC response from either a JSON body or an SSE stream. */
async function readMessage(response: Response): Promise<Record<string, any>> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("text/event-stream")) {
    const text = await response.text();
    const data = text
      .split("\n")
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice("data:".length).trim())
      .filter(Boolean)
      .pop();
    if (!data) throw new Error(`No SSE data frame in response: ${text}`);
    return JSON.parse(data);
  }
  return (await response.json()) as Record<string, any>;
}

describe("2026-07-28 modern era", () => {
  let handler: McpHttpHandler;

  beforeAll(async () => {
    await initDb();
    handler = createMcpHandler(() => createMcpServer(), { legacy: "reject" });
  });

  afterAll(async () => {
    await handler.close();
  });

  it("answers server/discover with the modern revision and cache hints", async () => {
    const response = await handler.fetch(modernRequest("server/discover"));
    expect(response.status).toBe(200);
    // Modern serving is stateless: no session is established.
    expect(response.headers.get("mcp-session-id")).toBeNull();

    const message = await readMessage(response);
    expect(message.error).toBeUndefined();
    expect(message.result.resultType).toBe("complete");
    expect(message.result.supportedVersions).toContain(MODERN_VERSION);
    expect(message.result.capabilities.tools).toBeDefined();
    expect(message.result.ttlMs).toBe(300_000);
    expect(message.result.cacheScope).toBe("private");
  });

  it("lists tools with resultType and configured cache hints", async () => {
    const response = await handler.fetch(modernRequest("tools/list"));
    expect(response.status).toBe(200);

    const message = await readMessage(response);
    expect(message.result.resultType).toBe("complete");
    expect(message.result.ttlMs).toBe(300_000);
    expect(message.result.cacheScope).toBe("private");

    const names = (message.result.tools as Array<{ name: string }>).map((tool) => tool.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "list_vendor_bills",
        "list_expense_reports",
        "list_sales_orders",
        "get_record_detail",
      ])
    );
  });

  it("calls a tool over the modern path", async () => {
    const response = await handler.fetch(
      modernRequest("tools/call", {
        name: "list_vendor_bills",
        arguments: { limit: 2 },
      })
    );
    expect(response.status).toBe(200);

    const message = await readMessage(response);
    expect(message.result.resultType).toBe("complete");
    expect(message.result.isError).not.toBe(true);
    expect(message.result.content[0].type).toBe("text");
    const rows = JSON.parse(message.result.content[0].text);
    expect(Array.isArray(rows)).toBe(true);
    expect(rows.length).toBeLessThanOrEqual(2);
  });

  it("rejects a legacy initialize handshake instead of serving it", async () => {
    const response = await handler.fetch(
      legacyRequest({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "legacy-test", version: "1.0.0" },
        },
      })
    );

    expect(response.status).toBe(400);
    const body = (await response.json()) as {
      error: { data?: { supported?: string[] } };
    };
    expect(body.error.data?.supported).toContain(MODERN_VERSION);
  });
});

describe("2025-era legacy serving", () => {
  it("initializes a session and serves tools/list on it", async () => {
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
    });
    const server = createMcpServer();
    await server.connect(transport);

    try {
      const initResponse = await transport.handleRequest(
        legacyRequest({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "legacy-test", version: "1.0.0" },
          },
        })
      );
      expect(initResponse.status).toBe(200);
      const sessionId = initResponse.headers.get("mcp-session-id");
      expect(sessionId).toBeTruthy();
      await initResponse.text();

      const initializedResponse = await transport.handleRequest(
        legacyRequest(
          { jsonrpc: "2.0", method: "notifications/initialized" },
          { "mcp-session-id": sessionId!, "mcp-protocol-version": "2025-11-25" }
        )
      );
      expect(initializedResponse.status).toBe(202);
      await initializedResponse.text();

      const listResponse = await transport.handleRequest(
        legacyRequest(
          { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
          { "mcp-session-id": sessionId!, "mcp-protocol-version": "2025-11-25" }
        )
      );
      expect(listResponse.status).toBe(200);
      const message = await readMessage(listResponse);
      expect(message.result.resultType).toBeUndefined();
      const names = (message.result.tools as Array<{ name: string }>).map((tool) => tool.name);
      expect(names).toContain("list_vendor_bills");
    } finally {
      await transport.close();
    }
  });
});

describe("isLegacyRequest routing", () => {
  it("classifies an envelope-less initialize as legacy", async () => {
    const request = legacyRequest({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-11-25",
        capabilities: {},
        clientInfo: { name: "legacy-test", version: "1.0.0" },
      },
    });
    expect(await isLegacyRequest(request)).toBe(true);
  });

  it("classifies an enveloped request as modern", async () => {
    expect(await isLegacyRequest(modernRequest("tools/list"))).toBe(false);
  });

  it("classifies a non-POST request as legacy (2025 session operations)", async () => {
    const request = new Request(MCP_URL, {
      method: "GET",
      headers: { accept: "text/event-stream" },
    });
    expect(await isLegacyRequest(request)).toBe(true);
  });
});
