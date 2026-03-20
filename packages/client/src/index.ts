import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  ListToolsResultSchema,
  CallToolResultSchema,
  type ListToolsResult,
} from "@modelcontextprotocol/sdk/types.js";

const MCP_BASE_URL = process.env.MCP_BASE_URL ?? "http://localhost:3000";

async function main() {
  console.log(`Connecting to MCP server at ${MCP_BASE_URL}/mcp ...`);

  const transport = new StreamableHTTPClientTransport(new URL(`${MCP_BASE_URL}/mcp`));
  const client = new Client({ name: "erp-client", version: "1.0.0" });

  await client.connect(transport);
  console.log("Connected!\n");

  const tools = await client.request({ method: "tools/list" }, ListToolsResultSchema);
  console.log("Available tools:");
  for (const tool of (tools as ListToolsResult).tools ?? []) {
    console.log(`  - ${tool.name}: ${tool.description}`);
  }

  console.log("\n--- Calling list_vendor_bills ---");
  const bills = await client.request(
    { method: "tools/call", params: { name: "list_vendor_bills", arguments: { limit: 3 } } },
    CallToolResultSchema
  );
  console.log(JSON.stringify(bills, null, 2));

  console.log("\n--- Calling list_expense_reports ---");
  const expenses = await client.request(
    { method: "tools/call", params: { name: "list_expense_reports", arguments: {} } },
    CallToolResultSchema
  );
  console.log(JSON.stringify(expenses, null, 2));

  console.log("\n--- Calling list_sales_orders ---");
  const orders = await client.request(
    { method: "tools/call", params: { name: "list_sales_orders", arguments: {} } },
    CallToolResultSchema
  );
  console.log(JSON.stringify(orders, null, 2));

  await client.close();
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
