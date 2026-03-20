import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod/v4";
import { getDb } from "./db.js";
import type { CallToolResult, GetPromptResult, ReadResourceResult } from "@modelcontextprotocol/sdk/types.js";

export function createMcpServer(): McpServer {
  const server = new McpServer(
    {
      name: "erp-data-warehouse",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
        resources: {},
        prompts: {},
      },
    }
  );

  server.registerTool(
    "list_vendor_bills",
    {
      title: "List Vendor Bills",
      description:
        "Retrieve a list of vendor bills. Supports filtering by vendor name, status, and date range.",
      inputSchema: z.object({
        vendor_name: z.string().optional().describe("Partial match on vendor name"),
        status: z.enum(["OPEN", "PAID", "DRAFT", "CANCELLED"]).optional().describe("Bill status"),
        from_date: z.number().optional().describe("Unix timestamp — bills on or after this date"),
        to_date: z.number().optional().describe("Unix timestamp — bills on or before this date"),
        limit: z.number().default(50).describe("Maximum number of records to return"),
        offset: z.number().default(0).describe("Number of records to skip"),
      }),
    },
    async ({ vendor_name, status, from_date, to_date, limit, offset }): Promise<CallToolResult> => {
      const db = getDb();
      const conditions: string[] = [];
      const params: (string | number | null)[] = [];

      if (vendor_name) {
        conditions.push("vendor_name LIKE ?");
        params.push(`%${vendor_name}%`);
      }
      if (status) {
        conditions.push("status = ?");
        params.push(status);
      }
      if (from_date !== undefined) {
        conditions.push("bill_date >= ?");
        params.push(from_date);
      }
      if (to_date !== undefined) {
        conditions.push("bill_date <= ?");
        params.push(to_date);
      }

      const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const rows = db.exec(
        `SELECT id, vendor_name, bill_number, bill_date, due_date, total_amount, currency, status, description
         FROM vendor_bills ${where}
         ORDER BY bill_date DESC
         LIMIT ? OFFSET ?`,
        [...params, limit ?? 50, offset ?? 0]
      );

      if (!rows.length) {
        return { content: [{ type: "text", text: "No vendor bills found matching the criteria." }] };
      }

      const headers = rows[0].columns;
      const values = rows[0].values.map((r) =>
        Object.fromEntries(headers.map((h, i) => [h, r[i]]))
      );

      return {
        content: [{ type: "text", text: JSON.stringify(values, null, 2) }],
      };
    }
  );

  server.registerTool(
    "list_expense_reports",
    {
      title: "List Expense Reports",
      description:
        "Retrieve expense reports. Supports filtering by employee, status, and date range.",
      inputSchema: z.object({
        employee_name: z.string().optional().describe("Partial match on employee name"),
        status: z.enum(["DRAFT", "PENDING", "APPROVED", "REJECTED"]).optional().describe("Report status"),
        from_date: z.number().optional().describe("Unix timestamp — reports submitted on or after"),
        to_date: z.number().optional().describe("Unix timestamp — reports submitted on or before"),
        limit: z.number().default(50).describe("Maximum number of records"),
        offset: z.number().default(0).describe("Records to skip"),
      }),
    },
    async ({ employee_name, status, from_date, to_date, limit, offset }): Promise<CallToolResult> => {
      const db = getDb();
      const conditions: string[] = [];
      const params: (string | number | null)[] = [];

      if (employee_name) {
        conditions.push("employee_name LIKE ?");
        params.push(`%${employee_name}%`);
      }
      if (status) {
        conditions.push("status = ?");
        params.push(status);
      }
      if (from_date !== undefined) {
        conditions.push("submitted_date >= ?");
        params.push(from_date);
      }
      if (to_date !== undefined) {
        conditions.push("submitted_date <= ?");
        params.push(to_date);
      }

      const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const rows = db.exec(
        `SELECT id, employee_name, report_number, submitted_date, total_amount, currency, status, description, approval_date, approved_by
         FROM expense_reports ${where}
         ORDER BY submitted_date DESC
         LIMIT ? OFFSET ?`,
        [...params, limit ?? 50, offset ?? 0]
      );

      if (!rows.length) {
        return { content: [{ type: "text", text: "No expense reports found matching the criteria." }] };
      }

      const headers = rows[0].columns;
      const values = rows[0].values.map((r) =>
        Object.fromEntries(headers.map((h, i) => [h, r[i]]))
      );

      return {
        content: [{ type: "text", text: JSON.stringify(values, null, 2) }],
      };
    }
  );

  server.registerTool(
    "list_sales_orders",
    {
      title: "List Sales Orders",
      description:
        "Retrieve sales orders. Supports filtering by customer, status, and date range.",
      inputSchema: z.object({
        customer_name: z.string().optional().describe("Partial match on customer name"),
        status: z.enum(["PENDING", "PROCESSING", "SHIPPED", "DELIVERED", "CANCELLED"]).optional().describe("Order status"),
        from_date: z.number().optional().describe("Unix timestamp — orders on or after"),
        to_date: z.number().optional().describe("Unix timestamp — orders on or before"),
        limit: z.number().default(50).describe("Maximum number of records"),
        offset: z.number().default(0).describe("Records to skip"),
      }),
    },
    async ({ customer_name, status, from_date, to_date, limit, offset }): Promise<CallToolResult> => {
      const db = getDb();
      const conditions: string[] = [];
      const params: (string | number | null)[] = [];

      if (customer_name) {
        conditions.push("customer_name LIKE ?");
        params.push(`%${customer_name}%`);
      }
      if (status) {
        conditions.push("status = ?");
        params.push(status);
      }
      if (from_date !== undefined) {
        conditions.push("order_date >= ?");
        params.push(from_date);
      }
      if (to_date !== undefined) {
        conditions.push("order_date <= ?");
        params.push(to_date);
      }

      const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
      const rows = db.exec(
        `SELECT id, customer_name, order_number, order_date, ship_date, total_amount, currency, status, salesperson
         FROM sales_orders ${where}
         ORDER BY order_date DESC
         LIMIT ? OFFSET ?`,
        [...params, limit ?? 50, offset ?? 0]
      );

      if (!rows.length) {
        return { content: [{ type: "text", text: "No sales orders found matching the criteria." }] };
      }

      const headers = rows[0].columns;
      const values = rows[0].values.map((r) =>
        Object.fromEntries(headers.map((h, i) => [h, r[i]]))
      );

      return {
        content: [{ type: "text", text: JSON.stringify(values, null, 2) }],
      };
    }
  );

  server.registerTool(
    "get_record_detail",
    {
      title: "Get Record Detail",
      description: "Fetch a single record by its table and ID.",
      inputSchema: z.object({
        table: z.enum(["vendor_bills", "expense_reports", "sales_orders"]).describe("ERP table name"),
        id: z.string().describe("Record ID"),
      }),
    },
    async ({ table, id }): Promise<CallToolResult> => {
      const db = getDb();
      const queries = {
        vendor_bills: "SELECT * FROM vendor_bills WHERE id = ?",
        expense_reports: "SELECT * FROM expense_reports WHERE id = ?",
        sales_orders: "SELECT * FROM sales_orders WHERE id = ?",
      } as const;
      if (!(table in queries)) {
        return { content: [{ type: "text", text: `Unknown table: ${table}` }], isError: true };
      }
      const rows = db.exec(queries[table as keyof typeof queries], [id]);
      if (!rows.length || !rows[0].values.length) {
        return { content: [{ type: "text", text: `Record not found: ${id} in ${table}` }], isError: true };
      }
      const headers = rows[0].columns;
      const record = Object.fromEntries(headers.map((h, i) => [h, rows[0].values[0][i]]));
      return { content: [{ type: "text", text: JSON.stringify(record, null, 2) }] };
    }
  );

  server.registerResource(
    "vendor-bills-list",
    "erp://vendor-bills",
    {
      title: "Vendor Bills",
      description: "List of all vendor bills",
      mimeType: "application/json",
    },
    async (): Promise<ReadResourceResult> => {
      const db = getDb();
      const rows = db.exec(
        "SELECT id, vendor_name, bill_number, bill_date, due_date, total_amount, currency, status FROM vendor_bills ORDER BY bill_date DESC LIMIT 100"
      );
      const data = rows.length ? rows[0].values.map((r) =>
        Object.fromEntries(rows[0].columns.map((h, i) => [h, r[i]]))
      ) : [];
      return { contents: [{ uri: "erp://vendor-bills", text: JSON.stringify(data), mimeType: "application/json" }] };
    }
  );

  server.registerResource(
    "expense-reports-list",
    "erp://expense-reports",
    {
      title: "Expense Reports",
      description: "List of all expense reports",
      mimeType: "application/json",
    },
    async (): Promise<ReadResourceResult> => {
      const db = getDb();
      const rows = db.exec(
        "SELECT id, employee_name, report_number, submitted_date, total_amount, currency, status FROM expense_reports ORDER BY submitted_date DESC LIMIT 100"
      );
      const data = rows.length ? rows[0].values.map((r) =>
        Object.fromEntries(rows[0].columns.map((h, i) => [h, r[i]]))
      ) : [];
      return { contents: [{ uri: "erp://expense-reports", text: JSON.stringify(data), mimeType: "application/json" }] };
    }
  );

  server.registerResource(
    "sales-orders-list",
    "erp://sales-orders",
    {
      title: "Sales Orders",
      description: "List of all sales orders",
      mimeType: "application/json",
    },
    async (): Promise<ReadResourceResult> => {
      const db = getDb();
      const rows = db.exec(
        "SELECT id, customer_name, order_number, order_date, ship_date, total_amount, currency, status FROM sales_orders ORDER BY order_date DESC LIMIT 100"
      );
      const data = rows.length ? rows[0].values.map((r) =>
        Object.fromEntries(rows[0].columns.map((h, i) => [h, r[i]]))
      ) : [];
      return { contents: [{ uri: "erp://sales-orders", text: JSON.stringify(data), mimeType: "application/json" }] };
    }
  );

  server.registerPrompt(
    "summarize-expenses",
    {
      title: "Summarize Expenses",
      description: "Generate an expense summary prompt for the last N days",
      argsSchema: {
        days: z.number().default(30).describe("Number of days to look back"),
      },
    },
    async ({ days }): Promise<GetPromptResult> => {
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Please summarize the expense reports from the last ${days} days. Include total spend, number of reports, status breakdown, and any notable outliers.`,
            },
          },
        ],
      };
    }
  );

  return server;
}
