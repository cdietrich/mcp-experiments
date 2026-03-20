import initSqlJs, { type Database } from "sql.js";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import { mkdirSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, "..", "..", "data");
const DB_PATH = join(DATA_DIR, "erp.db");

let _db: Database | null = null;

export async function initDb(): Promise<Database> {
  if (_db) return _db;

  mkdirSync(DATA_DIR, { recursive: true });

  const SQL = await initSqlJs();

  if (existsSync(DB_PATH)) {
    _db = new SQL.Database(readFileSync(DB_PATH));
  } else {
    _db = new SQL.Database();
  }

  const schema = readFileSync(join(__dirname, "schema.sql"), "utf-8");
  _db.run(schema);

  // Migrations for existing databases
  try {
    _db.run("ALTER TABLE oauth_tokens ADD COLUMN refresh_token_expires_at INTEGER");
  } catch {
    // Column already exists
  }

  seedData(_db);

  saveDb();
  return _db;
}

export function getDb(): Database {
  if (!_db) throw new Error("Database not initialized — call initDb() first");
  return _db;
}

export function saveDb(): void {
  if (!_db) return;
  writeFileSync(DB_PATH, _db.export());
}

function seedData(db: Database): void {
  const now = Math.floor(Date.now() / 1000);

  const hasData = db.exec("SELECT COUNT(*) FROM vendor_bills")[0]?.values[0]?.[0];
  if (Number(hasData) > 0) return;

  const vendors = [
    ["vb-001", "v-101", "Acme Supplies", "BILL-2024-001", now - 86400 * 30, now - 86400 * 5, 1250.00, "USD", "OPEN", "Office supplies"],
    ["vb-002", "v-102", "TechParts Inc", "BILL-2024-002", now - 86400 * 20, now + 86400 * 10, 8750.50, "USD", "OPEN", "Server hardware"],
    ["vb-003", "v-103", "Global Logistics", "BILL-2024-003", now - 86400 * 45, now - 86400 * 15, 3200.00, "USD", "PAID", "Shipping Q4"],
    ["vb-004", "v-101", "Acme Supplies", "BILL-2024-004", now - 86400 * 10, now + 86400 * 20, 499.99, "USD", "OPEN", "Printer ink"],
    ["vb-005", "v-104", "CloudHosting Co", "BILL-2024-005", now - 86400 * 5, now + 86400 * 25, 2100.00, "USD", "DRAFT", "Monthly hosting"],
    ["vb-006", "v-105", "SafetyFirst Gear", "BILL-2024-006", now - 86400 * 60, now - 86400 * 30, 875.00, "USD", "PAID", "Safety equipment"],
  ];

  const expenses = [
    ["er-001", "emp-1", "Alice Johnson", "EXP-2024-001", now - 86400 * 7, 345.50, "USD", "APPROVED", "Client dinner", now - 86400 * 3, "Bob Manager"],
    ["er-002", "emp-2", "Charlie Davis", "EXP-2024-002", now - 86400 * 14, 1250.00, "USD", "PENDING", "Conference travel", null, null],
    ["er-003", "emp-3", "Diana Chen", "EXP-2024-003", now - 86400 * 3, 89.99, "USD", "APPROVED", "Software subscription", now - 86400 * 1, "Alice Johnson"],
    ["er-004", "emp-1", "Alice Johnson", "EXP-2024-004", now - 86400 * 21, 450.00, "USD", "REJECTED", "Team building event", null, null],
    ["er-005", "emp-4", "Evan Park", "EXP-2024-005", now - 86400 * 2, 2100.75, "USD", "APPROVED", "Equipment purchase", now - 86400 * 1, "Bob Manager"],
  ];

  const orders = [
    ["so-001", "cust-1", "Globex Corporation", "SO-2024-001", now - 86400 * 30, now - 86400 * 25, 15000.00, "USD", "SHIPPED", "Maria Santos"],
    ["so-002", "cust-2", "Initech Systems", "SO-2024-002", now - 86400 * 10, null, 3750.00, "USD", "PENDING", "Tom Wilson"],
    ["so-003", "cust-3", "Umbrella Corp", "SO-2024-003", now - 86400 * 5, null, 8999.99, "USD", "PROCESSING", "Maria Santos"],
    ["so-004", "cust-1", "Globex Corporation", "SO-2024-004", now - 86400 * 60, now - 86400 * 55, 4200.00, "USD", "DELIVERED", "Tom Wilson"],
    ["so-005", "cust-4", "Stark Industries", "SO-2024-005", now - 86400 * 1, null, 25000.00, "USD", "PENDING", "Diana Chen"],
  ];

  const insertBill = db.prepare(
    "INSERT INTO vendor_bills VALUES (?,?,?,?,?,?,?,?,?,?,?)"
  );
  for (const b of vendors) {
    insertBill.run([...b, now]);
  }
  insertBill.free();

  const insertExpense = db.prepare(
    "INSERT INTO expense_reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
  );
  for (const e of expenses) {
    insertExpense.run([...e, now]);
  }
  insertExpense.free();

  const insertOrder = db.prepare(
    "INSERT INTO sales_orders VALUES (?,?,?,?,?,?,?,?,?,?,?)"
  );
  for (const o of orders) {
    insertOrder.run([...o, now]);
  }
  insertOrder.free();
}
