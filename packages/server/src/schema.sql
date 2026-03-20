-- Users (populated on first Google OAuth login)
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  google_id TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  name TEXT,
  picture TEXT,
  created_at INTEGER NOT NULL
);

-- OAuth clients (Dynamic Client Registration)
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,          -- hashed; null for public clients
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,      -- JSON array
  grant_types TEXT NOT NULL,        -- JSON array
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Authorization codes (short-lived, one-time use)
CREATE TABLE IF NOT EXISTS oauth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT,
  code_challenge_method TEXT,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Access and refresh tokens
CREATE TABLE IF NOT EXISTS oauth_tokens (
  jti TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  scope TEXT,
  access_token_hash TEXT NOT NULL,
  refresh_token_hash TEXT,
  token_type TEXT NOT NULL DEFAULT 'Bearer',
  expires_at INTEGER NOT NULL,
  issued_at INTEGER NOT NULL,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ERP: Vendor Bills
CREATE TABLE IF NOT EXISTS vendor_bills (
  id TEXT PRIMARY KEY,
  vendor_id TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  bill_number TEXT NOT NULL,
  bill_date INTEGER NOT NULL,
  due_date INTEGER NOT NULL,
  total_amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'OPEN',
  description TEXT,
  created_at INTEGER NOT NULL
);

-- ERP: Expense Reports
CREATE TABLE IF NOT EXISTS expense_reports (
  id TEXT PRIMARY KEY,
  employee_id TEXT NOT NULL,
  employee_name TEXT NOT NULL,
  report_number TEXT NOT NULL,
  submitted_date INTEGER NOT NULL,
  total_amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'DRAFT',
  description TEXT,
  approval_date INTEGER,
  approved_by TEXT,
  created_at INTEGER NOT NULL
);

-- ERP: Sales Orders
CREATE TABLE IF NOT EXISTS sales_orders (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL,
  customer_name TEXT NOT NULL,
  order_number TEXT NOT NULL,
  order_date INTEGER NOT NULL,
  ship_date INTEGER,
  total_amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  status TEXT NOT NULL DEFAULT 'PENDING',
  salesperson TEXT,
  created_at INTEGER NOT NULL
);
