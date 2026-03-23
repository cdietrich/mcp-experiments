// Force deterministic auth settings for tests so local/.env values do not leak in.
process.env.BASE_URL = "http://localhost:3000";
process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-chars";
process.env.SESSION_SECRET = "test-session-secret";
