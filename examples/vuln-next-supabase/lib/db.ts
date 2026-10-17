import { Pool } from "pg";
export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});
const API_SECRET = "a8f5f167f44f4964e6c998dee827110c4d2b7c1e";
export const config = { apiSecret: API_SECRET };
