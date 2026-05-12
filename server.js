const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const TelegramBot = require('node-telegram-bot-api');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const telegramBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: true });

// Initialize database
async function initDB() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY, telegram_id VARCHAR(255) UNIQUE, username VARCHAR(255), hwid VARCHAR(255), license_key VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_active BOOLEAN DEFAULT true
  )`);
  
  await pool.query(`CREATE TABLE IF NOT EXISTS licenses (
    id SERIAL PRIMARY KEY, key VARCHAR(255) UNIQUE, hwid VARCHAR(255), telegram_id VARCHAR(255), duration_days INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP, is_active BOOLEAN DEFAULT true, hwid_bound BOOLEAN DEFAULT false
  )`);
  
  await pool.query(`CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY, telegram_id VARCHAR(255) UNIQUE, username VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
}

initDB();

// Routes
app.get('/api/health', (req, res) => res.json({ success: true }));

app.post('/api/license/validate', async (req, res) => {
  const { key } = req.body;
  const result = await pool.query('SELECT * FROM licenses WHERE key = $1 AND is_active = true', [key]);
  if (result.rows.length === 0) return res.json({ success: false, message: 'Invalid key' });
  const license = result.rows[0];
  if (new Date(license.expires_at) < new Date()) return res.json({ success: false, message: 'Expired' });
  res.json({ success: true, data: license });
});

app.post('/api/license/activate', async (req, res) => {
  const { key, hwid } = req.body;
  const result = await pool.query('SELECT * FROM licenses WHERE key = $1 AND is_active = true', [key]);
  if (result.rows.length === 0) return res.json({ success: false, message: 'Invalid key' });
  const license = result.rows[0];
  if (license.hwid_bound && license.hwid !== hwid) return res.json({ success: false, message: 'Already bound' });
  await pool.query('UPDATE licenses SET hwid = $1, hwid_bound = true WHERE key = $2', [hwid, key]);
  res.json({ success: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Server running'));
