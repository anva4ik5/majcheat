const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const TelegramBot = require('node-telegram-bot-api');
const crypto = require('crypto');
const https = require('https');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();

// CORS for production - allow all origins (cheat clients connect from various IPs)
// In production Railway, this is fine since API is protected by API_SECRET_KEY
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));

app.use(express.json());

// Logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${req.method} ${req.path} - ${req.ip}`);
  next();
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const telegramBot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { polling: false });

// Generate license key
function generateLicenseKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = '';
  for (let i = 0; i < 16; i++) {
    if (i > 0 && i % 4 === 0) key += '-';
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

// Check if user is admin
async function isAdmin(telegramId) {
  try {
    const result = await pool.query('SELECT * FROM admins WHERE telegram_id = $1', [telegramId]);
    return result.rows.length > 0;
  } catch (err) {
    console.error('Admin check error:', err);
    return false;
  }
}

// Initialize database
async function initDB() {
  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      telegram_id VARCHAR(255) UNIQUE,
      username VARCHAR(255),
      login VARCHAR(64) UNIQUE,
      password_hash VARCHAR(255),
      hwid VARCHAR(255),
      license_key VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      is_active BOOLEAN DEFAULT true
    )`);

    // Migrations for legacy schema
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS login VARCHAR(64) UNIQUE`);
    await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255)`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY, key VARCHAR(255) UNIQUE, hwid VARCHAR(255), telegram_id VARCHAR(255), duration_days INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP, is_active BOOLEAN DEFAULT true, hwid_bound BOOLEAN DEFAULT false
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY, telegram_id VARCHAR(255) UNIQUE, username VARCHAR(255), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    await pool.query(`CREATE TABLE IF NOT EXISTS logs (
      id SERIAL PRIMARY KEY, telegram_id VARCHAR(255), action VARCHAR(255), details TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Two-step auth sessions: register/login confirmation via Telegram code
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_sessions (
      id SERIAL PRIMARY KEY,
      session_id VARCHAR(64) UNIQUE,
      type VARCHAR(16),
      login VARCHAR(64),
      password_hash VARCHAR(255),
      telegram_id VARCHAR(255),
      hwid VARCHAR(255),
      code VARCHAR(8),
      verified BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP
    )`);

    // Auth tokens for client sessions
    await pool.query(`CREATE TABLE IF NOT EXISTS auth_tokens (
      id SERIAL PRIMARY KEY,
      token VARCHAR(255) UNIQUE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      hwid VARCHAR(255),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP
    )`);
    
    console.log('Database initialized successfully');
  } catch (err) {
    console.error('Database initialization error:', err);
    process.exit(1);
  }
}

initDB().then(() => {
  console.log('Server ready');
}).catch(err => {
  console.error('Failed to initialize:', err);
});

// Error handler helper
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Auth middleware
async function authMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }
  next();
}

// ========== API ROUTES ==========

app.get('/api/health', (req, res) => {
  res.json({ success: true, timestamp: new Date().toISOString() });
});

// ========== AUTH HELPERS ==========

function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function isValidLogin(login) {
  return /^[a-zA-Z0-9_]{3,32}$/.test(login);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6 && password.length <= 64;
}

// Notify user via Telegram with code
async function notifyTelegram(telegramId, message) {
  try {
    await telegramBot.sendMessage(telegramId, message, { parse_mode: 'HTML' });
    return true;
  } catch (err) {
    console.error('Telegram notify error:', err.message);
    return false;
  }
}

// ========== AUTH ENDPOINTS ==========

// Step 1 of registration: client sends login/password/telegram_id, gets session_id, bot sends code
app.post('/api/auth/register/start', authMiddleware, asyncHandler(async (req, res) => {
  const { login, password, telegram_id, hwid } = req.body;
  
  if (!isValidLogin(login)) {
    return res.status(400).json({ success: false, message: 'Invalid login (3-32 chars, a-z, 0-9, _)' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ success: false, message: 'Password must be 6-64 chars' });
  }
  if (!telegram_id || !/^\d+$/.test(telegram_id.toString())) {
    return res.status(400).json({ success: false, message: 'Invalid telegram_id' });
  }
  if (!hwid) {
    return res.status(400).json({ success: false, message: 'HWID required' });
  }
  
  // Check login uniqueness
  const exists = await pool.query('SELECT id FROM users WHERE login = $1', [login]);
  if (exists.rows.length > 0) {
    return res.json({ success: false, message: 'Login already taken' });
  }
  
  // Check telegram_id not already linked
  const tgExists = await pool.query('SELECT id FROM users WHERE telegram_id = $1 AND login IS NOT NULL', [telegram_id.toString()]);
  if (tgExists.rows.length > 0) {
    return res.json({ success: false, message: 'Telegram already registered' });
  }
  
  const sessionId = uuidv4();
  const code = generateCode();
  const passwordHash = await bcrypt.hash(password, 10);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
  
  await pool.query(
    `INSERT INTO auth_sessions (session_id, type, login, password_hash, telegram_id, hwid, code, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [sessionId, 'register', login, passwordHash, telegram_id.toString(), hwid, code, expiresAt]
  );
  
  const sent = await notifyTelegram(telegram_id, 
    `🔐 <b>Регистрация</b>\n\nКод подтверждения: <code>${code}</code>\n\nВведите его в клиенте.\nКод действует 10 минут.\n\nЛогин: <code>${login}</code>`);
  
  if (!sent) {
    return res.json({ 
      success: false, 
      message: 'Не удалось отправить код в Telegram. Сначала запустите бота: /start' 
    });
  }
  
  res.json({ success: true, session_id: sessionId, message: 'Code sent to Telegram' });
}));

// Step 2 of registration: confirm code
app.post('/api/auth/register/confirm', authMiddleware, asyncHandler(async (req, res) => {
  const { session_id, code } = req.body;
  
  if (!session_id || !code) {
    return res.status(400).json({ success: false, message: 'session_id and code required' });
  }
  
  const result = await pool.query(
    `SELECT * FROM auth_sessions WHERE session_id = $1 AND type = 'register' AND verified = false`,
    [session_id]
  );
  if (result.rows.length === 0) {
    return res.json({ success: false, message: 'Invalid or expired session' });
  }
  
  const session = result.rows[0];
  if (new Date(session.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Code expired' });
  }
  if (session.code !== code.toString()) {
    return res.json({ success: false, message: 'Invalid code' });
  }
  
  // Create user
  const insertRes = await pool.query(
    `INSERT INTO users (login, password_hash, telegram_id, hwid, is_active)
     VALUES ($1, $2, $3, $4, true)
     ON CONFLICT (telegram_id) DO UPDATE SET login = $1, password_hash = $2, hwid = $4
     RETURNING id`,
    [session.login, session.password_hash, session.telegram_id, session.hwid]
  );
  
  await pool.query('UPDATE auth_sessions SET verified = true WHERE session_id = $1', [session_id]);
  
  // Generate auth token
  const token = generateToken();
  const tokenExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  await pool.query(
    'INSERT INTO auth_tokens (token, user_id, hwid, expires_at) VALUES ($1, $2, $3, $4)',
    [token, insertRes.rows[0].id, session.hwid, tokenExpires]
  );
  
  await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)',
    [session.telegram_id, 'REGISTER', `Login: ${session.login}`]);
  
  res.json({ 
    success: true, 
    token, 
    user: { id: insertRes.rows[0].id, login: session.login, telegram_id: session.telegram_id }
  });
}));

// Login: verify credentials, optionally send Telegram code for new HWID
app.post('/api/auth/login', authMiddleware, asyncHandler(async (req, res) => {
  const { login, password, hwid } = req.body;
  
  if (!login || !password || !hwid) {
    return res.status(400).json({ success: false, message: 'login, password, hwid required' });
  }
  
  const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
  if (result.rows.length === 0) {
    return res.json({ success: false, message: 'Invalid credentials' });
  }
  
  const user = result.rows[0];
  if (!user.is_active) {
    return res.json({ success: false, message: 'Account banned' });
  }
  if (!user.password_hash) {
    return res.json({ success: false, message: 'Account not registered properly' });
  }
  
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.json({ success: false, message: 'Invalid credentials' });
  }
  
  // If HWID matches OR no HWID set yet → direct login
  if (!user.hwid || user.hwid === hwid) {
    if (!user.hwid) {
      await pool.query('UPDATE users SET hwid = $1 WHERE id = $2', [hwid, user.id]);
    }
    const token = generateToken();
    const tokenExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO auth_tokens (token, user_id, hwid, expires_at) VALUES ($1, $2, $3, $4)',
      [token, user.id, hwid, tokenExpires]
    );
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)',
      [user.telegram_id, 'LOGIN', `Login: ${login}`]);
    return res.json({ 
      success: true, 
      token,
      user: { id: user.id, login: user.login, telegram_id: user.telegram_id }
    });
  }
  
  // HWID mismatch → require Telegram confirmation
  const sessionId = uuidv4();
  const code = generateCode();
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  
  await pool.query(
    `INSERT INTO auth_sessions (session_id, type, login, telegram_id, hwid, code, expires_at)
     VALUES ($1, 'login_2fa', $2, $3, $4, $5, $6)`,
    [sessionId, login, user.telegram_id, hwid, code, expiresAt]
  );
  
  await notifyTelegram(user.telegram_id,
    `⚠️ <b>Вход с нового устройства</b>\n\nКод: <code>${code}</code>\n\nЕсли это не вы — проигнорируйте.`);
  
  res.json({ 
    success: true, 
    require_2fa: true, 
    session_id: sessionId,
    message: 'Code sent to Telegram for new device'
  });
}));

// Confirm login from new device
app.post('/api/auth/login/confirm', authMiddleware, asyncHandler(async (req, res) => {
  const { session_id, code } = req.body;
  
  if (!session_id || !code) {
    return res.status(400).json({ success: false, message: 'session_id and code required' });
  }
  
  const result = await pool.query(
    `SELECT * FROM auth_sessions WHERE session_id = $1 AND type = 'login_2fa' AND verified = false`,
    [session_id]
  );
  if (result.rows.length === 0) {
    return res.json({ success: false, message: 'Invalid session' });
  }
  
  const session = result.rows[0];
  if (new Date(session.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Code expired' });
  }
  if (session.code !== code.toString()) {
    return res.json({ success: false, message: 'Invalid code' });
  }
  
  const userRes = await pool.query('SELECT * FROM users WHERE login = $1', [session.login]);
  if (userRes.rows.length === 0) {
    return res.json({ success: false, message: 'User not found' });
  }
  const user = userRes.rows[0];
  
  // Update HWID to new device
  await pool.query('UPDATE users SET hwid = $1 WHERE id = $2', [session.hwid, user.id]);
  await pool.query('UPDATE auth_sessions SET verified = true WHERE session_id = $1', [session_id]);
  
  const token = generateToken();
  const tokenExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await pool.query(
    'INSERT INTO auth_tokens (token, user_id, hwid, expires_at) VALUES ($1, $2, $3, $4)',
    [token, user.id, session.hwid, tokenExpires]
  );
  
  await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)',
    [user.telegram_id, 'LOGIN_2FA', `New HWID for ${session.login}`]);
  
  res.json({ 
    success: true, 
    token,
    user: { id: user.id, login: user.login, telegram_id: user.telegram_id }
  });
}));

// Verify token (used by client on launch)
app.post('/api/auth/verify', authMiddleware, asyncHandler(async (req, res) => {
  const { token, hwid } = req.body;
  
  if (!token) {
    return res.status(400).json({ success: false, message: 'Token required' });
  }
  
  const result = await pool.query(
    `SELECT t.*, u.login, u.telegram_id, u.is_active
     FROM auth_tokens t JOIN users u ON t.user_id = u.id
     WHERE t.token = $1`, [token]
  );
  
  if (result.rows.length === 0) {
    return res.json({ success: false, message: 'Invalid token' });
  }
  
  const row = result.rows[0];
  if (new Date(row.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Token expired' });
  }
  if (!row.is_active) {
    return res.json({ success: false, message: 'Account banned' });
  }
  if (hwid && row.hwid !== hwid) {
    return res.json({ success: false, message: 'HWID mismatch' });
  }
  
  res.json({ 
    success: true, 
    user: { login: row.login, telegram_id: row.telegram_id }
  });
}));

// Logout
app.post('/api/auth/logout', authMiddleware, asyncHandler(async (req, res) => {
  const { token } = req.body;
  if (token) {
    await pool.query('DELETE FROM auth_tokens WHERE token = $1', [token]);
  }
  res.json({ success: true });
}));

// Validate license
app.post('/api/license/validate', asyncHandler(async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ success: false, message: 'Key required' });
  
  const result = await pool.query('SELECT * FROM licenses WHERE key = $1 AND is_active = true', [key]);
  if (result.rows.length === 0) return res.json({ success: false, message: 'Invalid key' });
  
  const license = result.rows[0];
  if (new Date(license.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Expired' });
  }
  
  res.json({ success: true, data: license });
}));

// Activate license
app.post('/api/license/activate', asyncHandler(async (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ success: false, message: 'Key and HWID required' });
  
  const result = await pool.query('SELECT * FROM licenses WHERE key = $1 AND is_active = true', [key]);
  if (result.rows.length === 0) return res.json({ success: false, message: 'Invalid key' });
  
  const license = result.rows[0];
  if (new Date(license.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Expired' });
  }
  if (license.hwid_bound && license.hwid !== hwid) {
    return res.json({ success: false, message: 'Already bound to another HWID' });
  }
  
  await pool.query('UPDATE licenses SET hwid = $1, hwid_bound = true WHERE key = $2', [hwid, key]);
  res.json({ success: true, message: 'Activated successfully' });
}));

// Check license status
app.get('/api/license/:key/status', asyncHandler(async (req, res) => {
  const { key } = req.params;
  const result = await pool.query('SELECT * FROM licenses WHERE key = $1', [key]);
  if (result.rows.length === 0) return res.json({ success: false, message: 'Not found' });
  res.json({ success: true, data: result.rows[0] });
}));

// Bind/unbind HWID
app.post('/api/license/:key/bind', asyncHandler(async (req, res) => {
  const { key } = req.params;
  const { hwid } = req.body;
  await pool.query('UPDATE licenses SET hwid = $1, hwid_bound = true WHERE key = $2', [hwid, key]);
  res.json({ success: true });
}));

app.post('/api/license/:key/unbind', asyncHandler(async (req, res) => {
  const { key } = req.params;
  await pool.query('UPDATE licenses SET hwid = NULL, hwid_bound = false WHERE key = $1', [key]);
  res.json({ success: true });
}));

// User routes
app.post('/api/user/register', asyncHandler(async (req, res) => {
  const { telegram_id, username, hwid } = req.body;
  await pool.query(
    'INSERT INTO users (telegram_id, username, hwid) VALUES ($1, $2, $3) ON CONFLICT (telegram_id) DO UPDATE SET username = $2, hwid = $3',
    [telegram_id, username, hwid]
  );
  res.json({ success: true });
}));

app.get('/api/user/:telegram_id', asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [req.params.telegram_id]);
  if (result.rows.length === 0) return res.status(404).json({ success: false });
  res.json({ success: true, data: result.rows[0] });
}));

// Admin routes (protected)
app.post('/api/admin/license/create', authMiddleware, asyncHandler(async (req, res) => {
  const { admin_id, user_id, duration_days } = req.body;
  const key = generateLicenseKey();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + duration_days);
  
  await pool.query(
    'INSERT INTO licenses (key, telegram_id, duration_days, expires_at) VALUES ($1, $2, $3, $4)',
    [key, user_id, duration_days, expiresAt]
  );
  
  await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
    [admin_id, 'CREATE_LICENSE', `Created key ${key} for ${user_id}`]);
  
  res.json({ success: true, data: { key, expires_at: expiresAt } });
}));

app.post('/api/admin/license/revoke', authMiddleware, asyncHandler(async (req, res) => {
  const { admin_id, key } = req.body;
  await pool.query('UPDATE licenses SET is_active = false WHERE key = $1', [key]);
  await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
    [admin_id, 'REVOKE_LICENSE', `Revoked key ${key}`]);
  res.json({ success: true });
}));

app.post('/api/admin/license/extend', authMiddleware, asyncHandler(async (req, res) => {
  const { admin_id, key, additional_days } = req.body;
  const result = await pool.query('SELECT expires_at FROM licenses WHERE key = $1', [key]);
  if (result.rows.length === 0) return res.status(404).json({ success: false, message: 'Key not found' });
  
  const currentExpiry = new Date(result.rows[0].expires_at);
  currentExpiry.setDate(currentExpiry.getDate() + additional_days);
  
  await pool.query('UPDATE licenses SET expires_at = $1 WHERE key = $2', [currentExpiry, key]);
  await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
    [admin_id, 'EXTEND_LICENSE', `Extended key ${key} by ${additional_days} days`]);
  res.json({ success: true, data: { new_expiry: currentExpiry } });
}));

app.get('/api/admin/licenses', authMiddleware, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/admin/users', authMiddleware, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT * FROM users ORDER BY created_at DESC');
  res.json({ success: true, data: result.rows });
}));

app.get('/api/admin/statistics', authMiddleware, asyncHandler(async (req, res) => {
  const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
  const totalLicenses = await pool.query('SELECT COUNT(*) FROM licenses');
  const activeLicenses = await pool.query('SELECT COUNT(*) FROM licenses WHERE is_active = true');
  const expiredLicenses = await pool.query('SELECT COUNT(*) FROM licenses WHERE expires_at < NOW()');
  
  res.json({
    success: true,
    data: {
      total_users: parseInt(totalUsers.rows[0].count),
      total_licenses: parseInt(totalLicenses.rows[0].count),
      active_licenses: parseInt(activeLicenses.rows[0].count),
      expired_licenses: parseInt(expiredLicenses.rows[0].count)
    }
  });
}));

// Global error handler
app.use((err, req, res, next) => {
  console.error('API Error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ========== TELEGRAM BOT ==========

const adminKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '➕ Создать ключ', callback_data: 'admin_create' }],
      [{ text: '📜 Список лицензий', callback_data: 'admin_licenses' }],
      [{ text: '📊 Статистика', callback_data: 'admin_stats' }],
      [{ text: '👤 Пользователи', callback_data: 'admin_users' }],
      [{ text: '🔍 Поиск', callback_data: 'admin_search' }],
      [{ text: '📋 Логи', callback_data: 'admin_logs' }]
    ]
  }
};

const userKeyboard = {
  reply_markup: {
    inline_keyboard: [
      [{ text: '👤 Мой профиль', callback_data: 'user_profile' }],
      [{ text: '🔑 Проверить лицензию', callback_data: 'user_check_license' }]
    ]
  }
};

telegramBot.onText(/\/start/, async (msg) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id.toString();
  const username = msg.from.username || 'unknown';
  
  try {
    // Auto-register admin from env if matches
    if (process.env.ADMIN_TELEGRAM_ID && userId === process.env.ADMIN_TELEGRAM_ID.toString()) {
      await pool.query(
        'INSERT INTO admins (telegram_id, username) VALUES ($1, $2) ON CONFLICT (telegram_id) DO UPDATE SET username = $2',
        [userId, username]
      );
    }
    
    // Register/update user in DB
    await pool.query(
      'INSERT INTO users (telegram_id, username) VALUES ($1, $2) ON CONFLICT (telegram_id) DO UPDATE SET username = $2',
      [userId, username]
    );
    
    const admin = await isAdmin(userId);
    if (admin) {
      await telegramBot.sendMessage(chatId, 
        `🎯 Добро пожаловать, админ @${username}!\n\nВаш ID: <code>${userId}</code>\n\nИспользуйте кнопки или команды для управления.`, 
        { ...adminKeyboard, parse_mode: 'HTML' });
    } else {
      await telegramBot.sendMessage(chatId, 
        `👋 Привет, @${username}!\n\nВаш ID: <code>${userId}</code>`, 
        { ...userKeyboard, parse_mode: 'HTML' });
    }
  } catch (err) {
    console.error('Start command error:', err);
    await telegramBot.sendMessage(chatId, '❌ Ошибка. Попробуйте позже.');
  }
});

// Add admin (only existing admin can add new ones)
telegramBot.onText(/\/addadmin\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const newAdminId = match[1];
  try {
    await pool.query(
      'INSERT INTO admins (telegram_id, username) VALUES ($1, $2) ON CONFLICT (telegram_id) DO NOTHING',
      [newAdminId, 'added_by_admin']
    );
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'ADD_ADMIN', `Added ${newAdminId} as admin`]);
    await telegramBot.sendMessage(msg.chat.id, `✅ Пользователь ${newAdminId} назначен админом.`);
  } catch (err) {
    console.error('Add admin error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка добавления админа.');
  }
});

// Help command
telegramBot.onText(/\/help/, async (msg) => {
  const userId = msg.from.id.toString();
  const admin = await isAdmin(userId);
  
  let text = '📚 Доступные команды:\n\n';
  text += '/start - Запустить бота\n';
  text += '/help - Эта справка\n';
  
  if (admin) {
    text += '\n🔐 Админ-команды:\n';
    text += '/createkey <дни> <tg_id> - Создать ключ\n';
    text += '/extendkey <key> <дней> - Продлить ключ\n';
    text += '/revoke <key> - Отозвать ключ\n';
    text += '/delkey <key> - Удалить ключ\n';
    text += '/reset_hwid <key> - Сбросить HWID\n';
    text += '/userkeys <tg_id> - Ключи пользователя\n';
    text += '/finduser <tg_id> - Найти пользователя\n';
    text += '/banuser <tg_id> - Забанить\n';
    text += '/unbanuser <tg_id> - Разбанить\n';
    text += '/addadmin <tg_id> - Добавить админа\n';
    text += '/stats - Статистика\n';
    text += '/logs - Логи\n';
  }
  
  await telegramBot.sendMessage(msg.chat.id, text);
});

telegramBot.onText(/\/createkey\s+(\d+)\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const duration = parseInt(match[1]);
  const targetUser = match[2];
  const key = generateLicenseKey();
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + duration);
  
  try {
    await pool.query(
      'INSERT INTO licenses (key, telegram_id, duration_days, expires_at) VALUES ($1, $2, $3, $4)',
      [key, targetUser, duration, expiresAt]
    );
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'CREATE_KEY', `Created ${key} for ${targetUser}, ${duration}d`]);
    await telegramBot.sendMessage(msg.chat.id, `✅ Ключ создан:\n<code>${key}</code>\nДействует: ${duration} дней\nДля: ${targetUser}`, { parse_mode: 'HTML' });
    await telegramBot.sendMessage(targetUser, `Вам выдан ключ:\n<code>${key}</code>\nДействует: ${duration} дней`, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('Create key error:', err);
    await telegramBot.sendMessage(msg.chat.id, 'Ошибка создания ключа.');
  }
});

telegramBot.onText(/\/revoke\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const key = match[1];
  try {
    await pool.query('UPDATE licenses SET is_active = false WHERE key = $1', [key]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'REVOKE_KEY', `Revoked ${key}`]);
    await telegramBot.sendMessage(msg.chat.id, `❌ Ключ <code>${key}</code> отозван.`, { parse_mode: 'HTML' });
  } catch (err) {
    await telegramBot.sendMessage(msg.chat.id, 'Ошибка.');
  }
});

// Reusable stats function
async function sendStats(chatId) {
  try {
    const totalUsers = await pool.query('SELECT COUNT(*) FROM users');
    const totalLicenses = await pool.query('SELECT COUNT(*) FROM licenses');
    const activeLicenses = await pool.query('SELECT COUNT(*) FROM licenses WHERE is_active = true');
    const expiredLicenses = await pool.query('SELECT COUNT(*) FROM licenses WHERE expires_at < NOW()');
    const boundLicenses = await pool.query('SELECT COUNT(*) FROM licenses WHERE hwid_bound = true');
    const activeUsers = await pool.query('SELECT COUNT(*) FROM users WHERE is_active = true');
    
    await telegramBot.sendMessage(chatId, 
      `📊 Статистика:\n\n` +
      `👤 Пользователей: ${totalUsers.rows[0].count}\n` +
      `✅ Активных юзеров: ${activeUsers.rows[0].count}\n` +
      `🔑 Всего ключей: ${totalLicenses.rows[0].count}\n` +
      `✅ Активных ключей: ${activeLicenses.rows[0].count}\n` +
      `❌ Истекших: ${expiredLicenses.rows[0].count}\n` +
      `🔒 С привязкой HWID: ${boundLicenses.rows[0].count}`);
  } catch (err) {
    console.error('Stats error:', err);
    await telegramBot.sendMessage(chatId, '❌ Ошибка получения статистики.');
  }
}

telegramBot.onText(/\/stats/, async (msg) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  await sendStats(msg.chat.id);
});

// Extend license
telegramBot.onText(/\/extendkey\s+(\S+)\s+(\d+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const key = match[1];
  const additionalDays = parseInt(match[2]);
  
  try {
    const result = await pool.query('SELECT expires_at FROM licenses WHERE key = $1', [key]);
    if (result.rows.length === 0) {
      return telegramBot.sendMessage(msg.chat.id, '❌ Ключ не найден.');
    }
    
    const currentExpiry = new Date(result.rows[0].expires_at);
    currentExpiry.setDate(currentExpiry.getDate() + additionalDays);
    
    await pool.query('UPDATE licenses SET expires_at = $1 WHERE key = $2', [currentExpiry, key]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'EXTEND_KEY', `Extended ${key} by ${additionalDays}d`]);
    
    await telegramBot.sendMessage(msg.chat.id, 
      `✅ Ключ <code>${key}</code> продлен на ${additionalDays} дней.\n📅 Новая дата: ${currentExpiry.toLocaleDateString()}`, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('Extend error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка продления ключа.');
  }
});

// Reset HWID binding
telegramBot.onText(/\/reset_hwid\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const key = match[1];
  
  try {
    await pool.query('UPDATE licenses SET hwid = NULL, hwid_bound = false WHERE key = $1', [key]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'RESET_HWID', `Reset HWID for ${key}`]);
    
    await telegramBot.sendMessage(msg.chat.id, `✅ HWID сброшен для <code>${key}</code>.`, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('Reset HWID error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка сброса HWID.');
  }
});

// Show user keys
telegramBot.onText(/\/userkeys\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const targetUser = match[1];
  
  try {
    const result = await pool.query('SELECT key, is_active, expires_at, hwid_bound FROM licenses WHERE telegram_id = $1 ORDER BY created_at DESC', [targetUser]);
    if (result.rows.length === 0) {
      return telegramBot.sendMessage(msg.chat.id, '❌ У пользователя нет ключей.');
    }
    
    let text = `🔑 Ключи пользователя ${targetUser}:\n\n`;
    result.rows.forEach(row => {
      const status = row.is_active ? '✅' : '❌';
      const bound = row.hwid_bound ? '🔒' : '🔓';
      const expired = new Date(row.expires_at) < new Date() ? ' (ИСТЕК)' : '';
      text += `${status} ${bound} <code>${row.key}</code>\n📅 ${new Date(row.expires_at).toLocaleDateString()}${expired}\n\n`;
    });
    await telegramBot.sendMessage(msg.chat.id, text, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('User keys error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка получения ключей.');
  }
});

// Ban user
telegramBot.onText(/\/banuser\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const targetUser = match[1];
  
  try {
    await pool.query('UPDATE users SET is_active = false WHERE telegram_id = $1', [targetUser]);
    await pool.query('UPDATE licenses SET is_active = false WHERE telegram_id = $1', [targetUser]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'BAN_USER', `Banned ${targetUser}`]);
    
    await telegramBot.sendMessage(msg.chat.id, `🚫 Пользователь ${targetUser} забанен.\nВсе его лицензии отключены.`);
  } catch (err) {
    console.error('Ban error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка бана.');
  }
});

// Unban user
telegramBot.onText(/\/unbanuser\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const targetUser = match[1];
  
  try {
    await pool.query('UPDATE users SET is_active = true WHERE telegram_id = $1', [targetUser]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'UNBAN_USER', `Unbanned ${targetUser}`]);
    
    await telegramBot.sendMessage(msg.chat.id, `✅ Пользователь ${targetUser} разбанен.`);
  } catch (err) {
    console.error('Unban error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка разбана.');
  }
});

// Show logs
telegramBot.onText(/\/logs/, async (msg) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  try {
    const result = await pool.query('SELECT telegram_id, action, details, created_at FROM logs ORDER BY created_at DESC LIMIT 15');
    if (result.rows.length === 0) {
      return telegramBot.sendMessage(msg.chat.id, '📋 Логи пусты.');
    }
    
    let text = '📋 Последние действия:\n\n';
    result.rows.forEach(row => {
      text += `[${new Date(row.created_at).toLocaleDateString()}] ${row.action}: ${row.details}\n`;
    });
    await telegramBot.sendMessage(msg.chat.id, text);
  } catch (err) {
    console.error('Logs error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка получения логов.');
  }
});

// Find user by ID
telegramBot.onText(/\/finduser\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const targetUser = match[1];
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [targetUser]);
    if (result.rows.length === 0) {
      return telegramBot.sendMessage(msg.chat.id, '❌ Пользователь не найден.');
    }
    
    const user = result.rows[0];
    const keys = await pool.query('SELECT key, is_active, expires_at FROM licenses WHERE telegram_id = $1', [targetUser]);
    
    let text = `👤 Пользователь:\n\n`;
    text += `ID: ${user.telegram_id}\n`;
    text += `Имя: @${user.username || 'unknown'}\n`;
    text += `HWID: ${user.hwid ? '✅ ' + user.hwid : '❌ не привязан'}\n`;
    text += `Активен: ${user.is_active ? '✅' : '❌'}\n`;
    text += `Ключей: ${keys.rows.length}\n\n`;
    
    keys.rows.forEach(row => {
      const status = row.is_active ? '✅' : '❌';
      text += `${status} <code>${row.key}</code> — ${new Date(row.expires_at).toLocaleDateString()}\n`;
    });
    
    await telegramBot.sendMessage(msg.chat.id, text, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('Find user error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка поиска.');
  }
});

// Delete key
telegramBot.onText(/\/delkey\s+(\S+)/, async (msg, match) => {
  const userId = msg.from.id.toString();
  if (!await isAdmin(userId)) {
    return telegramBot.sendMessage(msg.chat.id, 'Нет доступа.');
  }
  
  const key = match[1];
  
  try {
    await pool.query('DELETE FROM licenses WHERE key = $1', [key]);
    await pool.query('INSERT INTO logs (telegram_id, action, details) VALUES ($1, $2, $3)', 
      [userId, 'DELETE_KEY', `Deleted ${key}`]);
    
    await telegramBot.sendMessage(msg.chat.id, `🗑 Ключ <code>${key}</code> удален.`, { parse_mode: 'HTML' });
  } catch (err) {
    console.error('Delete key error:', err);
    await telegramBot.sendMessage(msg.chat.id, '❌ Ошибка удаления.');
  }
});

telegramBot.on('callback_query', async (query) => {
  const chatId = query.message.chat.id;
  const userId = query.from.id.toString();
  const data = query.data;
  
  try {
    // Admin actions need admin check
    if (data.startsWith('admin_')) {
      const admin = await isAdmin(userId);
      if (!admin) {
        await telegramBot.answerCallbackQuery(query.id, { text: 'Нет доступа.' });
        return;
      }
    }
    
    if (data === 'admin_create') {
      await telegramBot.sendMessage(chatId, 'Используйте:\n<code>/createkey &lt;дни&gt; &lt;telegram_id&gt;</code>\n\nПример:\n/createkey 30 123456789\n\nДоступные команды:\n/createkey - создать ключ\n/extendkey - продлить ключ\n/revoke - отозвать\n/delkey - удалить\n/reset_hwid - сбросить HWID\n/userkeys - ключи юзера\n/finduser - найти юзера\n/banuser - забанить\n/unbanuser - разбанить\n/logs - логи\n/stats - статистика', { parse_mode: 'HTML' });
    } else if (data === 'admin_stats') {
      await sendStats(chatId);
    } else if (data === 'admin_licenses') {
      const result = await pool.query('SELECT key, is_active, expires_at FROM licenses ORDER BY created_at DESC LIMIT 20');
      if (result.rows.length === 0) {
        await telegramBot.sendMessage(chatId, '🔑 Лицензий пока нет.');
      } else {
        let text = '🔑 Последние ключи:\n\n';
        result.rows.forEach(row => {
          const status = row.is_active ? '✅' : '❌';
          text += `${status} <code>${row.key}</code>\n📅 ${new Date(row.expires_at).toLocaleDateString()}\n\n`;
        });
        await telegramBot.sendMessage(chatId, text, { parse_mode: 'HTML' });
      }
    } else if (data === 'admin_users') {
      const result = await pool.query('SELECT telegram_id, username, created_at, is_active FROM users ORDER BY created_at DESC LIMIT 20');
      if (result.rows.length === 0) {
        await telegramBot.sendMessage(chatId, '👤 Пользователей пока нет.');
      } else {
        let text = '👤 Пользователи:\n\n';
        result.rows.forEach(row => {
          const status = row.is_active ? '✅' : '❌';
          text += `${status} @${row.username || row.telegram_id} - ${new Date(row.created_at).toLocaleDateString()}\n`;
        });
        await telegramBot.sendMessage(chatId, text);
      }
    } else if (data === 'admin_search') {
      await telegramBot.sendMessage(chatId, 'Используйте:\n<code>/finduser &lt;telegram_id&gt;</code>\n\nПример: /finduser 123456789', { parse_mode: 'HTML' });
    } else if (data === 'admin_logs') {
      const result = await pool.query('SELECT telegram_id, action, details, created_at FROM logs ORDER BY created_at DESC LIMIT 15');
      if (result.rows.length === 0) {
        await telegramBot.sendMessage(chatId, '📋 Логи пусты.');
      } else {
        let text = '📋 Последние действия:\n\n';
        result.rows.forEach(row => {
          text += `[${new Date(row.created_at).toLocaleDateString()}] ${row.action}: ${row.details}\n`;
        });
        await telegramBot.sendMessage(chatId, text);
      }
    } else if (data === 'user_profile') {
      const result = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [userId]);
      if (result.rows.length === 0) {
        await telegramBot.sendMessage(chatId, 'Профиль не найден. Зарегистрируйтесь через клиент.');
      } else {
        const user = result.rows[0];
        await telegramBot.sendMessage(chatId, `👤 Профиль:\nID: ${user.telegram_id}\nИмя: @${user.username || 'unknown'}\nHWID: ${user.hwid ? '✅ привязан' : '❌ не привязан'}\nАктивен: ${user.is_active ? '✅' : '❌'}`);
      }
    }
    await telegramBot.answerCallbackQuery(query.id);
  } catch (err) {
    console.error('Callback error:', err);
    await telegramBot.answerCallbackQuery(query.id, { text: 'Ошибка' });
  }
});

// Webhook endpoint for Telegram - must use express.json() to get parsed object
app.post('/webhook', (req, res) => {
  try {
    telegramBot.processUpdate(req.body);
    res.sendStatus(200);
  } catch (err) {
    console.error('Webhook error:', err);
    res.sendStatus(200); // Always return 200 to Telegram
  }
});

// Setup webhook via direct Telegram API call (robust, no library method dependency)
function setTelegramWebhook(token, url) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ url });
    const options = {
      hostname: 'api.telegram.org',
      path: `/bot${token}/setWebhook`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(body);
          if (json.ok) resolve(json);
          else reject(new Error(json.description || 'Unknown error'));
        } catch (e) {
          resolve(body);
        }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Start server
const PORT = process.env.PORT || 3000;
const server = app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/api/health`);
  
  // Setup webhook for Railway
  const domain = process.env.RAILWAY_PUBLIC_DOMAIN || process.env.RAILWAY_STATIC_URL || process.env.BASE_URL;
  if (domain) {
    const cleanDomain = domain.replace(/^https?:\/\//, '');
    const webhookUrl = `https://${cleanDomain}/webhook`;
    try {
      await setTelegramWebhook(process.env.TELEGRAM_BOT_TOKEN, webhookUrl);
      console.log(`Webhook set: ${webhookUrl}`);
    } catch (err) {
      console.error('Failed to set webhook:', err.message);
    }
  } else {
    console.log('No RAILWAY_PUBLIC_DOMAIN found. Set webhook manually if needed.');
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});
