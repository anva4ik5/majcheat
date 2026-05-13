# Majestic RP Cheat Backend

## Railway Deployment

1. Create new project on Railway
2. Connect this folder (backend/) to Railway
3. Add PostgreSQL plugin to project (Railway provides DATABASE_URL automatically)
4. Set environment variables in Railway dashboard:
   - `TELEGRAM_BOT_TOKEN` - your Telegram bot token
   - `ADMIN_TELEGRAM_ID` - admin Telegram ID
   - `API_SECRET_KEY` - secret key for client auth (must match client's shared_key)
   - `NODE_ENV=production`
   - `PORT=3000` (Railway overrides this automatically)
5. Deploy — Railway will use `npm start` from package.json

## Client Configuration

In `config.ini`, set:
```ini
[Server]
url=https://your-app-name.up.railway.app
shared_key=your_API_SECRET_KEY_value
```

The client will automatically connect via HTTPS to your Railway backend.

## API Endpoints

All endpoints (except /webhook and /api/health) require `X-API-Key` header.

### Auth (login + Telegram code)
- `POST /api/auth/register/start` — body: `{login, password, telegram_id, hwid}` → returns `{session_id}`, bot sends 6-digit code
- `POST /api/auth/register/confirm` — body: `{session_id, code}` → returns `{token, user}`
- `POST /api/auth/login` — body: `{login, password, hwid}` → returns `{token}` or `{require_2fa, session_id}` if HWID changed
- `POST /api/auth/login/confirm` — body: `{session_id, code}` → returns `{token}`
- `POST /api/auth/verify` — body: `{token, hwid}` → returns `{user}` or fail
- `POST /api/auth/logout` — body: `{token}`

### License
- `POST /api/license/validate` — body: `{key}`
- `POST /api/license/activate` — body: `{key, hwid}`
- `GET /api/license/:key/status`

### Telegram bot commands
- `/start` — register/menu
- `/help` — list commands
- Admin: `/createkey /extendkey /revoke /delkey /reset_hwid /userkeys /finduser /banuser /unbanuser /addadmin /stats /logs`

## Auth flow (client perspective)

**Register:**
1. User opens client → enters login + password + their Telegram ID
2. Client → `POST /api/auth/register/start` → bot sends code in DM
3. User enters code → Client → `POST /api/auth/register/confirm` → receives `token`
4. Client saves `token` for next launch

**Login:**
1. Client → `POST /api/auth/login` with login/password/hwid
2. If `require_2fa=true` → user gets code in TG → confirm via `/login/confirm`
3. Otherwise → token immediately
