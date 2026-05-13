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

- GET /api/health - Health check
- POST /api/license/validate - Validate license
- POST /api/license/activate - Activate license with HWID
- POST /api/license/:key/bind - Bind HWID
- POST /api/license/:key/unbind - Unbind HWID
- GET /api/license/:key/status - Check license status
- POST /api/user/register - Register user
- GET /api/user/:id - Get user info
- POST /api/admin/license/create - Create license (protected)
- POST /api/admin/license/revoke - Revoke license (protected)
- POST /api/admin/license/extend - Extend license (protected)
- GET /api/admin/licenses - List all licenses (protected)
- GET /api/admin/users - List all users (protected)
- GET /api/admin/statistics - Get statistics (protected)
