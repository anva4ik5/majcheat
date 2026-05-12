# Majestic RP Cheat Backend

## Railway Deployment

1. Connect this folder to Railway
2. Set environment variables:
   - TELEGRAM_BOT_TOKEN
   - ADMIN_TELEGRAM_ID
   - DATABASE_URL (PostgreSQL)
   - NODE_ENV=production

## API Endpoints

- GET /api/health - Health check
- POST /api/license/validate - Validate license
- POST /api/license/activate - Activate license with HWID
