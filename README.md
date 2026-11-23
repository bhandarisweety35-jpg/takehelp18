# TakeHelp? – Backend (REST API)
Express API: auth, orders, uploads (private, in `STORAGE_DIR`), admin, pricing, notifications. Needs Node 20+.
1. The database file and tables are created automatically on first start (schema.sql). Set ADMIN_USERNAME, ADMIN_PASSWORD and RESET_ADMIN_PASSWORD=1 to create or reset the admin.
2. `cp .env.example .env`, set `JWT_SECRET` and `FRONTEND_ORIGIN`
3. `npm install && npm start` → http://localhost:3000
Production: set NODE_ENV=production, serve over HTTPS, keep DB file and STORAGE_DIR on persistent disk.
