# SecureMonitor AI

A deployable device-monitoring web application with email/password authentication, laptop/mobile/ESP32 telemetry, rule-based anomaly detection, alerts, recommendations, optional n8n automation, and an optional Gemini assessment layer.

## Architecture

Browser → SecureMonitor Node server → `/api/*`

Laptop / Android / ESP32 → authenticated telemetry endpoints → rule engine → alerts → dashboard / optional n8n

The **rule-based anomaly score is the primary risk classification**. Gemini is only an additional human-readable assessment when configured.

## Run locally

Requirements: Node.js 18+.

```bash
npm start
```

Open:

```text
http://localhost:3000
```

For local development, create `.env` from `.env.example` and set a stable `JWT_SECRET`.

## Deployment

See `DEPLOYMENT.md` for the deployment checklist and the Render demo deployment path. The free demo filesystem is ephemeral; use persistent storage/database before relying on registered accounts.

## Production deployment

Deploy the whole project as a Node 18+ web service with:

```text
npm start
```

The service must serve both:

```text
GET  /
GET  /api/health
POST /api/auth/register
POST /api/auth/login
POST /api/auth/refresh
POST /api/auth/logout
GET  /api/auth/me
POST /api/auth/forgot-password
POST /api/auth/reset-password
```

Do **not** deploy only `securemonitor.html` as a static site. The frontend and API must be served by the same Node service unless a separate backend URL is intentionally configured.

## Verify deployment

Open:

```text
https://YOUR-DOMAIN/api/health
```

Expected shape:

```json
{
  "ok": true,
  "status": "ok",
  "app": "securemonitor",
  "version": "1.0.0",
  "geminiConfigured": false,
  "n8nConfigured": false
}
```

The important value is:

```text
"app": "securemonitor"
```

If another JSON format appears, the domain is running a different backend.

## Authentication

Email/password only. Google Sign-In is intentionally not included.

- Short-lived access token in memory
- `__Host-refresh_token` HttpOnly cookie in production
- Refresh-token rotation
- Server-side ownership checks
- Password hashing with Node `scrypt`
- Rate limiting for login attempts

## Telemetry

After signing in, the Devices page can generate a device key. Send it as:

```text
X-Device-Key: <device-key>
```

Endpoints:

```text
POST /api/telemetry/laptop
POST /api/telemetry/mobile
POST /api/telemetry/iot
```

Example laptop payload:

```json
{
  "deviceId": "laptop-001",
  "timestamp": "2026-10-08T14:00:00Z",
  "cpu": 42,
  "ram": 55,
  "disk": 60,
  "download_mb": 3,
  "upload_mb": 1,
  "processes": 240
}
```

## n8n

Set `N8N_RESET_WEBHOOK` for password-reset delivery and `N8N_ALERT_WEBHOOK` for alert delivery. The dashboard and rule engine do not depend on n8n being available.

## Gemini

Set `GEMINI_API_KEY` to enable the optional AI assessment layer. The frontend must never contain this key. If Gemini is unavailable, the rule-based classification remains authoritative.

## Persistence

Accounts are stored in `users.json` under `DATA_DIR`. For production, point `DATA_DIR` at persistent storage. Telemetry/device/alert runtime state is currently held in memory and should be moved to a database for multi-instance production deployment.

## Smoke test

Start the app with `npm start`, then in another terminal run `node smoke-test.js`. This creates a throwaway local account and checks health, register, login, current-user access, and invalid-password handling. Do not run the smoke test against production unless you intend to create a test account.
