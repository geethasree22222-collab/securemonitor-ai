# SecureMonitor AI deployment checklist

## Required

Deploy the **whole folder** as a Node.js 18+ web service. The start command is:

```text
npm start
```

Do not publish only `securemonitor.html` as a static site.

## Environment variables

Set at minimum:

```text
NODE_ENV=production
PORT=3000
PUBLIC_URL=https://YOUR-DOMAIN
JWT_SECRET=<long-random-secret>
DATA_DIR=<persistent-storage-path>
```

Optional:

```text
N8N_RESET_WEBHOOK=<password-reset-n8n-webhook>
N8N_ALERT_WEBHOOK=<alert-n8n-webhook>
GEMINI_API_KEY=<server-side-only-gemini-key>
GEMINI_MODEL=gemini-2.5-flash
```

## First test

Open:

```text
https://YOUR-DOMAIN/api/health
```

It must contain:

```json
"app":"securemonitor"
```

If it instead returns the older response containing only `status`, `timestamp`, `version`, `geminiConfigured`, and `n8nConfigured` without `app: "securemonitor"`, the old backend is still deployed.

## Authentication test

1. Open the website.
2. Create a new account.
3. Sign out.
4. Sign in with the same email/password.
5. Refresh the page.
6. The session should remain authenticated through the HttpOnly refresh cookie.

## Production warning

Set a fixed `JWT_SECRET` and persistent `DATA_DIR`. The current server stores accounts on disk and runtime telemetry/alerts in memory. For multi-instance production, move runtime state to a database.

## Deploy without changing the old AI Studio service (Render demo deployment)

The existing `securemonitor-ai.ai.studio` domain is owned by the currently deployed AI Studio/Cloud Run app. Uploading a ZIP does not replace that service. This project must be deployed as its own Node/Docker web service first.

1. Extract this ZIP into a folder.
2. Create a new GitHub repository for this project and upload the extracted files, including `render.yaml`, `Dockerfile`, `server.js`, `securemonitor.html`, and `package.json`.
3. In Render, choose **New → Blueprint** and connect that repository. Render will read `render.yaml` and create the web service.
4. Wait for the service deployment to finish. Open the service's own `onrender.com` URL, then append `/api/health`.
5. Continue only when the JSON contains `"app":"securemonitor"`. Use that new service URL as the website URL. The old AI Studio URL will continue to serve its existing backend unless you separately change that deployment/domain.

### Demo-only persistence warning

The included free Render blueprint uses an ephemeral filesystem. Accounts stored in `users.json` can be lost when the service is redeployed/restarted. Use this only for a temporary demo; before relying on accounts, configure a persistent database/storage and update the backend accordingly. Do not assume the account created on the old AI Studio backend exists on this new service; register again after deployment.

### Smoke test

Start the service locally in one terminal:

```bash
npm start
```

In a second terminal run:

```bash
node smoke-test.js
```

The test checks health, registration, login, current-user access, and rejection of a wrong password using a throwaway account. You can pass a different base URL as an argument, but avoid running it against production because it creates an account.
