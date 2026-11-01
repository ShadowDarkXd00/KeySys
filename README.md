# Shadow Key System

License key generator + validator for your game/app.

- Admin panel (password protected) to generate, reset, revoke, extend and delete keys
- Keys look like `SHADOW-XXXXXXXXXXXX`
- Expiry by minutes / hours / days / lifetime (timer starts on first use or on creation)
- Max uses per key, optional device (HWID) lock
- Public check URL for your app

## Check URL (use this in your app)

```
GET  /api/check?key=SHADOW-XXXXXXXXXXXX&hwid=DEVICE_ID
POST /api/check   {"key":"SHADOW-XXXXXXXXXXXX","hwid":"DEVICE_ID"}
```

`hwid` is only needed for keys created with device lock. Add `consume=0` to look at a key without using a use or starting its timer.

Response:

```json
{ "ok": true, "valid": true, "status": "valid", "message": "Key is valid",
  "expires_at": 1767225600, "seconds_left": 86400, "lifetime": false,
  "uses": 1, "max_uses": 5, "uses_left": 4 }
```

`status` is one of: `valid`, `invalid`, `expired`, `revoked`, `max_uses`, `hwid_required`, `hwid_mismatch`, `rate_limited`.
Always check `valid === true`.

Each successful check uses one use. With device lock on, re-checks from the already-bound device do not use extra uses.

## Environment variables

| Name | Purpose |
|---|---|
| `ADMIN_PASSWORD` | Admin login password (required) |
| `DATABASE_URL` | Postgres connection string (keys are stored here) |
| `SESSION_SECRET` | Optional, signs admin sessions |
| `PGSSL` | Set to `off` if your Postgres does not use SSL |

Without `DATABASE_URL` it falls back to a local `data.json` file (development only; not persistent on Render).

## Run locally

```
npm install
ADMIN_PASSWORD=yourpassword npm start
```
