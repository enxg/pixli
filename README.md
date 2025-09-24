# Pixli
Simple URL shortener compatible with ShareX.

**Demo:** https://pixli.enesgenc.dev

---

## Features
- Shorten URLs with optional expiration
- User authentication via GitHub
- ShareX integration

## Quick Start (Docker)
1. Create a GitHub OAuth app.
2. Copy `.env.example` to `.env` and fill in the values (explained below).
3. Run:
   ```sh
   docker compose up
   ```

## Environment Variables
- `DATABASE_URL` – MongoDB connection string (You can use the one on .env.example with the default docker-compose.yml)
- `DATABASE_NAME` – Database name (default: `pixli`)
- `PIXLI_BASE_URL` - Base URL of your Pixli instance (e.g. `https://pixli.enesgenc.dev`)
- `PIXLI_MAX_DURATION` - Maximum duration of shortened URLs in minutes if you want to limit it (set to `0` for unlimited)
- `PIXLI_ADMINS` - Comma-separated GitHub user IDs for admin access, admins are exempt from the duration limit (e.g. `11111111,22222222`)
- `GITHUB_CLIENT_ID` – GitHub OAuth app client ID
- `GITHUB_CLIENT_SECRET` – GitHub OAuth app client secret
- `JWT_SECRET` – Secret for JWT tokens, generated using `cmd/jwtsecretgen` (go run ./cmd/jwtsecretgen)

## License
MIT
