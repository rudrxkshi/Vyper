# Central production deployment

Run `docker compose -f docker-compose.production.yml up --build`. Store the PostgreSQL password and complete psycopg URL in mode-0600 `secrets/postgres_password` and `secrets/central_database_url` files, or use the deployment platform's secret store. Set `VYPER_DOMAIN`; Caddy obtains/renews TLS, redirects HTTP, supplies HSTS, and proxies `/api` to FastAPI. Production cookies are Secure/HttpOnly/SameSite=Lax. Keep `VYPER_CORS_ORIGINS` empty for same-origin deployment, or set only exact HTTPS origins.

Production requires one `VYPER_DATABASE_URL` using `postgresql+psycopg://`; there is no SQLite fallback. The one-shot migration service runs `alembic upgrade head` before the non-root backend starts. Startup never calls `create_all` in production. Bootstrap the first operator after migration with `python -m backend.app.admin_cli admin --role ADMIN` in a protected administrative shell.

Trust forwarded headers only from the private proxy network. Do not publish backend port 8000 or PostgreSQL. The privileged local storage agent is never part of these central containers.

## Local privilege boundary

The browser-facing console is unprivileged. Central sync is outbound and can run unprivileged. Native storage execution is isolated in a short-lived child process with a fixed Python entry point; the current systemd package still runs the local API service with the permissions needed to spawn that executor. A future Unix-domain-socket split should move raw block privileges into a dedicated service account/root helper with socket mode 0660. Until then, bind the API to loopback, require its local API credential, and treat compromise of that service as compromise of the executor boundary.
