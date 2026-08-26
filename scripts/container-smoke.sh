#!/bin/sh
set -eu

compose=${COMPOSE_FILE:-docker-compose.production.yml}
cleanup() { docker compose -f "$compose" down; }
trap cleanup EXIT INT TERM

docker compose -f "$compose" config --quiet
docker compose -f "$compose" up --build --detach --wait
curl --fail --silent --show-error https://${VYPER_DOMAIN}/api/health
curl --fail --silent --show-error https://${VYPER_DOMAIN}/api/readiness
printf '%s\n' 'Container smoke PASS: TLS proxy, backend readiness, frontend, migration, and PostgreSQL are running.'
