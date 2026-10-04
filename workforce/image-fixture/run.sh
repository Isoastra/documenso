#!/usr/bin/env bash
set -euo pipefail
# Execute on the native Linux deployment builder. No production env or database is read.
image=${1:?usage: run.sh documenso:workforce-RELEASE [application-origin] [absent|production]}
application_origin=${2:-http://127.0.0.1:3000}
node_env=${3:-absent}
if [ "$node_env" != absent ] && [ "$node_env" != production ]; then
  printf 'Invalid fixture NODE_ENV mode\n' >&2
  exit 1
fi
test_dir=$(cd "$(dirname "$0")" && pwd)
fixture=$(mktemp -d /tmp/documenso-image-qualification.XXXXXX)
docker_cmd=(sudo docker)
network=documenso-qualified-network
postgres=documenso-qualified-pg
app=documenso-qualified-app
for name in "$postgres" "$app"; do
  if "${docker_cmd[@]}" container inspect "$name" >/dev/null 2>&1; then
    printf 'Refusing to replace existing fixture container: %s\n' "$name" >&2
    exit 1
  fi
done
if "${docker_cmd[@]}" network inspect "$network" >/dev/null 2>&1; then
  printf 'Refusing to replace existing fixture network\n' >&2
  exit 1
fi
cleanup() {
  "${docker_cmd[@]}" rm -fv "$app" "$postgres" >/dev/null 2>&1 || true
  "${docker_cmd[@]}" network rm "$network" >/dev/null 2>&1 || true
  rm -rf "$fixture"
}
trap cleanup EXIT
chmod 755 "$fixture"
cp "$test_dir/preload.ts" "$test_dir/qualify.ts" "$fixture/"
printf 'fixture-write-native-qualification-token\n' > "$fixture/write.token"
printf 'fixture-read-native-qualification-token\n' > "$fixture/read.token"
cat > "$fixture/app.env" <<'ENV'
NEXT_PRIVATE_DATABASE_URL=postgresql://fixture:fixture@documenso-qualified-pg:5432/documenso
NEXT_PRIVATE_DIRECT_DATABASE_URL=postgresql://fixture:fixture@documenso-qualified-pg:5432/documenso
NEXTAUTH_SECRET=fixture-native-runtime-secret-at-least-32-characters
NEXT_PRIVATE_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
NEXT_PRIVATE_ENCRYPTION_SECONDARY_KEY=abcdef0123456789abcdef0123456789
NEXT_PRIVATE_OIDC_WELL_KNOWN=https://auth.isoastra.com/.well-known/openid-configuration
NEXT_PRIVATE_OIDC_CLIENT_ID=fixture-client
NEXT_PRIVATE_OIDC_CLIENT_SECRET=fixture-secret
NEXT_PUBLIC_DISABLE_SIGNUP=true
WORKFORCE_SCIM_TOKEN_FILE=/fixture/write.token
WORKFORCE_SCIM_READ_TOKEN_FILE=/fixture/read.token
NODE_OPTIONS=--experimental-strip-types --import /fixture/preload.ts
ENV
printf 'NEXT_PUBLIC_WEBAPP_URL=%s\n' "$application_origin" >> "$fixture/app.env"
if [ "$node_env" = production ]; then
  printf 'NODE_ENV=production\n' >> "$fixture/app.env"
else
  printf 'NODE_ENV=\n' >> "$fixture/app.env"
fi
"${docker_cmd[@]}" network create "$network" >/dev/null
"${docker_cmd[@]}" run -d --name "$postgres" --network "$network" \
  --label isoastra.test=documenso-image-qualification \
  -e POSTGRES_USER=fixture -e POSTGRES_PASSWORD=fixture -e POSTGRES_DB=documenso \
  postgres:18 >/dev/null
for _ in $(seq 1 30); do
  if "${docker_cmd[@]}" exec "$postgres" pg_isready -U fixture -d documenso >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"${docker_cmd[@]}" run --rm --network "$network" --env-file "$fixture/app.env" \
  -e NODE_OPTIONS= --entrypoint npx "$image" prisma migrate deploy \
  --schema /app/packages/prisma/schema.prisma > "$fixture/migrate.log" 2>&1 || {
    tail -20 "$fixture/migrate.log" >&2; exit 1;
  }
"${docker_cmd[@]}" run --rm --network "$network" --env-file "$fixture/app.env" \
  -e NODE_OPTIONS= --entrypoint node "$image" --input-type=module -e \
  'import {pool,migration} from "/app/workforce/native.mjs"; await pool().query(migration); await pool().end();'
"${docker_cmd[@]}" run -d --name "$app" --network "$network" \
  --label isoastra.test=documenso-image-qualification --env-file "$fixture/app.env" \
  -v "$fixture:/fixture:ro" "$image" >/dev/null
ready=false
for _ in $(seq 1 60); do
  if "${docker_cmd[@]}" exec "$app" node -e \
    'fetch("http://127.0.0.1:3000/api/health").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))' >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  "${docker_cmd[@]}" logs "$app" >&2
  exit 1
fi
"${docker_cmd[@]}" exec "$app" node --experimental-strip-types /fixture/qualify.ts
