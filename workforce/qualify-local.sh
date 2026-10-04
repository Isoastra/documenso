#!/usr/bin/env bash
set -euo pipefail
fixture=$(mktemp -d /tmp/documenso-native-pg.XXXXXX)
trap '/opt/homebrew/opt/postgresql@18/bin/pg_ctl -D "$fixture/data" stop -m immediate >/dev/null 2>&1 || true; rm -rf "$fixture"' EXIT
pgbin=/opt/homebrew/opt/postgresql@18/bin
"$pgbin/initdb" -D "$fixture/data" -A trust --no-locale >/dev/null
"$pgbin/pg_ctl" -D "$fixture/data" -o '-h 127.0.0.1 -p 57349' -l "$fixture/server.log" start >/dev/null
"$pgbin/createdb" -h 127.0.0.1 -p 57349 workforce
export NEXT_PRIVATE_DATABASE_URL=postgresql://ronitnath@127.0.0.1:57349/workforce
for sql in ../packages/prisma/migrations/*/migration.sql; do
 "$pgbin/psql" "$NEXT_PRIVATE_DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$sql" >"$fixture/migration.log" 2>&1 || { tail -15 "$fixture/migration.log"; exit 1; }
done
node --import tsx --test native.test.ts
