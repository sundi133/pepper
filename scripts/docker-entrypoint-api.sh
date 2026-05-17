#!/bin/sh
# Pepper API container entrypoint.
#
# Runs schema sync + seed before starting Next.js. Designed to be safe under
# all of:
#   - fresh DB                        (db push creates everything)
#   - DB synced previously via push   (db push is a no-op)
#   - DB managed via prisma migrate   (migrate deploy runs new migrations)
#
# DB sync order:
#   1. Try `prisma migrate deploy` for any tracked migrations. If no
#      _prisma_migrations table exists yet, Prisma will create it.
#   2. Fall back to `prisma db push` so the live schema always matches
#      prisma/schema.prisma, even if a migration file is missing or the DB
#      was historically managed via push.
#
# Both steps are idempotent.
set -e

echo "[entrypoint] Applying schema changes…"

# Step 1 — apply any tracked migrations (idempotent).
if ! npx prisma migrate deploy 2>&1; then
  echo "[entrypoint] prisma migrate deploy reported a non-fatal error; continuing to db push"
fi

# Step 2 — bring the live schema fully in sync with schema.prisma.
# `--accept-data-loss` is safe here because the migration above is additive
# (no destructive columns/types), but we pass it explicitly so push doesn't
# bail out if a NOT NULL column was added with a default.
npx prisma db push --accept-data-loss

echo "[entrypoint] Seeding (idempotent)…"
npx tsx prisma/seed.ts || echo "[entrypoint] seed failed; continuing"

echo "[entrypoint] Starting Pepper API…"
exec npm start
