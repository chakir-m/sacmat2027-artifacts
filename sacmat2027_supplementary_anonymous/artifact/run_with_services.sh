#!/usr/bin/env bash
# Starts PostgreSQL 16 + Redis 7 (if not running) and then executes the given command.
# Usage: run_with_services.sh <pgdata-dir> <command...>
set -e
PGDATA="$1"; shift
d="$(dirname "$PGDATA")"
while [ "$d" != "/" ]; do chmod o+x "$d" 2>/dev/null || true; d="$(dirname "$d")"; done
if ! pg_isready -h 127.0.0.1 -q; then
  su postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PGDATA -o '-p 5432 -k /var/run/postgresql' -l $PGDATA/pg.log start" >/dev/null
  for i in $(seq 1 20); do pg_isready -h 127.0.0.1 -q && break; sleep 0.5; done
fi
redis-cli ping >/dev/null 2>&1 || { redis-server --port 6379 --daemonize yes --save '' >/dev/null; sleep 1; }
grep -q ' postgres$' /etc/hosts || echo '127.0.0.1 postgres' >> /etc/hosts
"$@"
