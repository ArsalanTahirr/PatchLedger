#!/usr/bin/env bash
# PatchLedger Bronze/Silver local development helper. No Gold or git actions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONTAINER="patchledger-postgres"
DB="patchledger"
DB_USER="patchledger"

usage() {
  cat <<'HELP'
Usage: bash scripts/setup_bronze_silver.sh <command> [--apply] [--confirm-large-nvd]

Read-only:
  check               Docker and schema preflight
  status              Table row counts, rejects, matching function names, storage

Writes ONLY to Bronze/Silver in the specified local PostgreSQL database:
  init --apply                    Base Bronze and Silver tables
  snapshot-oltp --apply           OLTP -> Bronze snapshot (requires operational schema)
  inventory --apply               Bronze/OLTP -> Silver software inventory
  transform-kev --apply           Bronze KEV -> Silver KEV
  transform-epss --apply          Bronze EPSS -> Silver EPSS
  transform-nvd --apply --confirm-large-nvd
                                  Heavy Bronze NVD -> Silver NVD SQL
  functions --apply               Silver SQL matching functions 006..013

Requires exact Docker container/user/database names hardcoded in this script.
Does not ingest CSVs; use scripts/ingest_bronze.py for Bronze CSV loading.
Does not touch Gold, run tests, commit, push, or create a PR.
HELP
}

if [[ $# -lt 1 ]]; then usage; exit 2; fi
ACTION="$1"
shift
APPLY=0
CONFIRM_NVD=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --confirm-large-nvd) CONFIRM_NVD=1 ;;
    *) echo "Unknown option: $arg" >&2; usage; exit 2 ;;
  esac
done

case "$ACTION" in
  check|status|init|snapshot-oltp|inventory|transform-kev|transform-epss|transform-nvd|functions) ;;
  *) echo "Unknown command: $ACTION" >&2; usage; exit 2 ;;
esac

command -v docker >/dev/null || { echo "STOP: docker not found" >&2; exit 1; }
docker container inspect "$CONTAINER" >/dev/null 2>&1 ||
  { echo "STOP: container $CONTAINER not found" >&2; exit 1; }
docker exec "$CONTAINER" pg_isready -U "$DB_USER" -d "$DB" >/dev/null ||
  { echo "STOP: PostgreSQL connection failed" >&2; exit 1; }

psql_query() {
  docker exec "$CONTAINER" psql -X -v ON_ERROR_STOP=1 \
    -U "$DB_USER" -d "$DB" -c "$1"
}
run_file() {
  local file="$1"
  [[ -f "$file" ]] || { echo "STOP: Missing $file" >&2; exit 1; }
  echo "SQL: $file"
  docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 \
    -U "$DB_USER" -d "$DB" < "$file"
}
require_apply() {
  [[ "$APPLY" -eq 1 ]] || {
    echo "DRY RUN ONLY. To execute writes, add --apply." >&2
    exit 2
  }
}
require_host_space() {
  local free_kib
  free_kib="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
  [[ "$free_kib" =~ ^[0-9]+$ ]] ||
    { echo "STOP: Host free space could not be measured" >&2; exit 1; }
  (( free_kib >= 20 * 1024 * 1024 )) ||
    { echo "STOP: Less than 20 GiB free on host" >&2; exit 1; }
}

if [[ "$ACTION" == check ]]; then
  echo "Docker container: $CONTAINER"
  echo "Database/user: $DB / $DB_USER"
  psql_query "SELECT current_database() AS database, current_user AS db_user, current_setting('server_version') AS postgres_version, to_regnamespace('bronze') AS bronze_schema, to_regnamespace('silver') AS silver_schema;"
  echo "Host disk:"
  df -h "$ROOT"
  exit 0
fi

if [[ "$ACTION" == status ]]; then
  echo "Database schema table counts (estimates for missing tables marked NULL):"
  psql_query "SELECT n.nspname AS schema_name, c.relname AS table_name, c.reltuples::bigint AS estimated_rows FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('bronze','silver') AND c.relkind='r' ORDER BY 1,2;"
  psql_query "SELECT pg_size_pretty(pg_database_size(current_database())) AS database_size;"
  psql_query "SELECT proname AS silver_function FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='silver' ORDER BY proname;"
  echo "Host disk:"
  df -h "$ROOT"
  exit 0
fi

require_apply
if [[ "$ACTION" == transform-nvd ]]; then
  [[ "$CONFIRM_NVD" -eq 1 ]] ||
    { echo "STOP: --confirm-large-nvd required for full NVD transformation" >&2; exit 2; }
  require_host_space
fi

case "$ACTION" in
  init)
    run_file sql/bronze/001_create_tables.sql
    run_file sql/silver/001_create_tables.sql
    ;;
  snapshot-oltp)
    run_file sql/bronze/002_snapshot_oltp.sql
    ;;
  inventory)
    run_file sql/silver/005_inventory.sql
    ;;
  transform-kev)
    run_file sql/silver/004_transform_kev.sql
    ;;
  transform-epss)
    run_file sql/silver/002_transform_epss.sql
    ;;
  transform-nvd)
    run_file sql/silver/003_transform_nvd.sql
    ;;
  functions)
    {
      printf 'BEGIN;\n'
      for n in \
        006_cpe_match \
        007_version_compare \
        008_version_range \
        009_cpe_rule_match \
        010_configuration_logic \
        011_asset_rule_state \
        012_nvd_node \
        013_evaluate_cve
      do
        file="sql/silver/${n}.sql"
        [[ -f "$file" ]] || { echo "STOP: Missing $file" >&2; exit 1; }
        cat "$file"
        printf '\n'
      done
      printf 'COMMIT;\n'
    } | docker exec -i "$CONTAINER" psql -X -v ON_ERROR_STOP=1 \
      -U "$DB_USER" -d "$DB"
    ;;
esac
echo "PASS: $ACTION completed"
