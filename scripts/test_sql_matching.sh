#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

container="patchledger-postgres"
db="patchledger_sql_test_$(date +%s)_$$"

docker exec "$container" pg_isready -U patchledger -d patchledger >/dev/null

echo "Creating isolated test database: $db"
docker exec "$container" createdb -U patchledger "$db"

cleanup() {
    echo "Removing isolated test database: $db"
    docker exec "$container" dropdb -U patchledger --if-exists -f "$db"
}

trap cleanup EXIT

run_sql() {
    docker exec -i "$container" \
        psql -X -v ON_ERROR_STOP=1 \
        -U patchledger -d "$db"
}

echo "Creating Bronze tables..."
run_sql < sql/bronze/001_create_tables.sql

echo "Creating Silver tables..."
run_sql < sql/silver/001_create_tables.sql

echo "Creating Silver inventory table..."
run_sql < sql/silver/005_inventory.sql

echo "Running matching regression tests..."

{
    printf 'BEGIN;\n'

    for file in \
        sql/silver/006_cpe_match.sql \
        sql/silver/007_version_compare.sql \
        sql/silver/008_version_range.sql \
        sql/silver/009_cpe_rule_match.sql \
        sql/silver/010_configuration_logic.sql \
        sql/silver/011_asset_rule_state.sql \
        sql/silver/012_nvd_node.sql \
        sql/silver/013_evaluate_cve.sql
    do
        cat "$file"
        printf '\n'
    done

    cat tests/sql/fixtures_inventory.sql
    cat tests/sql/test_nvd_matching.sql

    printf '\nROLLBACK;\n'
} | run_sql

echo "PASS: SQL matching regression suite completed."
