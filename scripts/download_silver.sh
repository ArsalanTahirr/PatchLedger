#!/usr/bin/env bash
set -euo pipefail

REPO="patchledger/patchledger-data"
REVISION="2cc5ee095a06b80d6579b89b98dcf1089085ca11"

DATA_DIR="${1:-../PatchLedgerData}"

mkdir -p "$DATA_DIR"

echo "Downloading validated Silver v1..."

uvx --from huggingface_hub hf download \
  "$REPO" \
  --repo-type dataset \
  --revision "$REVISION" \
  --include "silver/v1/*" \
  --local-dir "$DATA_DIR"

for name in \
  nvd_clean.csv \
  nvd_affected_cpe.csv \
  epss_clean.csv \
  kev_clean.csv
do
  test -s "$DATA_DIR/silver/v1/$name" || {
    echo "ERROR: Missing or empty file: $name"
    exit 1
  }
done

echo "Silver v1 downloaded successfully."
echo "Dataset location: $DATA_DIR/silver/v1"
