#!/usr/bin/env bash
set -euo pipefail

DATA_ROOT="deploy/pir-server"
DATA_ONE="$DATA_ROOT/data1"
DATA_TWO="$DATA_ROOT/data2"
DB_ONE="$DATA_ONE/pir.db"
DB_TWO="$DATA_TWO/pir.db"

mkdir -p "$DATA_ONE" "$DATA_TWO"

pir_server --database "$DB_ONE" build \
  --lightwalletd https://testnet.zec.rocks:443 \
  --start 2400000 \
  --end 2500000 \
  --bucket-size 1000

cp "$DB_ONE" "$DB_TWO"

docker-compose -f deploy/pir-server/docker-compose.yml up -d

echo "PIR servers now listening at:"
echo "  http://localhost:8080"
echo "  http://localhost:8081"
