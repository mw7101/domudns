#!/bin/bash
# Check PTR setup: DB records + DNS query
# Usage: ./scripts/check-ptr.sh [IP]
# Example: ./scripts/check-ptr.sh 192.0.2.1

set -e
IP="${1:-192.0.2.1}"
DSN="${DNS_STACK_POSTGRES_DSN:-host=localhost port=5432 user=postgres password=dnsstack dbname=dnsstack sslmode=disable}"

# Parse IP to get reverse zone and name (e.g. 192.0.2.1 -> zone 100.168.192.in-addr.arpa, name 5)
IFS='.' read -r o1 o2 o3 o4 <<< "$IP"
ZONE="${o3}.${o2}.${o1}.in-addr.arpa"
NAME="${o4}"

echo "=== PTR check for $IP ==="
echo "Expected zone: $ZONE"
echo "Expected record name: $NAME"
echo

echo "=== coredns_records in PostgreSQL ==="
psql "$DSN" -t -c "SELECT zone, name, record_type, content FROM coredns_records WHERE zone LIKE '%${o3}.${o2}.${o1}%' ORDER BY zone, name;"
echo

echo "=== DNS query (use 127.0.0.1 not localhost - config may listen IPv4 only) ==="
host "$IP" 127.0.0.1 2>/dev/null || echo "host failed - is CoreDNS running on :53?"
echo

echo "=== If PTR missing: re-save the PTR record in Web UI to trigger PutZone"
