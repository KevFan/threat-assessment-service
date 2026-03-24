#!/usr/bin/env bash
set -euo pipefail

ADDR="localhost:18080"
BINARY="$(git rev-parse --show-toplevel)/bin/threat-service"
PASS=0
FAIL=0

# ── helpers ──────────────────────────────────────────────────────────────────

log()  { echo "  $*"; }
ok()   { echo "  ✓ $*"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $*"; FAIL=$((FAIL+1)); }

assess() {
  grpcurl -plaintext -d "$1" "$ADDR" threat.v1.ThreatAssessmentService/AssessRequest 2>/dev/null
}

check_level() {
  local name="$1" payload="$2" want="$3"
  local got
  got=$(assess "$payload" | grep -o '"threatLevel": *[0-9]*' | grep -o '[0-9]*' || echo "0")
  if [ "$got" = "$want" ]; then
    ok "$name (threat_level=$got)"
  else
    fail "$name: expected threat_level=$want, got $got"
  fi
}

# ── build & start server ─────────────────────────────────────────────────────

echo "Building..."
make -C "$(git rev-parse --show-toplevel)" build > /dev/null

echo "Starting server on $ADDR..."
GRPC_ADDR=":18080" BLACKLIST_IPS="192.0.2.100,203.0.113.50,198.51.100.25" "$BINARY" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null; wait $SERVER_PID 2>/dev/null' EXIT

# wait for server to be ready
for i in $(seq 1 20); do
  if grpcurl -plaintext "$ADDR" list >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
  if [ "$i" -eq 20 ]; then
    echo "Server did not start in time"
    exit 1
  fi
done

# ── reflection check ─────────────────────────────────────────────────────────

echo ""
echo "Checking gRPC reflection..."
if grpcurl -plaintext "$ADDR" list | grep -q "threat.v1.ThreatAssessmentService"; then
  ok "ThreatAssessmentService visible via reflection"
else
  fail "ThreatAssessmentService not found via reflection"
fi

# ── test scenarios (from issue #1837) ────────────────────────────────────────

echo ""
echo "Running test scenarios..."

check_level "clean request" \
  '{"uri":"/users","is_authenticated":true,"source_ip":"10.0.0.1"}' 0

check_level "unauthenticated request" \
  '{"uri":"/users","is_authenticated":false,"source_ip":"10.0.0.1"}' 1

check_level "blacklisted IP" \
  '{"uri":"/users","is_authenticated":false,"source_ip":"192.0.2.100"}' 6

check_level "path traversal attempt" \
  '{"uri":"/../../etc/passwd","is_authenticated":false,"source_ip":"10.0.0.1"}' 5

check_level "unauthenticated admin access" \
  '{"uri":"/admin/users","is_authenticated":false,"source_ip":"10.0.0.1"}' 4

# ── summary ──────────────────────────────────────────────────────────────────

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
