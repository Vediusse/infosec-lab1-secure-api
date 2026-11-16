#!/usr/bin/env bash
# Start API and seed an account before running. Export DEMO_PASSWORD locally.
set -euo pipefail
BASE=http://127.0.0.1:5051
: "${DEMO_PASSWORD:?Set DEMO_PASSWORD}"
printf '\n1. No token -> 401\n'
curl -sS -i "$BASE/api/data"
printf '\n2. SQL injection -> 401\n'
curl -sS -i -X POST "$BASE/auth/login" -H 'Content-Type: application/json' --data "{\"username\":\"student' OR 1=1 --\",\"password\":\"wrong\"}"
printf '\n3. Login -> JWT (token omitted from transcript)\n'
TOKEN=$(python -c 'import json,os; print(json.dumps({"username":"student","password":os.environ["DEMO_PASSWORD"]}))' | curl -sS "$BASE/auth/login" -H 'Content-Type: application/json' --data-binary @- | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
printf 'JWT issued successfully\n'
printf '\n4. XSS is escaped -> 201\n'
curl -sS -i "$BASE/api/notes" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' --data '{"text":"<script>alert(1)</script>"}'
printf '\n5. Authorized data -> 200\n'
curl -sS -i "$BASE/api/data" -H "Authorization: Bearer $TOKEN"
printf '\n6. Forged token -> 401\n'
curl -sS -i "$BASE/api/data" -H 'Authorization: Bearer invalid.signature.token'
