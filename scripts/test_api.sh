#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
EMAIL="${EMAIL:-utente_test_$(date +%s)@example.com}"
PASSWORD="${PASSWORD:-Pass123!}"
NAME="${NAME:-Utente Test}"
TARGET_SEGMENT="${TARGET_SEGMENT:-privati}"

echo "== Registration OTP =="
OTP_RESP=$(curl -s -X POST "$BASE_URL/auth/registration/request-otp" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"target_segment\":\"$TARGET_SEGMENT\"}")
echo "$OTP_RESP"

REGISTRATION_OTP_CODE=$(python3 - <<'PY' "$OTP_RESP"
import json,sys
payload = json.loads(sys.argv[1])
print(payload.get("registration_otp_code") or payload.get("dev_registration_otp_code") or "")
PY
)

if [ -z "$REGISTRATION_OTP_CODE" ]; then
  echo "Errore: OTP registrazione mancante"
  exit 1
fi

echo "== Register =="
REGISTER_RESP=$(curl -s -X POST "$BASE_URL/users" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$NAME\",\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"target_segment\":\"$TARGET_SEGMENT\",\"registration_otp_code\":\"$REGISTRATION_OTP_CODE\"}")
echo "$REGISTER_RESP"

echo "== Login =="
LOGIN_RESP=$(curl -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN_RESP"

ACCESS_TOKEN=$(python3 - <<'PY' "$LOGIN_RESP"
import json,sys
print(json.loads(sys.argv[1]).get("access_token",""))
PY
)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "Errore: access token mancante"
  exit 1
fi

echo "== Missions =="
curl -s "$BASE_URL/missions"
echo

echo "== Wallet =="
curl -s "$BASE_URL/wallet/me" -H "Authorization: Bearer $ACCESS_TOKEN"
echo

echo "== Products =="
curl -s "$BASE_URL/products"
echo

echo "Test API completato."
