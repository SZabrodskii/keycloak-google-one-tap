#!/usr/bin/env bash
# End-to-end smoke test against a throwaway Keycloak (docker/compose.yml) with the built jar:
#   1. both providers are registered (server info);
#   2. an exchange aimed at a google-one-tap instance is served by this extension's token
#      exchange provider and validated as a Google ID token;
#   3. an exchange aimed at a plain google instance is left to Keycloak's own provider.
# Needs: docker compose, curl, python3, and build/libs/*.jar (scripts/gradlew-docker.sh shadowJar).
set -euo pipefail
cd "$(dirname "$0")/.."

KC=${KC:-http://localhost:9000}
REALM=onetap
COMPOSE=(docker compose -f docker/compose.yml)

j() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# KEEP=1 leaves the Keycloak container running for inspection after the run.
cleanup() { [ "${KEEP:-0}" = "1" ] || "${COMPOSE[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

ls build/libs/*.jar >/dev/null 2>&1 || fail "no jar in build/libs — run scripts/gradlew-docker.sh shadowJar first"

echo "[*] starting keycloak 26.2.5 with $(ls build/libs/*.jar)"
"${COMPOSE[@]}" up -d --wait

TOK=$(curl -sf -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli -d username=admin -d password=admin | j 'd["access_token"]')
A=(-H "Authorization: Bearer $TOK" -H "Content-Type: application/json")

echo "[*] providers registered"
INFO=$(curl -sf "${A[@]}" "$KC/admin/serverinfo")
echo "$INFO" | j '"google-one-tap" in d["providers"]["social"]["providers"]' | grep -q True \
  || fail "social identity provider google-one-tap is not registered"
echo "$INFO" | j '"google-one-tap" in d["providers"]["oauth2-token-exchange"]["providers"]' | grep -q True \
  || fail "token exchange provider google-one-tap is not registered"
echo "    social: google-one-tap ✓   oauth2-token-exchange: google-one-tap ✓"

echo "[*] realm, identity providers, client"
curl -sf "${A[@]}" -X POST "$KC/admin/realms" -d "{\"realm\":\"$REALM\",\"enabled\":true,\"eventsEnabled\":true}"
curl -sf "${A[@]}" -X POST "$KC/admin/realms/$REALM/identity-provider/instances" -d '{
  "alias":"google-one-tap","providerId":"google-one-tap","enabled":true,"trustEmail":true,
  "config":{"clientId":"smoke.apps.googleusercontent.com","clientSecret":"unused"}}'
curl -sf "${A[@]}" -X POST "$KC/admin/realms/$REALM/identity-provider/instances" -d '{
  "alias":"google","providerId":"google","enabled":true,"trustEmail":true,
  "config":{"clientId":"smoke.apps.googleusercontent.com","clientSecret":"unused"}}'
curl -sf "${A[@]}" -X POST "$KC/admin/realms/$REALM/clients" -d '{
  "clientId":"exchanger","secret":"exchanger-secret","publicClient":false,
  "serviceAccountsEnabled":true,"standardFlowEnabled":false,"directAccessGrantsEnabled":false}'
EXCHANGER_ID=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients?clientId=exchanger" | j 'd[0]["id"]')
RM_ID=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients?clientId=realm-management" | j 'd[0]["id"]')

grant_exchange() {
  local alias=$1
  local perm_id policy_id resource_id scope_id
  perm_id=$(curl -sf "${A[@]}" -X PUT "$KC/admin/realms/$REALM/identity-provider/instances/$alias/management/permissions" \
    -d '{"enabled":true}' | j 'd["scopePermissions"]["token-exchange"]')
  policy_id=$(curl -sf "${A[@]}" -X POST "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/policy/client" \
    -d "{\"name\":\"exchanger-to-$alias\",\"clients\":[\"$EXCHANGER_ID\"],\"logic\":\"POSITIVE\"}" | j 'd["id"]')
  resource_id=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/policy/$perm_id/resources" | j 'd[0]["_id"]')
  scope_id=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/policy/$perm_id/scopes" | j 'd[0]["id"]')
  # Update the permission Keycloak generated (same id and name) — only attach the policy.
  local body
  body=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/permission/scope/$perm_id" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); d.update(resources=['$resource_id'], scopes=['$scope_id'], policies=['$policy_id']); print(json.dumps(d))")
  curl -sf "${A[@]}" -X PUT "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/permission/scope/$perm_id" -d "$body" >/dev/null
  local attached
  attached=$(curl -sf "${A[@]}" "$KC/admin/realms/$REALM/clients/$RM_ID/authz/resource-server/policy/$perm_id/associatedPolicies" | j 'len(d)')
  [ "$attached" = "1" ] || fail "token-exchange permission on $alias has $attached associated policies, want 1"
}
echo "[*] granting token-exchange permission to client exchanger on both providers"
grant_exchange google-one-tap
grant_exchange google

exchange() {
  local issuer=$1 type=$2
  curl -s -o /tmp/smoke-body -w '%{http_code}' -X POST "$KC/realms/$REALM/protocol/openid-connect/token" \
    -d client_id=exchanger -d client_secret=exchanger-secret \
    -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d subject_issuer="$issuer" -d subject_token_type="$type" \
    -d subject_token=this.is.not.a.google.token
}
last_event() {
  curl -sf "${A[@]}" "$KC/admin/realms/$REALM/events?type=TOKEN_EXCHANGE_ERROR&max=1" | j 'json.dumps(d[0]["details"])'
}

echo "[*] exchange id_token → google-one-tap (this extension)"
CODE=$(exchange google-one-tap urn:ietf:params:oauth:token-type:id_token)
BODY=$(cat /tmp/smoke-body)
EV=$(last_event)
echo "    HTTP $CODE $BODY"
echo "    event: $EV"
[ "$CODE" = "400" ] || fail "expected 400 for a bogus id token, got $CODE"
echo "$EV" | grep -q '"token_exchange_provider": "google-one-tap"' || fail "exchange was not served by the google-one-tap token exchange provider"
echo "$EV" | grep -q '"validation_method": "google id token"' || fail "id token was not validated by the google-one-tap identity provider"
echo "$EV" | grep -q '"reason": "id token rejected"' || fail "unexpected rejection reason"

echo "[*] exchange access_token → google-one-tap (inherited user info path)"
CODE=$(exchange google-one-tap urn:ietf:params:oauth:token-type:access_token)
EV=$(last_event)
echo "    HTTP $CODE $(cat /tmp/smoke-body)"
echo "    event: $EV"
[ "$CODE" = "400" ] || fail "expected 400, got $CODE"
echo "$EV" | grep -q '"validation_method": "user info"' || fail "access token was not validated through user info"

echo "[*] exchange id_token → google (must stay with keycloak's own provider)"
CODE=$(exchange google urn:ietf:params:oauth:token-type:id_token)
EV=$(last_event)
echo "    HTTP $CODE $(cat /tmp/smoke-body)"
echo "    event: $EV"
[ "$CODE" = "400" ] || fail "expected 400, got $CODE"
echo "$EV" | grep -q 'token_exchange_provider' && fail "plain google exchange was hijacked by the google-one-tap provider"
echo "$EV" | grep -q '"reason": "subject_token_type invalid"' || fail "keycloak's google provider did not answer as expected"

echo "SMOKE OK"
