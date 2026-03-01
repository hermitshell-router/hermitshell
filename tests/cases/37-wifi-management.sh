#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- Idempotency: remove any leftover providers from prior runs ---
for pid in $(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK" | grep -oP '"id":"[^"]+"' | grep -oP '(?<="id":")[^"]+'); do
    vm_exec router "echo '{\"method\":\"wifi_remove_provider\",\"provider_id\":\"$pid\"}' | socat - $SOCK" >/dev/null 2>&1
done

# --- wifi_list_providers defaults empty ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_list_providers succeeds"
assert_match "$result" '"wifi_providers":\[\]' "no providers by default"

# --- wifi_add_provider (eap_standalone) ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"protocol\":\"eap_standalone\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"url\":\"192.168.1.100\",\"name\":\"Office AP\",\"key\":\"admin\",\"value\":\"testpass123\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "wifi_add_provider succeeds"

# --- extract provider_id ---
PROVIDER_ID=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['wifi_providers'][0]['id'] if d.get('wifi_providers') else '')")
if [ -z "$PROVIDER_ID" ]; then
    fail "could not extract provider_id"
fi
echo "PASS: extracted provider_id=$PROVIDER_ID"

# --- verify password is encrypted (not plaintext) ---
vm_sudo router "chmod 644 /var/lib/hermitshell/hermitshell.db"
stored_pass=$(vm_exec router "python3 -c \"import sqlite3; r = sqlite3.connect('/var/lib/hermitshell/hermitshell.db').execute('SELECT password_enc FROM wifi_providers WHERE id=\\\"$PROVIDER_ID\\\"').fetchone(); print(r[0] if r else '')\"")
vm_sudo router "chmod 600 /var/lib/hermitshell/hermitshell.db"
if [ "$stored_pass" = "testpass123" ]; then
    fail "password stored as plaintext"
fi
assert_match "$stored_pass" '.' "password_enc is not empty"
echo "PASS: password is encrypted (not plaintext)"

# --- wifi_list_providers shows provider ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_list_providers after add succeeds"
assert_match "$result" 'Office AP' "provider name appears"
assert_match "$result" 'eap_standalone' "provider type appears"
assert_match "$result" '"status"' "provider status field present"

# --- wifi_list_aps shows discovered AP ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_list_aps after add_provider succeeds"
assert_match "$result" 'aa:bb:cc:dd:ee:01' "AP MAC appears in list"
assert_match "$result" "\"provider_id\":\"$PROVIDER_ID\"" "AP has correct provider_id"

# --- wifi_add_provider validation: without url ---
result=$(vm_exec router "echo '{\"method\":\"wifi_add_provider\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"name\":\"Test\",\"key\":\"admin\",\"value\":\"pass\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_add_provider without url fails"

# --- wifi_add_provider validation: without password ---
result=$(vm_exec router "echo '{\"method\":\"wifi_add_provider\",\"mac\":\"aa:bb:cc:dd:ee:02\",\"url\":\"192.168.1.101\",\"name\":\"Test\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_add_provider without password fails"

# --- wifi_add_provider validation: invalid IP for eap_standalone ---
result=$(vm_exec router "echo '{\"method\":\"wifi_add_provider\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"not-an-ip\",\"name\":\"Bad\",\"key\":\"admin\",\"value\":\"pass\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_add_provider rejects invalid IP"

# --- wifi_add_provider validation: invalid name ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"192.168.1.102\",\"name\":\"bad<name>\",\"key\":\"admin\",\"value\":\"pass\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_add_provider rejects name with special chars"

# --- wifi_add_provider validation: unknown provider type ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"mac\":\"aa:bb:cc:dd:ee:03\",\"url\":\"192.168.1.102\",\"name\":\"Test\",\"key\":\"admin\",\"value\":\"pass\",\"protocol\":\"fake\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_add_provider rejects unknown provider type"

# --- wifi_add_provider validation: unifi type accepted ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"url\":\"https://192.168.1.200:8443\",\"name\":\"UniFi Test\",\"key\":\"admin\",\"value\":\"pass\",\"protocol\":\"unifi\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "wifi_add_provider accepts unifi type"

# Remove the unifi provider we just added
UNIFI_PID=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK" | python3 -c "import sys,json; d=json.load(sys.stdin); ps=[p for p in d.get('wifi_providers',[]) if p['provider_type']=='unifi']; print(ps[0]['id'] if ps else '')")
if [ -n "$UNIFI_PID" ]; then
    vm_exec router "echo '{\"method\":\"wifi_remove_provider\",\"provider_id\":\"$UNIFI_PID\"}' | socat - $SOCK" >/dev/null 2>&1
fi

# --- wifi_add_provider validation: unifi with bad URL ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"url\":\"not-a-url\",\"name\":\"UniFi Bad\",\"key\":\"admin\",\"value\":\"pass\",\"protocol\":\"unifi\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_add_provider rejects invalid unifi URL"

# --- wifi_add_provider validation: unifi requires https ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"url\":\"http://192.168.1.200:8443\",\"name\":\"UniFi HTTP\",\"key\":\"admin\",\"value\":\"pass\",\"protocol\":\"unifi\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_add_provider rejects http for unifi"

# --- wifi_get_clients (empty, no real APs) ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_clients\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_get_clients succeeds"

# --- wifi_remove_provider ---
result=$(vm_exec router "echo '{\"method\":\"wifi_remove_provider\",\"provider_id\":\"$PROVIDER_ID\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_remove_provider succeeds"

# --- verify removed ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"wifi_providers":\[\]' "provider removed from list"

result=$(vm_exec router "echo '{\"method\":\"wifi_list_aps\"}' | socat - $SOCK")
assert_match "$result" '"wifi_aps":\[\]' "cascade-deleted APs also removed"

# --- audit log recorded ---
result=$(vm_exec router "echo '{\"method\":\"list_audit_logs\",\"limit\":10}' | socat - $SOCK")
assert_match "$result" 'wifi_add_provider' "add_provider audit logged"
assert_match "$result" 'wifi_remove_provider' "remove_provider audit logged"

# --- wifi_get_ssids requires provider_id ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_ssids\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_get_ssids without provider_id fails"

# --- wifi_set_ssid validates band ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_set_ssid\",\"provider_id\":\"fake-id\",\"ssid_name\":\"Test\",\"band\":\"invalid\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_set_ssid rejects invalid band"

# --- wifi_set_ssid validates ssid_name length ---
long_name=$(printf 'A%.0s' {1..33})
result=$(vm_exec router "echo '{\"method\":\"wifi_set_ssid\",\"provider_id\":\"fake-id\",\"ssid_name\":\"$long_name\",\"band\":\"5GHz\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_ssid rejects SSID >32 chars"

# --- wifi_get_radios for non-existent AP ---
result=$(vm_exec router "echo '{\"method\":\"wifi_get_radios\",\"mac\":\"ff:ff:ff:ff:ff:ff\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_get_radios for missing AP fails"

# --- wifi_set_radio without band fails ---
result=$(vm_exec router "echo '{\"method\":\"wifi_set_radio\",\"mac\":\"aa:bb:cc:dd:ee:01\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_radio without band fails"

# --- wifi_set_radio rejects invalid band ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_set_radio\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"band\":\"invalid\",\"channel\":\"Auto\",\"channel_width\":\"Auto\",\"tx_power\":\"25dBm\",\"enabled\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_set_radio rejects invalid band"

# --- Re-add provider for CA cert and TOFU tests ---
result=$(vm_exec router 'echo "{\"method\":\"wifi_add_provider\",\"protocol\":\"eap_standalone\",\"mac\":\"aa:bb:cc:dd:ee:01\",\"url\":\"192.168.1.100\",\"name\":\"Office AP\",\"key\":\"admin\",\"value\":\"testpass123\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "re-add provider for cert tests"

PROVIDER_ID=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['wifi_providers'][0]['id'] if d.get('wifi_providers') else '')")

# --- generate test CA cert ---
TEST_CA_PEM=$(vm_exec router 'openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 1 -nodes -subj "/CN=testca" 2>/dev/null')

# --- wifi_set_provider_ca_cert ---
CA_REQ=$(python3 -c "
import json
pem = '''$TEST_CA_PEM'''
print(json.dumps({'method': 'wifi_set_provider_ca_cert', 'provider_id': '$PROVIDER_ID', 'value': pem}))
")
result=$(echo "$CA_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "wifi_set_provider_ca_cert succeeds"

# --- wifi_list_providers shows has_ca_cert ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":true' "wifi_list_providers shows has_ca_cert"

# --- invalid PEM rejected ---
INVALID_REQ=$(python3 -c "import json; print(json.dumps({'method': 'wifi_set_provider_ca_cert', 'provider_id': '$PROVIDER_ID', 'value': 'garbage'}))")
result=$(echo "$INVALID_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "wifi_set_provider_ca_cert rejects invalid PEM"

# --- clear CA cert ---
result=$(vm_exec router "echo '{\"method\":\"wifi_set_provider_ca_cert\",\"provider_id\":\"$PROVIDER_ID\",\"value\":\"\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "wifi_set_provider_ca_cert clears cert"

result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":false' "has_ca_cert false after clear"

# --- wifi_set_provider_ca_cert on non-existent provider ---
result=$(vm_exec router "echo '{\"method\":\"wifi_set_provider_ca_cert\",\"provider_id\":\"nonexistent-id\",\"value\":\"test\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "wifi_set_provider_ca_cert rejects missing provider"

# --- TOFU: verify ca_cert_pem starts empty for new provider ---
vm_sudo router "chmod 644 /var/lib/hermitshell/hermitshell.db"
result=$(vm_exec router "python3 -c \"import sqlite3; r = sqlite3.connect('/var/lib/hermitshell/hermitshell.db').execute('SELECT ca_cert_pem FROM wifi_providers WHERE id=\\\"$PROVIDER_ID\\\"').fetchone(); print(r[0] if r and r[0] else 'NONE')\"")
vm_sudo router "chmod 600 /var/lib/hermitshell/hermitshell.db"
assert_match "$result" 'NONE' "new provider has no ca_cert_pem (TOFU not yet triggered)"

# --- TOFU: simulate TOFU by setting ca_cert_pem via API ---
TEST_TOFU_PEM=$(vm_exec router 'openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out /dev/stdout -days 1 -nodes -subj "/CN=ap-tofu" 2>/dev/null')
TOFU_REQ=$(python3 -c "
import json
pem = '''$TEST_TOFU_PEM'''
print(json.dumps({'method': 'wifi_set_provider_ca_cert', 'provider_id': '$PROVIDER_ID', 'value': pem}))
")
result=$(echo "$TOFU_REQ" | vm_exec router 'socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "TOFU: set pinned cert succeeds"

# --- verify has_ca_cert is now true ---
result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":true' "TOFU: has_ca_cert true after pin"

# --- clearing cert resets for re-TOFU ---
result=$(vm_exec router "echo '{\"method\":\"wifi_set_provider_ca_cert\",\"provider_id\":\"$PROVIDER_ID\",\"value\":\"\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "TOFU: clear pinned cert succeeds"

result=$(vm_exec router "echo '{\"method\":\"wifi_list_providers\"}' | socat - $SOCK")
assert_match "$result" '"has_ca_cert":false' "TOFU: has_ca_cert false after clear"

# --- Clean up: remove provider ---
result=$(vm_exec router "echo '{\"method\":\"wifi_remove_provider\",\"provider_id\":\"$PROVIDER_ID\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "cleanup: remove provider"
