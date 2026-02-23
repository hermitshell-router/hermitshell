#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- get_tls_status returns mode and cert info ---
result=$(vm_exec router "echo '{\"method\":\"get_tls_status\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_tls_status succeeds"
assert_match "$result" '"tls_mode":"self_signed"' "default tls_mode is self_signed"
assert_match "$result" '"issuer"' "get_tls_status returns issuer"
assert_match "$result" '"expires_at"' "get_tls_status returns expiry"
assert_match "$result" '"sans"' "get_tls_status returns SANs"

# --- Generate a test cert for upload ---
test_cert=$(vm_sudo router 'cd /tmp && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout test.key -out test.crt -days 1 -subj "/CN=test.hermitshell.local" 2>/dev/null && cat test.crt')
test_key=$(vm_sudo router 'cat /tmp/test.key')

# --- set_tls_cert with valid PEM via jq ---
result=$(vm_exec router "jq -n --arg cert \"\$(cat /tmp/test.crt)\" --arg key \"\$(cat /tmp/test.key)\" '{method:\"set_tls_cert\",tls_cert_pem:\$cert,tls_key_pem:\$key}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_tls_cert succeeds with valid PEM"

# --- verify tls_mode changed to custom ---
result=$(vm_exec router "echo '{\"method\":\"get_tls_status\"}' | socat - $SOCK")
assert_match "$result" '"tls_mode":"custom"' "tls_mode is custom after upload"
assert_match "$result" 'test.hermitshell.local' "cert CN matches uploaded cert"

# --- get_tls_config returns the uploaded cert ---
result=$(vm_exec router "echo '{\"method\":\"get_tls_config\"}' | socat - $SOCK")
assert_match "$result" 'test.hermitshell.local' "get_tls_config returns uploaded cert"

# --- set_tls_cert rejects invalid PEM ---
result=$(vm_exec router "echo '{\"method\":\"set_tls_cert\",\"tls_cert_pem\":\"not a cert\",\"tls_key_pem\":\"not a key\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "set_tls_cert rejects invalid PEM"

# --- set_tls_cert rejects missing fields ---
result=$(vm_exec router "echo '{\"method\":\"set_tls_cert\",\"tls_cert_pem\":\"test\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "set_tls_cert rejects missing key"
