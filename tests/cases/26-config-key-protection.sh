#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

SOCK="UNIX-CONNECT:/run/hermitshell/agent.sock"

# --- Blocked config key reads ---
for key in admin_password_hash session_secret wg_private_key tls_key_pem tls_cert_pem; do
    result=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"$key\"}' | socat - $SOCK")
    assert_match "$result" '"ok":false' "get_config blocks $key"
    assert_match "$result" 'access denied' "get_config $key returns access denied"
done

# --- Blocked config key writes ---
for key in admin_password_hash session_secret wg_private_key tls_key_pem tls_cert_pem; do
    result=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"$key\",\"value\":\"hack\"}' | socat - $SOCK")
    assert_match "$result" '"ok":false' "set_config blocks $key"
    assert_match "$result" 'access denied' "set_config $key returns access denied"
done

# --- Non-secret keys still work ---
result=$(vm_exec router "echo '{\"method\":\"set_config\",\"key\":\"test_key_26\",\"value\":\"hello\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "set_config allows non-secret key"

result=$(vm_exec router "echo '{\"method\":\"get_config\",\"key\":\"test_key_26\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_config allows non-secret key"
assert_match "$result" 'hello' "get_config returns correct value"

# --- has_password ---
result=$(vm_exec router "echo '{\"method\":\"has_password\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "has_password responds"
assert_match "$result" '"config_value"' "has_password returns config_value"

# --- verify_password with no password set ---
result=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrongpass\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "verify_password responds when no password set"
assert_match "$result" '"false"' "verify_password returns false when no password"

# --- verify_password missing value ---
result=$(vm_exec router "echo '{\"method\":\"verify_password\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "verify_password requires value"

# --- setup_password rejects short password ---
result=$(vm_exec router "echo '{\"method\":\"setup_password\",\"value\":\"short\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "setup_password rejects short password"
assert_match "$result" 'too short' "setup_password says too short"

# --- setup_password rejects long password ---
long_pw=$(printf 'x%.0s' $(seq 1 129))
result=$(vm_exec router "echo '{\"method\":\"setup_password\",\"value\":\"$long_pw\"}' | socat - $SOCK")
assert_match "$result" '"ok":false' "setup_password rejects long password"
assert_match "$result" 'too long' "setup_password says too long"

# --- setup_password succeeds (first time, no current password needed) ---
result=$(vm_exec router "echo '{\"method\":\"setup_password\",\"value\":\"testpass123\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "setup_password succeeds first time"

# --- has_password now returns true ---
result=$(vm_exec router "echo '{\"method\":\"has_password\"}' | socat - $SOCK")
assert_match "$result" '"true"' "has_password returns true after setup"

# --- verify_password with correct password ---
result=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"testpass123\"}' | socat - $SOCK")
assert_match "$result" '"true"' "verify_password accepts correct password"

# --- verify_password with wrong password ---
result=$(vm_exec router "echo '{\"method\":\"verify_password\",\"value\":\"wrongpass\"}' | socat - $SOCK")
assert_match "$result" '"false"' "verify_password rejects wrong password"

# --- create_session returns a cookie ---
result=$(vm_exec router "echo '{\"method\":\"create_session\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "create_session succeeds"
assert_match "$result" 'admin:' "create_session returns admin cookie"

# Extract cookie value for verify_session
cookie=$(echo "$result" | sed 's/.*"config_value":"\([^"]*\)".*/\1/')

# --- verify_session accepts valid cookie ---
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"$cookie\"}' | socat - $SOCK")
assert_match "$result" '"true"' "verify_session accepts valid cookie"

# --- verify_session rejects invalid cookie ---
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"admin:0.badsignature\"}' | socat - $SOCK")
assert_match "$result" '"false"' "verify_session rejects invalid cookie"

# --- verify_session rejects malformed cookie ---
result=$(vm_exec router "echo '{\"method\":\"verify_session\",\"value\":\"garbage\"}' | socat - $SOCK")
assert_match "$result" '"false"' "verify_session rejects malformed cookie"

# --- get_tls_config returns cert ---
result=$(vm_exec router "echo '{\"method\":\"get_tls_config\"}' | socat - $SOCK")
assert_match "$result" '"ok":true' "get_tls_config succeeds"
assert_match "$result" 'tls_cert_pem' "get_tls_config returns cert"
assert_match "$result" 'tls_key_pem' "get_tls_config returns key"
assert_match "$result" 'BEGIN CERTIFICATE' "get_tls_config cert is PEM"

# --- Clean up: remove the password we set (directly via DB since set_config is blocked) ---
# We don't need to clean up; the test DB is ephemeral.
