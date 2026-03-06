#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_docker
require_lan_ip

ROUTER=https://10.0.0.1
SOCK=/run/hermitshell/agent.sock

# Helper: generate TOTP code on router VM (same clock as agent)
generate_totp_code() {
    local s=$1
    vm_exec router "python3 -c \"
import hmac, hashlib, struct, time, base64
key = base64.b32decode('$s')
t = int(time.time()) // 30
msg = struct.pack('>Q', t)
h = hmac.new(key, msg, hashlib.sha1).digest()
offset = h[19] & 0x0f
code = ((h[offset] & 0x7f) << 24 | h[offset+1] << 16 | h[offset+2] << 8 | h[offset+3]) % 10**6
print(f'{code:06d}')
\""
}

# --- 1. TOTP status defaults to disabled ---
status_result=$(vm_exec router "echo '{\"method\":\"totp_status\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$status_result" '"ok":true' "totp_status returns ok"
assert_contains "$status_result" '"config_value":"false"' "TOTP disabled by default"

# --- 2. TOTP setup generates secret and otpauth URI ---
setup_result=$(vm_exec router "echo '{\"method\":\"totp_setup\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$setup_result" '"ok":true' "totp_setup returns ok"
assert_contains "$setup_result" "otpauth://totp/" "totp_setup returns otpauth URI"

# --- 3. Extract base32 secret from setup response ---
secret=$(echo "$setup_result" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
config = json.loads(resp['config_value'])
print(config['secret'])
")
assert_match "$secret" "^[A-Z2-7]+" "Extracted base32 secret from setup"

# --- 4. Generate valid TOTP code ---
totp_code=$(generate_totp_code "$secret")
assert_match "$totp_code" "^[0-9]{6}$" "Generated 6-digit TOTP code"

# --- 5. Verify valid code works ---
verify_result=$(vm_exec router "echo '{\"method\":\"totp_verify\",\"value\":\"$totp_code\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$verify_result" '"ok":true' "totp_verify returns ok"
assert_contains "$verify_result" '"config_value":"true"' "Valid TOTP code accepted"

# --- 6. Verify invalid code rejects ---
invalid_result=$(vm_exec router "echo '{\"method\":\"totp_verify\",\"value\":\"000000\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$invalid_result" '"config_value":"false"' "Invalid TOTP code rejected"

# --- 7. Enable TOTP with fresh valid code ---
enable_code=$(generate_totp_code "$secret")
enable_result=$(vm_exec router "echo '{\"method\":\"totp_enable\",\"value\":\"$enable_code\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$enable_result" '"ok":true' "totp_enable succeeds with valid code"

# --- 8. Verify TOTP status is now enabled ---
status_enabled=$(vm_exec router "echo '{\"method\":\"totp_status\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$status_enabled" '"config_value":"true"' "TOTP status is enabled"

# --- 9. Login redirects to TOTP step when 2FA enabled ---
login_action=$(vm_exec lan "curl -s -k -L $ROUTER/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'" 2>/dev/null)
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi
login_headers=$(vm_exec lan "curl -s -k -D - -o /dev/null -X POST -d 'password=testpass123' $ROUTER${login_action}" 2>/dev/null)
assert_match "$login_headers" "totp_pending=" "Login sets totp_pending cookie when 2FA enabled"

# --- 10. Disable TOTP via CLI escape hatch ---
disable_result=$(vm_sudo router "/opt/hermitshell/hermitshell-agent totp-disable 2>&1")
assert_match "$disable_result" "disabled" "CLI totp-disable reports disabled"

# --- 11. Verify TOTP is now disabled ---
status_disabled=$(vm_exec router "echo '{\"method\":\"totp_status\"}' | socat - UNIX-CONNECT:$SOCK")
assert_contains "$status_disabled" '"config_value":"false"' "TOTP status is disabled after CLI disable"

# --- 12. Normal login works after TOTP disabled ---
login_action2=$(vm_exec lan "curl -s -k -L $ROUTER/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'" 2>/dev/null)
if [ -z "$login_action2" ]; then
    login_action2="/api/login"
fi
vm_exec lan "curl -s -k -c /tmp/cookies-totp -D /tmp/headers-totp -X POST -d 'password=testpass123' $ROUTER${login_action2}" >/dev/null 2>&1
normal_headers=$(vm_exec lan "cat /tmp/headers-totp" 2>/dev/null)
assert_match "$normal_headers" "session=" "Login sets session cookie after TOTP disabled"
dashboard=$(vm_exec lan "curl -s -k -b /tmp/cookies-totp $ROUTER/" 2>/dev/null)
assert_contains "$dashboard" "Dashboard" "Dashboard accessible after normal login"

# Clean up
vm_exec lan "rm -f /tmp/cookies-totp /tmp/headers-totp" >/dev/null 2>&1
