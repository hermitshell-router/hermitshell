#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

# Clean up any leftover port forwards from prior runs (idempotency)
existing_ids=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -oP '"id":\K[0-9]+')
for id in $existing_ids; do
    vm_exec router "echo '{\"method\":\"remove_port_forward\",\"id\":$id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1
done
# Reset log config to defaults
vm_exec router 'echo "{\"method\":\"set_log_config\",\"value\":\"{\\\"log_retention_days\\\":\\\"7\\\",\\\"log_format\\\":\\\"text\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null 2>&1

# --- Export Config ---
# Note: export_config returns config_value as a JSON string, so inner keys are backslash-escaped
result=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "export_config succeeds"
assert_match "$result" 'version.*:.*2' "export has version 2"
assert_match "$result" 'devices' "export contains devices"
assert_match "$result" 'config' "export contains config"
assert_match "$result" 'port_forwards' "export contains port_forwards"
assert_match "$result" 'dhcp_reservations' "export contains dhcp_reservations"

# Verify export contains the LAN device
lan_mac=$(vm_exec lan "cat /sys/class/net/eth1/address")
assert_contains "$result" "$lan_mac" "export includes LAN device MAC"

# Verify sensitive keys are NOT in export
if echo "$result" | grep -qF "admin_password_hash"; then
    echo -e "${RED}FAIL${NC}: export leaks admin_password_hash"
    exit 1
else
    echo -e "${GREEN}PASS${NC}: export excludes sensitive keys"
fi

# --- Test import_config round-trip ---
# Run entirely on router VM to avoid shell quoting issues with nested JSON
args=$(_vm_ssh_args router)
round_trip=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'SCRIPT'
SOCK=/run/hermitshell/agent.sock

# 1. Create test data
echo '{"method":"add_port_forward","protocol":"tcp","external_port_start":7777,"external_port_end":7777,"internal_ip":"10.0.1.1","internal_port":7070,"description":"import-test"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"log_retention_days","value":"21"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# 2. Export snapshot
export_resp=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json" > /tmp/test-export.json

# 3. Delete test data (simulate data loss)
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"log_retention_days","value":"7"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# 4. Verify data is gone
fwd_pre=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "PRE_IMPORT_7777:$(echo "$fwd_pre" | grep -c '7777')"

# 5. Import saved snapshot to restore (-t 5: wait up to 5s for response after sending)
import_payload=$(python3 -c "import sys,json; d=open('/tmp/test-export.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
import_resp=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "$import_resp"

# 6. Verify restored
fwd_post=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
config_post=$(echo '{"method":"get_config","key":"log_retention_days"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_FWD_7777:$(echo "$fwd_post" | grep -c '7777')"
echo "POST_CONFIG_21:$(echo "$config_post" | grep -c '"21"')"

# 7. Clean up
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"log_retention_days","value":"7"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
rm -f /tmp/test-export.json
SCRIPT
)

assert_contains "$round_trip" '"ok":true' "import_config succeeds"
assert_contains "$round_trip" "PRE_IMPORT_7777:0" "Port forward gone before import"
assert_contains "$round_trip" "POST_FWD_7777:1" "Port forward restored after import"
assert_contains "$round_trip" "POST_CONFIG_21:1" "Config value restored after import"

# --- import_config validation ---
# Invalid MAC
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"devices\\\":[{\\\"mac\\\":\\\"BADMAC\\\",\\\"device_group\\\":\\\"trusted\\\"}]}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects invalid MAC"
assert_contains "$result" "invalid device MAC" "import error mentions device MAC"

# Invalid group
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"devices\\\":[{\\\"mac\\\":\\\"aa:bb:cc:dd:ee:ff\\\",\\\"device_group\\\":\\\"hacker\\\"}]}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects invalid group"
assert_contains "$result" "invalid device group" "import error mentions group"

# Invalid port forward IP
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"port_forwards\\\":[{\\\"protocol\\\":\\\"tcp\\\",\\\"external_port_start\\\":80,\\\"external_port_end\\\":80,\\\"internal_ip\\\":\\\"not-an-ip\\\",\\\"internal_port\\\":80}]}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects invalid port forward IP"
assert_contains "$result" "invalid port forward IP" "import error mentions IP"

# Invalid port forward protocol
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"port_forwards\\\":[{\\\"protocol\\\":\\\"sctp\\\",\\\"external_port_start\\\":80,\\\"external_port_end\\\":80,\\\"internal_ip\\\":\\\"10.0.1.1\\\",\\\"internal_port\\\":80}]}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects invalid protocol"
assert_contains "$result" "invalid port forward protocol" "import error mentions protocol"

# Invalid pinhole protocol
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"ipv6_pinholes\\\":[{\\\"device_mac\\\":\\\"aa:bb:cc:dd:ee:ff\\\",\\\"protocol\\\":\\\"icmp\\\",\\\"port_start\\\":80,\\\"port_end\\\":80}]}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects invalid pinhole protocol"
assert_contains "$result" "invalid pinhole protocol" "import error mentions pinhole protocol"

# --- Backup Database ---
result=$(vm_exec router 'echo "{\"method\":\"backup_database\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "backup_database succeeds"
assert_match "$result" "hermitshell-backup.db" "backup returns path"

# Verify backup file exists with restricted permissions
assert_success "Backup file exists" \
    vm_exec router "sudo test -f /var/lib/hermitshell/hermitshell-backup.db"

perms=$(vm_exec router "sudo stat -c '%a' /var/lib/hermitshell/hermitshell-backup.db")
assert_match "$perms" "600" "Backup file has 0600 permissions"

# Verify backup is a valid SQLite database (check magic bytes)
backup_magic=$(vm_exec router "sudo head -c 15 /var/lib/hermitshell/hermitshell-backup.db" 2>/dev/null || echo "")
assert_contains "$backup_magic" "SQLite format" "Backup file is a valid SQLite database"

# =====================================================
# v2 Backup/Restore Tests
# =====================================================

# --- v2 export format ---
result=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "v2 export_config succeeds"
# Extract inner JSON from config_value string (it's double-encoded in the response)
export_json=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
assert_contains "$export_json" '"version":2' "export is version 2"
assert_contains "$export_json" '"agent_version"' "export has agent_version"
assert_contains "$export_json" '"wifi_aps"' "export has wifi_aps"
assert_contains "$export_json" '"secrets":null' "export without secrets has null secrets"
assert_contains "$export_json" '"secrets_encrypted":false' "export without secrets not encrypted"

# Verify config section is present
assert_contains "$export_json" '"config"' "export has config section"

# --- v2 export with secrets (no encryption) ---
result=$(vm_exec router 'echo "{\"method\":\"export_config\",\"include_secrets\":true}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "export with secrets succeeds"
secrets_json=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
assert_contains "$secrets_json" '"secrets_encrypted":false' "secrets not encrypted"

# --- v2 export with encrypted secrets ---
result=$(vm_exec router 'echo "{\"method\":\"export_config\",\"include_secrets\":true,\"passphrase\":\"testpass123\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "export with encrypted secrets succeeds"
enc_json=$(echo "$result" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
assert_contains "$enc_json" '"secrets_encrypted":true' "secrets are encrypted"

# --- v2 import round-trip ---
args=$(_vm_ssh_args router)
v2_trip=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'V2SCRIPT'
SOCK=/run/hermitshell/agent.sock

# 1. Set up test data
echo '{"method":"set_config","key":"analyzer_enabled","value":"false"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"add_port_forward","protocol":"tcp","external_port_start":9999,"external_port_end":9999,"internal_ip":"10.0.1.1","internal_port":9090,"description":"v2-test"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# 2. Export v2
export_resp=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json" > /tmp/test-v2-export.json

# 3. Verify export is v2
echo "EXPORT_V2:$(echo "$config_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',0))" 2>/dev/null)"

# 4. Delete test data
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"analyzer_enabled","value":"true"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# 5. Import (-t 5: wait up to 5s for response after sending)
import_payload=$(python3 -c "import sys,json; d=open('/tmp/test-v2-export.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
import_resp=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "$import_resp"

# 6. Verify
fwd_post=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_FWD_9999:$(echo "$fwd_post" | grep -c '9999')"
analyzer_post=$(echo '{"method":"get_config","key":"analyzer_enabled"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_ANALYZER:$(echo "$analyzer_post" | grep -c '"false"')"

# 7. Clean up
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"analyzer_enabled","value":"true"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
rm -f /tmp/test-v2-export.json
V2SCRIPT
)

assert_contains "$v2_trip" '"ok":true' "v2 import succeeds"
assert_contains "$v2_trip" "EXPORT_V2:2" "exported version is 2"
assert_contains "$v2_trip" "POST_FWD_9999:1" "v2 port forward restored"
assert_contains "$v2_trip" "POST_ANALYZER:1" "v2 analyzer_enabled restored"

# --- Version rejection ---
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":99}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":false' "import rejects future version"
assert_contains "$result" "newer version" "error mentions newer version"

# --- v1 backward compat ---
result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":1,\\\"devices\\\":[],\\\"config\\\":{}}\"}" | socat -t5 - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "v1 import still works"

# --- Encrypted secrets round-trip ---
args=$(_vm_ssh_args router)
enc_trip=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'ENCSCRIPT'
SOCK=/run/hermitshell/agent.sock

# Export with encryption
export_resp=$(echo '{"method":"export_config","include_secrets":true,"passphrase":"mypass"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json" > /tmp/test-enc-export.json

# Verify it's encrypted
echo "ENC:$(echo "$config_json" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('secrets_encrypted',False))" 2>/dev/null)"

# Try import without passphrase (should fail)
import_payload=$(python3 -c "import sys,json; d=open('/tmp/test-enc-export.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
fail_resp=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "NO_PASS:$(echo "$fail_resp" | grep -c 'passphrase required')"

# Import with wrong passphrase (should fail)
import_payload=$(python3 -c "import sys,json; d=open('/tmp/test-enc-export.json').read(); print(json.dumps({'method':'import_config','value':d,'passphrase':'wrongpass'}))" 2>/dev/null)
fail_resp2=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "WRONG_PASS:$(echo "$fail_resp2" | grep -c 'decryption failed')"

# Import with correct passphrase (should succeed; -t 5: wait for response)
import_payload=$(python3 -c "import sys,json; d=open('/tmp/test-enc-export.json').read(); print(json.dumps({'method':'import_config','value':d,'passphrase':'mypass'}))" 2>/dev/null)
ok_resp=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "$ok_resp"

rm -f /tmp/test-enc-export.json
ENCSCRIPT
)

assert_contains "$enc_trip" "ENC:True" "export is encrypted"
assert_contains "$enc_trip" "NO_PASS:1" "import without passphrase rejected"
assert_contains "$enc_trip" "WRONG_PASS:1" "import with wrong passphrase rejected"
assert_contains "$enc_trip" '"ok":true' "import with correct passphrase succeeds"

# --- Audit log records export and import ---
result=$(vm_exec router 'echo "{\"method\":\"list_audit_logs\",\"limit\":20}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" "config_export" "audit log has config_export entry"
assert_contains "$result" "config_import" "audit log has config_import entry"
