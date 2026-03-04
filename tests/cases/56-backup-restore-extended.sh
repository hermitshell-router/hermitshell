#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_docker

ROUTER=https://10.0.0.1

# =====================================================
# Web UI Endpoint Tests
# =====================================================

# --- Unauthenticated backup request rejected ---
http_code=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' -X POST $ROUTER/api/backup/config")
assert_match "$http_code" "^(302|303|401|403)$" "Backup without auth rejected"

# --- Unauthenticated restore request rejected ---
http_code=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' -X POST -F 'file=@/dev/null' $ROUTER/api/restore/config")
assert_match "$http_code" "^(302|303|401|403)$" "Restore without auth rejected"

# --- Login to get session cookie ---
# Scrape login action URL from form
login_action=$(vm_exec lan "curl -s -k -L $ROUTER/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'" 2>/dev/null)
[ -z "$login_action" ] && login_action="/api/login"
vm_exec lan "curl -s -k -c /tmp/cookies-br -X POST -d 'password=testpass123' $ROUTER${login_action}" >/dev/null 2>&1

# --- Authenticated backup download ---
backup_headers=$(vm_exec lan "curl -s -k -b /tmp/cookies-br -X POST -D - -o /tmp/backup-test.json $ROUTER/api/backup/config" 2>/dev/null)
assert_contains "$backup_headers" "attachment" "Backup response has Content-Disposition attachment"
backup_body=$(vm_exec lan "cat /tmp/backup-test.json" 2>/dev/null)
assert_contains "$backup_body" '"version":2' "Backup response is valid v2 JSON"

# --- Backup with encrypted secrets via HTTP ---
enc_headers=$(vm_exec lan "curl -s -k -b /tmp/cookies-br -X POST -d 'secrets=1&passphrase=httptest' -D - -o /tmp/backup-enc-test.json $ROUTER/api/backup/config" 2>/dev/null)
enc_body=$(vm_exec lan "cat /tmp/backup-enc-test.json" 2>/dev/null)
assert_contains "$enc_body" '"secrets_encrypted":true' "HTTP backup with passphrase encrypts secrets"

# --- Restore via multipart upload ---
restore_code=$(vm_exec lan "curl -s -k -b /tmp/cookies-br -o /dev/null -w '%{http_code}' -X POST -F 'file=@/tmp/backup-test.json' $ROUTER/api/restore/config" 2>/dev/null)
# Redirect (302/303) to /settings on success, or 200 if Leptos returns OK
assert_match "$restore_code" "^(200|302|303)$" "Restore via HTTP succeeds"

# --- Restore without file field returns 400 ---
nofile_code=$(vm_exec lan "curl -s -k -b /tmp/cookies-br -o /dev/null -w '%{http_code}' -X POST $ROUTER/api/restore/config" 2>/dev/null)
assert_match "$nofile_code" "^400$" "Restore without file returns 400"

# Clean up
vm_exec lan "rm -f /tmp/cookies-br /tmp/backup-test.json /tmp/backup-enc-test.json" >/dev/null 2>&1

# =====================================================
# Edge Cases & Robustness
# =====================================================

# --- Quantity limit: too many devices ---
args=$(_vm_ssh_args router)
qty_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'QSCRIPT'
SOCK=/run/hermitshell/agent.sock
# Generate 10001 devices via python3
payload=$(python3 -c "
import json
devices = [{'mac': f'aa:bb:cc:{i//256//256%256:02x}:{i//256%256:02x}:{i%256:02x}', 'device_group': 'trusted'} for i in range(10001)]
print(json.dumps({'method': 'import_config', 'value': json.dumps({'version': 2, 'devices': devices})}))
" 2>/dev/null)
echo "$payload" | socat -t 5 - UNIX-CONNECT:$SOCK
QSCRIPT
)
assert_contains "$qty_result" '"ok":false' "Import rejects >10000 devices"
assert_contains "$qty_result" "too many devices" "Error mentions too many devices"

# --- Quantity limit: too many port forwards ---
qty_pf=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'PFSCRIPT'
SOCK=/run/hermitshell/agent.sock
payload=$(python3 -c "
import json
pfs = [{'protocol': 'tcp', 'external_port_start': i, 'external_port_end': i, 'internal_ip': '10.0.1.1', 'internal_port': i} for i in range(1001)]
print(json.dumps({'method': 'import_config', 'value': json.dumps({'version': 2, 'port_forwards': pfs})}))
" 2>/dev/null)
echo "$payload" | socat -t 5 - UNIX-CONNECT:$SOCK
PFSCRIPT
)
assert_contains "$qty_pf" '"ok":false' "Import rejects >1000 port forwards"
assert_contains "$qty_pf" "too many port forwards" "Error mentions too many port forwards"

# --- Gateway IP rejection ---
gateway_result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":2,\\\"port_forwards\\\":[{\\\"protocol\\\":\\\"tcp\\\",\\\"external_port_start\\\":80,\\\"external_port_end\\\":80,\\\"internal_ip\\\":\\\"10.0.0.1\\\",\\\"internal_port\\\":80}]}\"}" | socat -t 5 - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$gateway_result" '"ok":false' "Import rejects gateway IP port forward"
assert_contains "$gateway_result" "gateway" "Error mentions gateway"

# --- Port forward description too long (>256 chars) ---
long_desc=$(python3 -c "print('x' * 257)")
desc_result=$(vm_exec router "echo '{\"method\":\"import_config\",\"value\":\"{\\\\\"version\\\\\":2,\\\\\"port_forwards\\\\\":[{\\\\\"protocol\\\\\":\\\\\"tcp\\\\\",\\\\\"external_port_start\\\\\":80,\\\\\"external_port_end\\\\\":80,\\\\\"internal_ip\\\\\":\\\\\"10.0.1.1\\\\\",\\\\\"internal_port\\\\\":80,\\\\\"description\\\\\":\\\\\"${long_desc}\\\\\"}]}\"}' | socat -t 5 - UNIX-CONNECT:/run/hermitshell/agent.sock")
assert_contains "$desc_result" '"ok":false' "Import rejects description >256 chars"
assert_contains "$desc_result" "description too long" "Error mentions description too long"

# --- Invalid WAN interface ---
wan_result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":2,\\\"config\\\":{\\\"wan_iface\\\":\\\"../etc/passwd\\\"}}\"}" | socat -t 5 - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$wan_result" '"ok":false' "Import rejects invalid WAN interface"
assert_contains "$wan_result" "invalid WAN interface" "Error mentions WAN interface"

# --- Invalid LAN interface ---
lan_result=$(vm_exec router 'echo "{\"method\":\"import_config\",\"value\":\"{\\\"version\\\":2,\\\"config\\\":{\\\"lan_iface\\\":\\\"foo bar\\\"}}\"}" | socat -t 5 - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$lan_result" '"ok":false' "Import rejects invalid LAN interface"
assert_contains "$lan_result" "invalid LAN interface" "Error mentions LAN interface"

# --- Empty config import clears port forwards ---
args=$(_vm_ssh_args router)
empty_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'EMPTYSCRIPT'
SOCK=/run/hermitshell/agent.sock

# Add a port forward
echo '{"method":"add_port_forward","protocol":"tcp","external_port_start":5555,"external_port_end":5555,"internal_ip":"10.0.1.1","internal_port":5050,"description":"empty-test"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# Verify it exists
pre=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "PRE_5555:$(echo "$pre" | grep -c '5555')"

# Import empty config (no port_forwards section = DELETE all)
import_payload=$(python3 -c "import json; print(json.dumps({'method':'import_config','value':json.dumps({'version':2})}))")
echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK > /dev/null

# Check port forwards are cleared
post=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_5555:$(echo "$post" | grep -c '5555')"
EMPTYSCRIPT
)
assert_contains "$empty_result" "PRE_5555:1" "Port forward exists before empty import"
assert_contains "$empty_result" "POST_5555:0" "Port forward cleared by empty import"
