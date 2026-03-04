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

# =====================================================
# DNS Data Round-Trip Tests
# =====================================================

args=$(_vm_ssh_args router)
dns_trip=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'DNSSCRIPT'
SOCK=/run/hermitshell/agent.sock

# --- DNS Forward Zones Round-Trip ---
# 1. Add a forward zone
echo '{"method":"add_dns_forward","name":"roundtrip.local","value":"10.0.0.1"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# 2. Export
export_resp=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json" > /tmp/dns-test-export.json
echo "EXPORT_FWD:$(echo "$config_json" | grep -c 'roundtrip.local')"

# 3. Delete the zone
zone_id=$(echo '{"method":"list_dns_forwards"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; zones=json.loads(sys.stdin.read()).get('dns_forward_zones',[]); print(next((z['id'] for z in zones if z['domain']=='roundtrip.local'), ''))" 2>/dev/null || echo "")
[ -n "$zone_id" ] && echo "{\"method\":\"remove_dns_forward\",\"id\":$zone_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null

# 4. Verify gone
pre=$(echo '{"method":"list_dns_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "PRE_IMPORT_FWD:$(echo "$pre" | grep -c 'roundtrip.local')"

# 5. Import
import_payload=$(python3 -c "import sys,json; d=open('/tmp/dns-test-export.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK > /dev/null

# 6. Verify restored
post=$(echo '{"method":"list_dns_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_IMPORT_FWD:$(echo "$post" | grep -c 'roundtrip.local')"

# --- DNS Custom Rules Round-Trip ---
echo '{"method":"add_dns_rule","name":"myhost.test","key":"A","value":"10.0.1.99"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

export_resp2=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json2=$(echo "$export_resp2" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json2" > /tmp/dns-test-export2.json
echo "EXPORT_RULE:$(echo "$config_json2" | grep -c 'myhost.test')"

# Delete
rule_id=$(echo '{"method":"list_dns_rules"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; rules=json.loads(sys.stdin.read()).get('dns_custom_rules',[]); print(next((r['id'] for r in rules if r['domain']=='myhost.test'), ''))" 2>/dev/null || echo "")
[ -n "$rule_id" ] && echo "{\"method\":\"remove_dns_rule\",\"id\":$rule_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null

import_payload2=$(python3 -c "import sys,json; d=open('/tmp/dns-test-export2.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
echo "$import_payload2" | socat -t 5 - UNIX-CONNECT:$SOCK > /dev/null

post2=$(echo '{"method":"list_dns_rules"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_IMPORT_RULE:$(echo "$post2" | grep -c 'myhost.test')"

# --- DNS Blocklists Round-Trip ---
echo '{"method":"add_dns_blocklist","name":"test-blocklist","url":"https://example.com/blocklist.txt","key":"custom"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

export_resp3=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json3=$(echo "$export_resp3" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json3" > /tmp/dns-test-export3.json
echo "EXPORT_BL:$(echo "$config_json3" | grep -c 'test-blocklist')"

bl_id=$(echo '{"method":"list_dns_blocklists"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; bls=json.loads(sys.stdin.read()).get('dns_blocklists',[]); print(next((b['id'] for b in bls if b['name']=='test-blocklist'), ''))" 2>/dev/null || echo "")
[ -n "$bl_id" ] && echo "{\"method\":\"remove_dns_blocklist\",\"id\":$bl_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null

import_payload3=$(python3 -c "import sys,json; d=open('/tmp/dns-test-export3.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
echo "$import_payload3" | socat -t 5 - UNIX-CONNECT:$SOCK > /dev/null

post3=$(echo '{"method":"list_dns_blocklists"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_IMPORT_BL:$(echo "$post3" | grep -c 'test-blocklist')"

# Clean up all test DNS data
zone_id=$(echo '{"method":"list_dns_forwards"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; zones=json.loads(sys.stdin.read()).get('dns_forward_zones',[]); print(next((z['id'] for z in zones if z['domain']=='roundtrip.local'), ''))" 2>/dev/null || echo "")
[ -n "$zone_id" ] && echo "{\"method\":\"remove_dns_forward\",\"id\":$zone_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
rule_id=$(echo '{"method":"list_dns_rules"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; rules=json.loads(sys.stdin.read()).get('dns_custom_rules',[]); print(next((r['id'] for r in rules if r['domain']=='myhost.test'), ''))" 2>/dev/null || echo "")
[ -n "$rule_id" ] && echo "{\"method\":\"remove_dns_rule\",\"id\":$rule_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
bl_id=$(echo '{"method":"list_dns_blocklists"}' | socat - UNIX-CONNECT:$SOCK | python3 -c "import sys,json; bls=json.loads(sys.stdin.read()).get('dns_blocklists',[]); print(next((b['id'] for b in bls if b['name']=='test-blocklist'), ''))" 2>/dev/null || echo "")
[ -n "$bl_id" ] && echo "{\"method\":\"remove_dns_blocklist\",\"id\":$bl_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
rm -f /tmp/dns-test-export.json /tmp/dns-test-export2.json /tmp/dns-test-export3.json
DNSSCRIPT
)

assert_contains "$dns_trip" "EXPORT_FWD:1" "DNS forward zone in export"
assert_contains "$dns_trip" "PRE_IMPORT_FWD:0" "DNS forward zone deleted before import"
assert_contains "$dns_trip" "POST_IMPORT_FWD:1" "DNS forward zone restored after import"
assert_contains "$dns_trip" "EXPORT_RULE:1" "DNS custom rule in export"
assert_contains "$dns_trip" "POST_IMPORT_RULE:1" "DNS custom rule restored after import"
assert_contains "$dns_trip" "EXPORT_BL:1" "DNS blocklist in export"
assert_contains "$dns_trip" "POST_IMPORT_BL:1" "DNS blocklist restored after import"

# =====================================================
# Cross-Restart Persistence
# =====================================================

# --- Export, restart agent, import, verify ---
args=$(_vm_ssh_args router)

# 1. Create test data and export
restart_export=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'RSCRIPT'
SOCK=/run/hermitshell/agent.sock

# Add a port forward
echo '{"method":"add_port_forward","protocol":"udp","external_port_start":6666,"external_port_end":6666,"internal_ip":"10.0.1.1","internal_port":6060,"description":"restart-test"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
# Set a config value
echo '{"method":"set_config","key":"log_retention_days","value":"30"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

# Export
export_resp=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)
echo "$config_json" > /tmp/restart-test-export.json

# Remove test data
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"log_retention_days","value":"7"}' | socat - UNIX-CONNECT:$SOCK > /dev/null

echo "EXPORTED"
RSCRIPT
)
assert_contains "$restart_export" "EXPORTED" "Pre-restart export completed"

# 2. Restart agent
deploy_stop_agent
wait_for 5 "Agent stopped" deploy_agent_dead

deploy_start_agent
socket_ready() {
    vm_sudo router "chmod 666 /run/hermitshell/agent.sock"
    vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q '"ok":true'
}
wait_for 15 "Agent socket ready after restart" socket_ready

# 3. Import the previously exported config
restart_import=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'ISCRIPT'
SOCK=/run/hermitshell/agent.sock
import_payload=$(python3 -c "import sys,json; d=open('/tmp/restart-test-export.json').read(); print(json.dumps({'method':'import_config','value':d}))" 2>/dev/null)
import_resp=$(echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
echo "$import_resp"

# Verify
fwd_post=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_FWD_6666:$(echo "$fwd_post" | grep -c '6666')"
config_post=$(echo '{"method":"get_config","key":"log_retention_days"}' | socat - UNIX-CONNECT:$SOCK)
echo "POST_RETENTION_30:$(echo "$config_post" | grep -c '"30"')"

# Clean up
fwd_id=$(echo '{"method":"list_port_forwards"}' | socat - UNIX-CONNECT:$SOCK | grep -oP '"id":\K[0-9]+' | tail -1)
[ -n "$fwd_id" ] && echo "{\"method\":\"remove_port_forward\",\"id\":$fwd_id}" | socat - UNIX-CONNECT:$SOCK > /dev/null
echo '{"method":"set_config","key":"log_retention_days","value":"7"}' | socat - UNIX-CONNECT:$SOCK > /dev/null
rm -f /tmp/restart-test-export.json
ISCRIPT
)
assert_contains "$restart_import" '"ok":true' "Import after restart succeeds"
assert_contains "$restart_import" "POST_FWD_6666:1" "Port forward restored after restart+import"
assert_contains "$restart_import" "POST_RETENTION_30:1" "Config value restored after restart+import"

# --- Database backup after restart ---
result=$(vm_exec router 'echo "{\"method\":\"backup_database\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "backup_database after restart succeeds"
backup_magic=$(vm_exec router "sudo head -c 15 /var/lib/hermitshell/hermitshell-backup.db" 2>/dev/null || echo "")
assert_contains "$backup_magic" "SQLite format" "Backup after restart is valid SQLite"

# --- WireGuard peers deliberately excluded from import ---
wg_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'WGSCRIPT'
SOCK=/run/hermitshell/agent.sock

# Export (includes wg_peers section)
export_resp=$(echo '{"method":"export_config"}' | socat - UNIX-CONNECT:$SOCK)
config_json=$(echo "$export_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('config_value',''))" 2>/dev/null)

# Inject a fake WG peer into the export JSON
modified=$(echo "$config_json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
d['wg_peers'] = [{'public_key': 'dGVzdHBlZXJrZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEy', 'name': 'fake-peer', 'subnet_id': 99, 'device_group': 'trusted', 'enabled': True}]
print(json.dumps(d))
" 2>/dev/null)

# Import the modified config
import_payload=$(python3 -c "import sys,json; print(json.dumps({'method':'import_config','value':sys.argv[1]}))" "$modified" 2>/dev/null)
echo "$import_payload" | socat -t 5 - UNIX-CONNECT:$SOCK > /dev/null

# Check that the fake peer was NOT added
wg_status=$(echo '{"method":"get_wireguard"}' | socat - UNIX-CONNECT:$SOCK)
echo "FAKE_PEER:$(echo "$wg_status" | grep -c 'fake-peer')"
WGSCRIPT
)
assert_contains "$wg_result" "FAKE_PEER:0" "WireGuard peers excluded from import"
