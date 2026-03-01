#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip

ROUTER_IP="10.0.0.1"
REST_PORT=9080
BASE="http://${ROUTER_IP}:${REST_PORT}"

# ---- Step 1: Set up API key via socket command ----
API_KEY="test-rest-api-key-1234567890"

args=$(_vm_ssh_args router)
set_key_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<SETKEY
SOCK=/run/hermitshell/agent.sock
python3 -c "
import json
req = {'method': 'set_api_key', 'value': '${API_KEY}'}
print(json.dumps(req))
" | socat - UNIX-CONNECT:\$SOCK
SETKEY
)
assert_match "$set_key_result" '"ok":true' "set_api_key succeeds"

# ---- Test 1: GET /api/v1/status without auth should fail ----
status_no_auth=$(vm_exec lan "curl -s -o /dev/null -w '%{http_code}' ${BASE}/api/v1/status")
assert_match "$status_no_auth" "401" "GET /status without auth returns 401"

# ---- Test 2: GET /api/v1/status with wrong key should fail ----
status_bad_key=$(vm_exec lan "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrong-key' ${BASE}/api/v1/status")
assert_match "$status_bad_key" "401" "GET /status with wrong key returns 401"

# ---- Test 3: GET /api/v1/status with correct key ----
status_result=$(vm_exec lan "curl -s -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/status")
assert_contains "$status_result" '"uptime_secs"' "GET /status returns uptime"
assert_contains "$status_result" '"version"' "GET /status returns version"

# ---- Test 4: GET /api/v1/config ----
config_result=$(vm_exec lan "curl -s -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/config")
assert_contains "$config_result" '"network"' "GET /config returns network section"
assert_contains "$config_result" '"dns"' "GET /config returns dns section"
assert_contains "$config_result" '"firewall"' "GET /config returns firewall section"

# ---- Test 5: GET /api/v1/config/network (section) ----
network_result=$(vm_exec lan "curl -s -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/config/network")
assert_contains "$network_result" '"wan_interface"' "GET /config/network returns wan_interface"

# ---- Test 6: GET /api/v1/config/invalid should 404 ----
invalid_section=$(vm_exec lan "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/config/nonexistent")
assert_match "$invalid_section" "404" "GET /config/nonexistent returns 404"

# ---- Test 7: GET /api/v1/devices ----
devices_result=$(vm_exec lan "curl -s -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/devices")
# Should be a JSON array (even if empty)
assert_match "$devices_result" '^\[' "GET /devices returns JSON array"

# ---- Test 8: POST /api/v1/config/validate with valid config ----
args=$(_vm_ssh_args lan)
validate_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<VALIDATE
curl -s -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"network":{},"dns":{"ad_blocking":true},"firewall":{},"wireguard":{"enabled":false},"devices":[],"dhcp":{},"qos":{"enabled":false},"logging":{},"tls":{"mode":"self_signed"},"analysis":{},"wifi":{}}' \
  ${BASE}/api/v1/config/validate
VALIDATE
)
assert_contains "$validate_result" '"valid":true' "POST /config/validate accepts valid config"

# ---- Test 9: POST /api/v1/config/validate with invalid config ----
args=$(_vm_ssh_args lan)
validate_bad=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<VALIDATEBAD
curl -s -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"tls":{"mode":"invalid_mode"}}' \
  ${BASE}/api/v1/config/validate
VALIDATEBAD
)
assert_contains "$validate_bad" '"valid":false' "POST /config/validate rejects invalid config"
assert_contains "$validate_bad" '"errors"' "POST /config/validate returns errors"

# ---- Test 10: PUT /api/v1/config (apply full config) ----
args=$(_vm_ssh_args lan)
put_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<PUTCONFIG
curl -s -X PUT \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"network":{"wan_interface":"eth0","lan_interface":"eth1"},"dns":{"ad_blocking":true,"blocklists":[],"forward_zones":[],"custom_records":[]},"firewall":{"port_forwards":[],"ipv6_pinholes":[]},"wireguard":{"enabled":false,"listen_port":51820,"peers":[]},"devices":[],"dhcp":{"reservations":[]},"qos":{"enabled":false,"upload_mbps":0,"download_mbps":0},"logging":{"format":"text","retention_days":7},"tls":{"mode":"self_signed"},"analysis":{"enabled":false},"wifi":{"providers":[]}}' \
  ${BASE}/api/v1/config
PUTCONFIG
)
assert_contains "$put_result" '"ok":true' "PUT /config applies config"

# ---- Test 11: POST /api/v1/config/diff ----
args=$(_vm_ssh_args lan)
diff_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<DIFFCONFIG
curl -s -X POST \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"network":{"wan_interface":"eth0","lan_interface":"eth1"},"dns":{"ad_blocking":true,"blocklists":[],"forward_zones":[],"custom_records":[]},"firewall":{"port_forwards":[],"ipv6_pinholes":[]},"wireguard":{"enabled":false,"listen_port":51820,"peers":[]},"devices":[],"dhcp":{"reservations":[]},"qos":{"enabled":false,"upload_mbps":0,"download_mbps":0},"logging":{"format":"text","retention_days":7},"tls":{"mode":"self_signed"},"analysis":{"enabled":false},"wifi":{"providers":[]}}' \
  ${BASE}/api/v1/config/diff
DIFFCONFIG
)
assert_contains "$diff_result" '"sections"' "POST /config/diff returns sections"

# ---- Test 12: PUT /api/v1/config/qos (section-level update) ----
args=$(_vm_ssh_args lan)
put_section_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<PUTSECTION
curl -s -X PUT \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"enabled":false,"upload_mbps":0,"download_mbps":0}' \
  ${BASE}/api/v1/config/qos
PUTSECTION
)
assert_contains "$put_section_result" '"ok":true' "PUT /config/qos (section) succeeds"

# Verify the section update persisted
qos_check=$(vm_exec lan "curl -s -H 'Authorization: Bearer ${API_KEY}' ${BASE}/api/v1/config/qos")
assert_contains "$qos_check" '"enabled":false' "Section update persisted"
