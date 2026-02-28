#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_nftables

# Clean up any leftover port forwards from prior runs (idempotency)
existing_ids=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -oP '"id":\K[0-9]+')
for id in $existing_ids; do
    vm_exec router "echo '{\"method\":\"remove_port_forward\",\"id\":$id}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null 2>&1
done

# ---- Test 1: Apply minimal HermitConfig ----
# Run on router to avoid quoting issues with nested JSON
args=$(_vm_ssh_args router)
apply_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'APPLYSCRIPT'
SOCK=/run/hermitshell/agent.sock

config_json=$(python3 -c "
import json
config = {
    'network': {'wan_interface': 'eth0', 'lan_interface': 'eth1'},
    'dns': {'ad_blocking': True, 'blocklists': [], 'forward_zones': [], 'custom_records': []},
    'firewall': {'port_forwards': [], 'ipv6_pinholes': []},
    'wireguard': {'enabled': False, 'listen_port': 51820, 'peers': []},
    'devices': [],
    'dhcp': {'reservations': []},
    'qos': {'enabled': False, 'upload_mbps': 0, 'download_mbps': 0},
    'logging': {'format': 'text', 'retention_days': 7},
    'tls': {'mode': 'self_signed'},
    'analysis': {'enabled': False},
    'wifi': {'providers': []},
}
req = {'method': 'apply_config', 'value': json.dumps(config)}
print(json.dumps(req))
")

echo "$config_json" | socat - UNIX-CONNECT:$SOCK
APPLYSCRIPT
)
assert_match "$apply_result" '"ok":true' "apply_config with minimal config succeeds"

# ---- Test 2: Read back via get_full_config ----
result=$(vm_exec router 'echo "{\"method\":\"get_full_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "get_full_config succeeds"
assert_match "$result" '"config_value"' "get_full_config returns config_value field"

# Verify the returned config_value contains network config
args=$(_vm_ssh_args router)
has_network=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'CHECKSCRIPT'
SOCK=/run/hermitshell/agent.sock
echo '{"method":"get_full_config"}' | socat - UNIX-CONNECT:$SOCK > /tmp/hermit-check-resp.json
python3 -c "
import json
resp = json.load(open('/tmp/hermit-check-resp.json'))
config = json.loads(resp['config_value'])
if 'network' in config:
    print('HAS_NETWORK')
else:
    print('NO_NETWORK')
" 2>/dev/null
rm -f /tmp/hermit-check-resp.json
CHECKSCRIPT
)
assert_match "$has_network" "HAS_NETWORK" "get_full_config returns network section"

# ---- Test 3: Apply with a port forward, verify nftables ----
args=$(_vm_ssh_args router)
pf_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'PFSCRIPT'
SOCK=/run/hermitshell/agent.sock

config_json=$(python3 -c "
import json
config = {
    'network': {'wan_interface': 'eth0', 'lan_interface': 'eth1'},
    'dns': {'ad_blocking': True, 'blocklists': [], 'forward_zones': [], 'custom_records': []},
    'firewall': {
        'port_forwards': [{
            'protocol': 'tcp',
            'external_port': 8222,
            'internal_ip': '10.99.0.2',
            'internal_port': 80,
            'enabled': True,
            'description': 'apply-config-test'
        }],
        'ipv6_pinholes': []
    },
    'wireguard': {'enabled': False, 'listen_port': 51820, 'peers': []},
    'devices': [],
    'dhcp': {'reservations': []},
    'qos': {'enabled': False, 'upload_mbps': 0, 'download_mbps': 0},
    'logging': {'format': 'text', 'retention_days': 7},
    'tls': {'mode': 'self_signed'},
    'analysis': {'enabled': False},
    'wifi': {'providers': []},
}
req = {'method': 'apply_config', 'value': json.dumps(config)}
print(json.dumps(req))
")

echo "$config_json" | socat - UNIX-CONNECT:$SOCK
PFSCRIPT
)
assert_match "$pf_result" '"ok":true' "apply_config with port forward succeeds"

# Verify port forward appears in nftables
nft_output=$(vm_nft "list ruleset")
assert_match "$nft_output" "8222" "Port forward 8222 appears in nftables"

# ---- Test 4: Apply with invalid config should fail ----
args=$(_vm_ssh_args router)
bad_result=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'BADSCRIPT'
SOCK=/run/hermitshell/agent.sock

bad_json=$(python3 -c "
import json
config = {
    'firewall': {
        'port_forwards': [{
            'protocol': 'invalid_proto',
            'external_port': 0,
            'internal_ip': 'not-an-ip',
            'internal_port': 80,
            'enabled': True,
            'description': 'bad forward'
        }]
    }
}
req = {'method': 'apply_config', 'value': json.dumps(config)}
print(json.dumps(req))
")

echo "$bad_json" | socat - UNIX-CONNECT:$SOCK
BADSCRIPT
)
assert_match "$bad_result" '"ok":false' "apply_config rejects invalid config"

# ---- Test 5: Apply with completely invalid JSON should fail ----
result=$(vm_exec router 'echo "{\"method\":\"apply_config\",\"value\":\"not valid json at all\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":false' "apply_config rejects non-JSON value"

# ---- Cleanup: remove test port forwards ----
args=$(_vm_ssh_args router)
ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'CLEANUP'
SOCK=/run/hermitshell/agent.sock

config_json=$(python3 -c "
import json
config = {
    'network': {'wan_interface': 'eth0', 'lan_interface': 'eth1'},
    'dns': {'ad_blocking': True, 'blocklists': [], 'forward_zones': [], 'custom_records': []},
    'firewall': {'port_forwards': [], 'ipv6_pinholes': []},
    'wireguard': {'enabled': False, 'listen_port': 51820, 'peers': []},
    'devices': [],
    'dhcp': {'reservations': []},
    'qos': {'enabled': False, 'upload_mbps': 0, 'download_mbps': 0},
    'logging': {'format': 'text', 'retention_days': 7},
    'tls': {'mode': 'self_signed'},
    'analysis': {'enabled': False},
    'wifi': {'providers': []},
}
req = {'method': 'apply_config', 'value': json.dumps(config)}
print(json.dumps(req))
")

echo "$config_json" | socat - UNIX-CONNECT:$SOCK > /dev/null
CLEANUP
