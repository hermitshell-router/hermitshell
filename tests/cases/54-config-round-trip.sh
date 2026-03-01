#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

# Run the entire round-trip on the router to avoid nested JSON quoting issues.
# The config_value field in the get_full_config response is a JSON string
# (double-encoded), so we use python3 to parse and reconstruct it.
args=$(_vm_ssh_args router)
round_trip=$(ssh $SSH_COMMON $args 'bash -s' 2>/dev/null <<'RTSCRIPT'
SOCK=/run/hermitshell/agent.sock

# 1. Export current config
export1=$(echo '{"method":"get_full_config"}' | socat - UNIX-CONNECT:$SOCK)
ok1=$(echo "$export1" | python3 -c "import sys,json; r=json.load(sys.stdin); print('true' if r.get('ok') else 'false')" 2>/dev/null)
echo "EXPORT1_OK:$ok1"

if [ "$ok1" != "true" ]; then
    echo "EXPORT1_FAILED"
    exit 0
fi

# Save config_value (the inner JSON string) to a file for safe handling
echo "$export1" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
cv = resp.get('config_value', '{}')
# Parse and re-serialize to normalize
config = json.loads(cv)
with open('/tmp/hermit-rt-config1.json', 'w') as f:
    json.dump(config, f, sort_keys=True)
" 2>/dev/null

# 2. Apply it back via apply_config
apply_payload=$(python3 -c "
import json
config = json.load(open('/tmp/hermit-rt-config1.json'))
req = {'method': 'apply_config', 'value': json.dumps(config)}
print(json.dumps(req))
" 2>/dev/null)

apply_resp=$(echo "$apply_payload" | socat -t 5 - UNIX-CONNECT:$SOCK)
ok_apply=$(echo "$apply_resp" | python3 -c "import sys,json; r=json.load(sys.stdin); print('true' if r.get('ok') else 'false')" 2>/dev/null)
echo "APPLY_OK:$ok_apply"

# 3. Export again
export2=$(echo '{"method":"get_full_config"}' | socat - UNIX-CONNECT:$SOCK)
ok2=$(echo "$export2" | python3 -c "import sys,json; r=json.load(sys.stdin); print('true' if r.get('ok') else 'false')" 2>/dev/null)
echo "EXPORT2_OK:$ok2"

# Save second config
echo "$export2" | python3 -c "
import sys, json
resp = json.load(sys.stdin)
cv = resp.get('config_value', '{}')
config = json.loads(cv)
with open('/tmp/hermit-rt-config2.json', 'w') as f:
    json.dump(config, f, sort_keys=True)
" 2>/dev/null

# 4. Compare the two configs
match=$(python3 -c "
import json
c1 = json.load(open('/tmp/hermit-rt-config1.json'))
c2 = json.load(open('/tmp/hermit-rt-config2.json'))
if c1 == c2:
    print('MATCH')
else:
    # Show first difference for debugging
    s1 = json.dumps(c1, sort_keys=True, indent=2).splitlines()
    s2 = json.dumps(c2, sort_keys=True, indent=2).splitlines()
    for i, (a, b) in enumerate(zip(s1, s2)):
        if a != b:
            print('MISMATCH line %d: %s != %s' % (i, a, b))
            break
    else:
        if len(s1) != len(s2):
            print('MISMATCH length %d vs %d' % (len(s1), len(s2)))
        else:
            print('MISMATCH unknown')
" 2>/dev/null)
echo "COMPARE:$match"

# Cleanup temp files
rm -f /tmp/hermit-rt-config1.json /tmp/hermit-rt-config2.json
RTSCRIPT
)

assert_contains "$round_trip" "EXPORT1_OK:true" "First export succeeds"
assert_contains "$round_trip" "APPLY_OK:true" "Re-apply succeeds"
assert_contains "$round_trip" "EXPORT2_OK:true" "Second export succeeds"
assert_contains "$round_trip" "COMPARE:MATCH" "Round-trip produces identical config"
