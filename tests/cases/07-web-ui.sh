#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Check if container is running
assert_success "Web UI container running" \
    vm_exec router "docker ps | grep -q hermitshell"

# Check dashboard responds
response=$(vm_exec router "curl -s http://localhost:3000/")
assert_match "$response" "HermitShell" "Dashboard responds with content"
assert_match "$response" "Dashboard" "Dashboard page renders"

# Check devices page
response=$(vm_exec router "curl -s http://localhost:3000/devices")
assert_match "$response" "Devices" "Devices page responds"

# Check groups page
response=$(vm_exec router "curl -s http://localhost:3000/groups")
assert_match "$response" "Groups" "Groups page responds"
assert_match "$response" "Trusted" "Groups page shows Trusted group"

# Check traffic page
response=$(vm_exec router "curl -s http://localhost:3000/traffic")
assert_match "$response" "Traffic" "Traffic page responds"

# Check DNS page
response=$(vm_exec router "curl -s http://localhost:3000/dns")
assert_match "$response" "Ad Blocking" "DNS page responds"

# Check settings page
response=$(vm_exec router "curl -s http://localhost:3000/settings")
assert_match "$response" "Settings" "Settings page responds"

# Check CSS is served
response=$(vm_exec router "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000/style.css")
assert_match "$response" "200" "CSS file served"
