#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_docker
require_lan_ip

ROUTER=https://10.0.0.1

# HTTPS should respond (may redirect to /setup or /login since no password set yet)
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' $ROUTER/")
assert_match "$response" "200|30[0-9]" "HTTPS responds"

# HTTP should redirect to HTTPS
response=$(vm_exec lan "curl -s -o /dev/null -w '%{http_code}' http://10.0.0.1/" 2>/dev/null || echo "000")
assert_match "$response" "30[0-9]|000" "HTTP redirects or refused"

# Get the setup form action URL (Leptos appends a hash to server fn paths)
setup_action=$(vm_exec lan "curl -s -k -L $ROUTER/setup/6 | grep -oP 'action=\"[^\"]*setup_password[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$setup_action" ]; then
    setup_action="/api/setup_password_step"
fi

# Setup: set password first
vm_exec lan "curl -s -k -X POST -d 'password=testpass123&confirm=testpass123' $ROUTER${setup_action}" >/dev/null 2>&1

# Finalize setup so middleware doesn't redirect to wizard
vm_exec router 'echo "{\"method\":\"finalize_setup\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null 2>&1

# Get the login form action URL
login_action=$(vm_exec lan "curl -s -k -L $ROUTER/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi

# Login to get session cookie
vm_exec lan "curl -s -k -c /tmp/cookies -X POST -d 'password=testpass123' $ROUTER${login_action}" >/dev/null 2>&1

# Check pages with session cookie
response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/")
assert_match "$response" "HermitShell" "Dashboard responds with content"
assert_match "$response" "Dashboard" "Dashboard page renders"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/devices")
assert_match "$response" "Devices" "Devices page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/groups")
assert_match "$response" "Groups" "Groups page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/traffic")
assert_match "$response" "Traffic" "Traffic page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/dns")
assert_match "$response" "Ad Blocking" "DNS page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/settings")
assert_match "$response" "Settings" "Settings page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/wireguard")
assert_match "$response" "WireGuard" "WireGuard page responds"

response=$(vm_exec lan "curl -s -k -b /tmp/cookies $ROUTER/port-forwarding")
assert_match "$response" "Port Forwarding" "Port Forwarding page responds"

# Check CSS is served (exempt from auth)
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' $ROUTER/style.css")
assert_match "$response" "200" "CSS file served"
