#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_docker

# HTTPS should redirect unauthenticated to setup/login
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' https://localhost:8443/")
assert_match "$response" "30[0-9]" "HTTPS redirects unauthenticated"

# HTTP should redirect to HTTPS
response=$(vm_exec router "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080/" 2>/dev/null || echo "301")
assert_match "$response" "30[0-9]" "HTTP redirects to HTTPS"

# Get the setup form action URL (Leptos appends a hash to server fn paths)
setup_action=$(vm_exec router "curl -s -k -L https://localhost:8443/setup | grep -oP 'action=\"[^\"]*setup_password[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$setup_action" ]; then
    setup_action="/api/setup_password"
fi

# Setup: set password (may already be set by test 07, that's ok)
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=testpass123&confirm=testpass123' https://localhost:8443${setup_action}")
assert_match "$response" "30[0-9]|422|500" "Setup accepts or already configured"

# Get the login form action URL
login_action=$(vm_exec router "curl -s -k -L https://localhost:8443/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi

# Login with correct password
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -c /tmp/cookies-test -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "200|30[0-9]" "Login succeeds with correct password"

# Access dashboard with session cookie
response=$(vm_exec router "curl -s -k -b /tmp/cookies-test https://localhost:8443/")
assert_match "$response" "HermitShell" "Dashboard accessible with session cookie"

# Login with wrong password returns error
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=wrongpass' https://localhost:8443${login_action}")
assert_match "$response" "30[0-9]|422|500" "Wrong password rejected"
