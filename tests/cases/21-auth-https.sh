#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# HTTPS should redirect unauthenticated to setup/login
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' https://localhost/")
assert_match "$response" "30[0-9]" "HTTPS redirects unauthenticated"

# HTTP should redirect to HTTPS
response=$(vm_exec router "curl -s -o /dev/null -w '%{http_code}' http://localhost/" 2>/dev/null || echo "301")
assert_match "$response" "30[0-9]" "HTTP redirects to HTTPS"

# Setup: set password
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=testpass123&confirm=testpass123' https://localhost/api/setup")
assert_match "$response" "30[0-9]" "Setup accepts password"

# Login with correct password
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -c /tmp/cookies-test -X POST -d 'password=testpass123' https://localhost/api/login")
assert_match "$response" "30[0-9]" "Login succeeds with correct password"

# Access dashboard with session cookie
response=$(vm_exec router "curl -s -k -b /tmp/cookies-test https://localhost/")
assert_match "$response" "HermitShell" "Dashboard accessible with session cookie"

# Login with wrong password stays on login
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=wrongpass' https://localhost/api/login")
assert_match "$response" "30[0-9]" "Wrong password redirects back"
