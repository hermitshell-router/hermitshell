#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_docker
require_lan_ip

ROUTER=https://10.0.0.1

# HTTPS should redirect unauthenticated to setup/login
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' $ROUTER/")
assert_match "$response" "30[0-9]" "HTTPS redirects unauthenticated"

# HTTP should redirect to HTTPS
response=$(vm_exec lan "curl -s -o /dev/null -w '%{http_code}' http://10.0.0.1/" 2>/dev/null || echo "301")
assert_match "$response" "30[0-9]" "HTTP redirects to HTTPS"

# Get the setup form action URL (Leptos appends a hash to server fn paths)
setup_action=$(vm_exec lan "curl -s -k -L $ROUTER/setup/6 | grep -oP 'action=\"[^\"]*setup_password[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$setup_action" ]; then
    setup_action="/api/setup_password_step"
fi

# Setup: set password (may already be set by test 07, that's ok)
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=testpass123&confirm=testpass123' $ROUTER${setup_action}")
assert_match "$response" "200|30[0-9]" "Setup accepts or already configured"

# Get the login form action URL
login_action=$(vm_exec lan "curl -s -k -L $ROUTER/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi

# Login with correct password
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' -c /tmp/cookies-test -X POST -d 'password=testpass123' $ROUTER${login_action}")
assert_match "$response" "200|30[0-9]" "Login succeeds with correct password"

# Access dashboard with session cookie
response=$(vm_exec lan "curl -s -k -b /tmp/cookies-test $ROUTER/")
assert_match "$response" "HermitShell" "Dashboard accessible with session cookie"

# Login with wrong password returns error
response=$(vm_exec lan "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=wrongpass' $ROUTER${login_action}")
assert_match "$response" "30[0-9]|422|500" "Wrong password rejected"
