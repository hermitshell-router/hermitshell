#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_docker

# Get a valid login session for authenticated endpoint testing
login_action=$(vm_exec router "curl -s -k -L https://localhost:8443/login | grep -oP 'action=\"[^\"]*login[^\"]*\"' | head -1 | grep -oP '/api/[^\"]*'")
if [ -z "$login_action" ]; then
    login_action="/api/login"
fi

# POST with no origin headers (curl default) should succeed — non-browser client
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "200|30[0-9]" "POST without origin headers succeeds (non-browser)"

# POST with Sec-Fetch-Site: same-origin should succeed
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-origin' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "200|30[0-9]" "POST with Sec-Fetch-Site: same-origin succeeds"

# POST with Sec-Fetch-Site: cross-site should be rejected
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: cross-site' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "403" "POST with Sec-Fetch-Site: cross-site blocked"

# POST with Sec-Fetch-Site: same-site should be rejected (not same-origin)
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: same-site' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "403" "POST with Sec-Fetch-Site: same-site blocked"

# POST with Sec-Fetch-Site: none should be rejected
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: none' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "403" "POST with Sec-Fetch-Site: none blocked"

# POST with matching Origin header should succeed
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Origin: https://localhost:8443' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "200|30[0-9]" "POST with matching Origin succeeds"

# POST with mismatched Origin header should be rejected
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Origin: https://evil.com' -X POST -d 'password=testpass123' https://localhost:8443${login_action}")
assert_match "$response" "403" "POST with mismatched Origin blocked"

# GET requests should always pass regardless of headers
response=$(vm_exec router "curl -s -k -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Site: cross-site' https://localhost:8443/login")
assert_match "$response" "200" "GET with cross-site header still succeeds"
