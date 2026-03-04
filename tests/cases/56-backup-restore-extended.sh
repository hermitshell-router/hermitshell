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
