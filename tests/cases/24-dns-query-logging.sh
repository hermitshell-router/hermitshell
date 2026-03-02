#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_dns

# Make DNS queries from the router that we can identify in logs.
# Using the router avoids cross-VM networking flakiness during suite runs.
# Send a burst of queries to overflow unbound's stdio write buffer (~4KB);
# a single query line is ~80 bytes and may sit in the buffer indefinitely.
vm_exec router "for i in \$(seq 1 60); do dig +short dns-log-test-\$i.example.com @10.0.0.1 +time=1 +tries=1 2>/dev/null & done; wait" || true
vm_exec router "dig +short dns-log-test.example.com @10.0.0.1 2>/dev/null" || true

# Wait for the periodic ingest loop (30s) to pick up the query.
# On-demand ingest via ingest_dns_logs is rate-limited (10s debounce) and
# unbound 1.19+ buffers log output, so the periodic loop is more reliable.
# Trigger one immediate ingest first for the common fast path.
sleep 1
vm_sudo router 'echo "{\"method\":\"ingest_dns_logs\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' > /dev/null
dns_logged() {
    vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":200}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' | grep -q 'dns-log-test'
}
wait_for 60 "DNS query logged in database" dns_logged || exit 1

# Query DNS logs (unfiltered)
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":100}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs succeeds"
assert_contains "$result" '"dns_logs"' "response has dns_logs field"

# Verify the logged query has correct fields
assert_contains "$result" 'dns-log-test' "Log has correct queried domain"
assert_contains "$result" '"domain"' "Log entries have domain field"
assert_contains "$result" '"ts":' "Log has timestamp"

# Query with offset
result=$(vm_exec router 'echo "{\"method\":\"list_dns_logs\",\"limit\":10,\"offset\":0}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "list_dns_logs with offset succeeds"
