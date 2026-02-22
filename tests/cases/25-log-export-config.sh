#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent

# Reset log config to defaults (idempotency: prior run may have left non-default values)
vm_exec router 'echo "{\"method\":\"set_log_config\",\"value\":\"{\\\"log_retention_days\\\":\\\"7\\\",\\\"log_format\\\":\\\"text\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null 2>&1

# Get current log config
result=$(vm_exec router 'echo "{\"method\":\"get_log_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "get_log_config succeeds"
assert_match "$result" '"log_format"' "config contains log_format"
assert_match "$result" '"syslog_target"' "config contains syslog_target"
assert_match "$result" '"log_retention_days"' "config contains log_retention_days"

# Set log retention to 14 days
result=$(vm_exec router 'echo "{\"method\":\"set_log_config\",\"value\":\"{\\\"log_retention_days\\\":\\\"14\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_log_config succeeds"

# Verify it persisted
result=$(vm_exec router 'echo "{\"method\":\"get_log_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "get_log_config after update succeeds"
assert_match "$result" '"14"' "log_retention_days updated to 14"

# Set log format
result=$(vm_exec router 'echo "{\"method\":\"set_log_config\",\"value\":\"{\\\"log_format\\\":\\\"json\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "set_log_config log_format succeeds"

# Verify log format persisted
result=$(vm_exec router 'echo "{\"method\":\"get_log_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"json"' "log_format updated to json"

# Verify backup includes log config keys
result=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "export_config succeeds"
assert_contains "$result" 'log_retention_days' "backup includes log_retention_days"
assert_contains "$result" 'log_format' "backup includes log_format"

# Reset log config to defaults
vm_exec router 'echo "{\"method\":\"set_log_config\",\"value\":\"{\\\"log_retention_days\\\":\\\"7\\\",\\\"log_format\\\":\\\"text\\\"}\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' >/dev/null
