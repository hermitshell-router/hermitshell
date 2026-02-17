#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Export config
result=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "export_config succeeds"
assert_match "$result" '"version":1' "export contains version"
assert_match "$result" '"devices"' "export contains devices"

# Backup database
result=$(vm_exec router 'echo "{\"method\":\"backup_database\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "backup_database succeeds"
assert_match "$result" "hermitshell-backup.db" "backup returns path"

# Verify backup file exists
vm_exec router "test -f /tmp/hermitshell-backup.db"
assert_match "$?" "0" "Backup file exists"
