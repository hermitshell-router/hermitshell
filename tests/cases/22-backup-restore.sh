#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Export config
result=$(vm_exec router 'echo "{\"method\":\"export_config\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$result" '"ok":true' "export_config succeeds"
assert_contains "$result" 'version' "export contains version"
assert_contains "$result" 'devices' "export contains devices"

# Backup database
result=$(vm_exec router 'echo "{\"method\":\"backup_database\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$result" '"ok":true' "backup_database succeeds"
assert_match "$result" "hermitshell-backup.db" "backup returns path"

# Verify backup file exists
assert_success "Backup file exists" \
    vm_exec router "sudo test -f /data/hermitshell/hermitshell-backup.db"

# Verify backup file has restricted permissions (0600)
perms=$(vm_exec router "sudo stat -c '%a' /data/hermitshell/hermitshell-backup.db")
assert_match "$perms" "600" "Backup file has 0600 permissions"
