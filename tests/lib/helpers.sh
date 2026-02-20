#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Run command on VM (filters out Vagrant noise, preserves exit code)
vm_exec() {
    local vm=$1
    shift
    local output
    output=$(vagrant ssh "$vm" -c "$*" 2>/dev/null)
    local rc=$?
    echo "$output" | grep -v "^==>" | grep -v "^\[fog\]"
    return $rc
}

# Assert string matches regex
assert_match() {
    local actual=$1
    local pattern=$2
    local msg=$3
    if [[ $actual =~ $pattern ]]; then
        echo -e "${GREEN}PASS${NC}: $msg"
        return 0
    else
        echo -e "${RED}FAIL${NC}: $msg"
        echo "  Expected pattern: $pattern"
        echo "  Actual: $actual"
        return 1
    fi
}

# Assert command succeeds
assert_success() {
    local msg=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}: $msg"
        return 0
    else
        echo -e "${RED}FAIL${NC}: $msg"
        return 1
    fi
}

# Assert command fails (for negative tests)
assert_failure() {
    local msg=$1
    shift
    if "$@" >/dev/null 2>&1; then
        echo -e "${RED}FAIL${NC}: $msg (expected failure but succeeded)"
        return 1
    else
        echo -e "${GREEN}PASS${NC}: $msg"
        return 0
    fi
}

# Assert string contains fixed substring (no regex — safe for long strings)
assert_contains() {
    local actual=$1
    local substring=$2
    local msg=$3
    if echo "$actual" | grep -qF "$substring"; then
        echo -e "${GREEN}PASS${NC}: $msg"
        return 0
    else
        echo -e "${RED}FAIL${NC}: $msg"
        echo "  Expected substring: $substring"
        echo "  Actual: $actual"
        return 1
    fi
}

# Wait for condition with timeout
wait_for() {
    local timeout=$1
    local msg=$2
    shift 2
    local count=0
    while ! "$@" >/dev/null 2>&1; do
        sleep 1
        count=$((count + 1))
        if [ $count -ge $timeout ]; then
            echo -e "${RED}TIMEOUT${NC}: $msg"
            return 1
        fi
    done
    echo -e "${GREEN}OK${NC}: $msg"
    return 0
}

# --- Infrastructure readiness guards ---

require_agent() {
    _check_ready() {
        vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' 2>/dev/null | grep -q '"ok":true'
    }
    wait_for 15 "Agent socket ready" _check_ready
}

require_wan() {
    _check_ready() {
        vm_exec router "ping -c1 -W2 192.168.100.2" >/dev/null 2>&1
    }
    wait_for 15 "WAN connectivity" _check_ready
}

require_lan_ip() {
    _check_ready() {
        vm_exec lan "ip -4 addr show eth1" 2>/dev/null | grep -q '10\.0\.'
    }
    wait_for 15 "LAN device has IP" _check_ready
}

require_docker() {
    _check_ready() {
        vm_exec router "docker inspect -f '{{.State.Running}}' hermitshell" 2>/dev/null | grep -q true
    }
    wait_for 20 "Docker container running" _check_ready
}

require_blocky() {
    _check_ready() {
        vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" 2>/dev/null | grep -q '[0-9]'
    }
    wait_for 15 "Blocky DNS ready" _check_ready
}

require_nftables() {
    _check_ready() {
        vagrant ssh router -c "sudo nft list tables" 2>/dev/null | grep -q 'inet filter'
    }
    wait_for 10 "nftables inet filter loaded" _check_ready
}
