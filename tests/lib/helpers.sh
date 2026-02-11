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
