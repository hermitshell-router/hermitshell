#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Unconditional pass (for assertions checked by the caller)
pass() { echo -e "${GREEN}PASS${NC}: $1"; }

# --- SSH multiplexing setup ---
# Use raw SSH with ControlMaster instead of vagrant ssh (~0.02s vs ~5s per call)
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$(dirname "${BASH_SOURCE[0]}")/deploy.sh"
SSH_SOCK_DIR="$HOME/.ssh/sockets"
mkdir -p "$SSH_SOCK_DIR"
SSH_COMMON="-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ControlMaster=auto -o ControlPath=$SSH_SOCK_DIR/%r@%h:%p -o ControlPersist=300"

# Resolve VM SSH connection details from vagrant ssh-config (cached to file)
_SSH_CACHE_DIR="/tmp/hermit-ssh-cache"
mkdir -p "$_SSH_CACHE_DIR"

_vm_ssh_args() {
    local vm=$1
    local cache_file="$_SSH_CACHE_DIR/$vm"
    if [ ! -f "$cache_file" ]; then
        local cfg
        cfg=$(cd "$TESTS_DIR" && vagrant ssh-config "$vm" 2>/dev/null)
        local host port key user
        host=$(echo "$cfg" | awk '/HostName/ {print $2}')
        port=$(echo "$cfg" | awk '/Port/ {print $2}')
        key=$(echo "$cfg" | awk '/IdentityFile/ {print $2}')
        user=$(echo "$cfg" | awk '/User / {print $2}')
        echo "-i $key -p $port ${user}@${host}" > "$cache_file"
    fi
    cat "$cache_file"
}

# Run command on VM via fast multiplexed SSH
vm_exec() {
    local vm=$1
    shift
    local args
    args=$(_vm_ssh_args "$vm")
    ssh $SSH_COMMON $args "$*" 2>/dev/null
}

# Run command on VM as root via fast multiplexed SSH
vm_sudo() {
    local vm=$1
    shift
    local args
    args=$(_vm_ssh_args "$vm")
    ssh $SSH_COMMON $args "sudo bash -c '$*'" 2>/dev/null
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
        deploy_check_webui
    }
    wait_for 30 "Web UI running" _check_ready
}

require_dns() {
    _check_ready() {
        vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" 2>/dev/null | grep -q '[0-9]'
    }
    wait_for 15 "DNS ready" _check_ready
}

# Run nft on router — uses container nft in docker mode (host nft may be incompatible)
vm_nft() {
    if [ "${HERMIT_MODE:-direct}" = "docker" ]; then
        vm_exec router "docker exec hermitshell-aio nft $*" 2>/dev/null
    else
        vm_sudo router "nft $*"
    fi
}

# Run tc on router — uses container tc in docker mode (host may not have tc)
vm_tc() {
    if [ "${HERMIT_MODE:-direct}" = "docker" ]; then
        vm_exec router "docker exec hermitshell-aio tc $*" 2>/dev/null
    else
        vm_exec router "sudo tc $*"
    fi
}

require_nftables() {
    _check_ready() {
        vm_nft "list tables" 2>/dev/null | grep -q 'inet filter'
    }
    wait_for 10 "nftables inet filter loaded" _check_ready
}
