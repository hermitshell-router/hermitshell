#!/bin/bash
# Deployment-mode abstractions for test infrastructure.
# Sourced by helpers.sh. Requires HERMIT_MODE=docker|install|direct (default: direct).

HERMIT_MODE="${HERMIT_MODE:-direct}"

# Resolve nix-store binary paths on the NixOS router VM.
# Called once, results cached in _NIX_PATHS_RESOLVED.
# NixOS SSH sessions have a minimal PATH that excludes /run/current-system/sw/bin,
# so we prepend it explicitly.
_NIX_PATHS_RESOLVED=""
_resolve_nix_paths() {
    if [ -n "$_NIX_PATHS_RESOLVED" ]; then return; fi
    local nix_which="PATH=/run/current-system/sw/bin:\$PATH which"
    _NIX_NFT=$(vm_exec router "$nix_which nft")
    _NIX_IP=$(vm_exec router "$nix_which ip")
    _NIX_WG=$(vm_exec router "$nix_which wg")
    _NIX_TC=$(vm_exec router "$nix_which tc")
    _NIX_MODPROBE=$(vm_exec router "$nix_which modprobe")
    _NIX_CONNTRACK=$(vm_exec router "$nix_which conntrack")
    _NIX_PATHS_RESOLVED=1
}

# Build the env var string for launching the agent on NixOS
_nix_agent_env() {
    _resolve_nix_paths
    echo "PATH=/run/current-system/sw/bin:/usr/bin:/usr/sbin:/bin:/sbin WAN_IFACE=eth1 LAN_IFACE=eth2 HERMITSHELL_NFT_PATH=$_NIX_NFT HERMITSHELL_IP_PATH=$_NIX_IP HERMITSHELL_WG_PATH=$_NIX_WG HERMITSHELL_TC_PATH=$_NIX_TC HERMITSHELL_MODPROBE_PATH=$_NIX_MODPROBE HERMITSHELL_CONNTRACK_PATH=$_NIX_CONNTRACK"
}

# Start agent on NixOS. SSH+ControlMaster keeps sessions open when a backgrounded
# child inherits fds, so we cap the wait at 10s — the agent starts within 1s.
_nix_start_agent() {
    local env="$1"
    local args
    args=$(_vm_ssh_args router)
    timeout 10 ssh $SSH_COMMON $args "sudo bash -c '$env setsid /opt/hermitshell/hermitshell-agent </dev/null >/var/log/hermitshell-agent.log 2>&1 &'" 2>/dev/null || true
    # Wait briefly for the agent to create its socket
    for i in $(seq 1 10); do
        if vm_exec router "test -S /run/hermitshell/agent.sock" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
}

# Build artifacts on the host
deploy_build() {
    (cd "$TESTS_DIR/.." && bash scripts/build-agent.sh)
    if [ "$HERMIT_MODE" = "docker" ]; then
        (cd "$TESTS_DIR/.." && bash scripts/build-docker-local.sh)
        docker save hermitshell:latest -o "$TESTS_DIR/../target/release/hermitshell-aio.tar"
        echo "Docker image saved: target/release/hermitshell-aio.tar"
    fi
    # deb mode: build-agent.sh already builds the .deb if cargo-deb is available
}

# Rsync to router VM
deploy_send() {
    if [ "$HERMIT_MODE" = "nix" ]; then
        # NixOS has read-only /etc so 'vagrant rsync' fails (writes to /etc/fstab).
        # Use raw rsync via SSH instead.
        _deploy_rsync_nix "$TESTS_DIR/../target/release/" "/opt/hermitshell/"
        _deploy_rsync_nix "$TESTS_DIR/../" "/hermitshell-src/" \
            --exclude target/ --exclude .git/ --exclude tests/.vagrant/ \
            --exclude docker-ctx/ --exclude .worktrees/
    else
        (cd "$TESTS_DIR" && vagrant rsync router)
    fi
}

# Rsync a local path to the NixOS router via SSH.
# Usage: _deploy_rsync_nix <local_path> <remote_path> [extra rsync args...]
_deploy_rsync_nix() {
    local src="$1" dest="$2"
    shift 2
    local args
    args=$(_vm_ssh_args router)
    # Parse ssh args: "-i /key [-i /key2] -p PORT [-o ...] user@host"
    # Extract all -i and -o flags for SSH, plus port and user@host
    local ssh_flags="" port="" userhost=""
    local -a tokens=($args)
    local i=0
    while [ $i -lt ${#tokens[@]} ]; do
        case "${tokens[$i]}" in
            -i) ssh_flags="$ssh_flags -i ${tokens[$((i+1))]}"; i=$((i+2)) ;;
            -p) port="${tokens[$((i+1))]}"; i=$((i+2)) ;;
            -o) ssh_flags="$ssh_flags -o ${tokens[$((i+1))]}"; i=$((i+2)) ;;
            *@*) userhost="${tokens[$i]}"; i=$((i+1)) ;;
            *) i=$((i+1)) ;;
        esac
    done
    vm_sudo router "mkdir -p $dest && chown vagrant:vagrant $dest"
    rsync -az --delete \
        -e "ssh $SSH_COMMON $ssh_flags -p $port" \
        "$@" \
        "$src" "${userhost}:${dest}"
}

# Stop all hermitshell processes/containers
deploy_stop_all() {
    if [ "$HERMIT_MODE" = "docker" ]; then
        vm_sudo router "docker stop hermitshell-aio 2>/dev/null; docker rm -f hermitshell-aio 2>/dev/null; true"
        # Also stop any leftover native processes
        vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; pkill -f hermitshell-agent 2>/dev/null; pkill -f hermitshell-dhcp 2>/dev/null; pkill unbound 2>/dev/null; true"
        # Stop old web-UI container too
        vm_sudo router "docker stop hermitshell 2>/dev/null; docker rm -f hermitshell 2>/dev/null; true"
    else
        vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; systemctl stop hermitshell-ui 2>/dev/null; pkill -f hermitshell-agent 2>/dev/null; pkill -f hermitshell-dhcp 2>/dev/null; pkill unbound 2>/dev/null; true"
        vm_sudo router "docker stop hermitshell 2>/dev/null; docker rm -f hermitshell 2>/dev/null; true"
        vm_sudo router "docker stop hermitshell-aio 2>/dev/null; docker rm -f hermitshell-aio 2>/dev/null; true"
    fi
}

# Start services after fresh deploy
deploy_start() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "docker load -i /opt/hermitshell/hermitshell-aio.tar"
            vm_sudo router "docker run -d \
                --name hermitshell-aio \
                --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_MODULE \
                --device /dev/net/tun --security-opt no-new-privileges \
                --network host \
                -e WAN_IFACE=eth1 \
                -e LAN_IFACE=eth2 \
                -v /var/lib/hermitshell:/var/lib/hermitshell \
                -v /run/hermitshell:/run/hermitshell \
                hermitshell:latest"
            ;;
        install)
            vm_sudo router "bash /opt/hermitshell/install.sh --wan eth1 --lan eth2 --local /opt/hermitshell/hermitshell-local.tar.gz"
            ;;
        deb)
            vm_sudo router "dpkg -i /opt/hermitshell/hermitshell_*.deb || true"
            vm_sudo router "apt-get install -f -y"
            vm_sudo router "sed -i 's/^WAN_IFACE=.*/WAN_IFACE=eth1/' /etc/default/hermitshell"
            vm_sudo router "sed -i 's/^LAN_IFACE=.*/LAN_IFACE=eth2/' /etc/default/hermitshell"
            vm_sudo router "systemctl start hermitshell-agent hermitshell-ui"
            ;;
        direct)
            vm_sudo router "rm -f /run/hermitshell/*.sock && cp /opt/hermitshell/hermitshell-agent.service /etc/systemd/system/ && systemctl daemon-reload && systemctl restart hermitshell-agent"
            vm_sudo router "if [ -f /opt/hermitshell/hermitshell-container.tar ]; then docker load -i /opt/hermitshell/hermitshell-container.tar; docker rm -f hermitshell 2>/dev/null; docker run -d --name hermitshell --restart unless-stopped --network host --read-only --cap-drop ALL --security-opt no-new-privileges -v /run/hermitshell:/run/hermitshell hermitshell:latest; fi"
            ;;
        nix)
            local env
            env=$(_nix_agent_env)
            vm_sudo router "rm -f /run/hermitshell/*.sock"
            # Start agent. SSH+ControlMaster may keep the session open because
            # the backgrounded process inherits fds — cap the wait with timeout.
            # The agent starts within 1s; the 5s timeout only fires on the hang.
            _nix_start_agent "$env"
            vm_sudo router "if [ -f /opt/hermitshell/hermitshell-container.tar ]; then docker load -i /opt/hermitshell/hermitshell-container.tar; docker rm -f hermitshell 2>/dev/null; docker run -d --name hermitshell --restart unless-stopped --network host --read-only --cap-drop ALL --security-opt no-new-privileges -v /run/hermitshell:/run/hermitshell hermitshell:latest; fi"
            ;;
    esac
}

# Stop agent (for restart tests)
deploy_stop_agent() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "docker stop hermitshell-aio"
            ;;
        install|direct|deb|nix)
            vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; pkill -f hermitshell-agent 2>/dev/null; pkill -f hermitshell-dhcp 2>/dev/null; pkill unbound 2>/dev/null; true"
            ;;
    esac
}

# Start agent after stop (for restart tests)
deploy_start_agent() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "rm -f /run/hermitshell/*.sock && docker start hermitshell-aio"
            ;;
        install|deb)
            vm_sudo router "rm -f /run/hermitshell/*.sock && systemctl restart hermitshell-agent"
            # Wait for socket, then restart UI (PartOf= may race with socket creation)
            for i in $(seq 1 15); do
                if vm_exec router "test -S /run/hermitshell/agent.sock" 2>/dev/null; then
                    vm_sudo router "systemctl restart hermitshell-ui"
                    break
                fi
                sleep 1
            done
            ;;
        direct)
            vm_sudo router "rm -f /run/hermitshell/*.sock && systemctl restart hermitshell-agent"
            ;;
        nix)
            local env
            env=$(_nix_agent_env)
            vm_sudo router "rm -f /run/hermitshell/*.sock"
            _nix_start_agent "$env"
            ;;
    esac
}

# Check if agent process is dead (for restart tests)
deploy_agent_dead() {
    case "$HERMIT_MODE" in
        docker)
            # Container should be stopped
            local state
            state=$(vm_exec router "docker inspect -f '{{.State.Running}}' hermitshell-aio 2>/dev/null" 2>/dev/null || echo "false")
            [ "$state" != "true" ]
            ;;
        install|direct|deb|nix)
            ! vm_exec router "pgrep -f hermitshell-agent" 2>/dev/null | grep -q '[0-9]'
            ;;
    esac
}

# Check if DNS process is running (for restart tests)
deploy_check_dns_running() {
    case "$HERMIT_MODE" in
        docker)
            vm_exec router "docker exec hermitshell-aio pgrep unbound" 2>/dev/null | grep -q '[0-9]'
            ;;
        install|direct|deb|nix)
            vm_exec router "pgrep unbound" 2>/dev/null | grep -q '[0-9]'
            ;;
    esac
}

deploy_check_dhcp_running() {
    case "$HERMIT_MODE" in
        docker)
            vm_exec router "docker exec hermitshell-aio pgrep -x hermitshell-dhc" 2>/dev/null | grep -q '[0-9]'
            ;;
        install|direct|deb|nix)
            vm_exec router "pgrep -x hermitshell-dhc" 2>/dev/null | grep -q '[0-9]'
            ;;
    esac
}

# Restart web UI (to clear rate-limit state between test phases)
deploy_restart_webui() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "docker restart hermitshell-aio"
            ;;
        install|deb)
            vm_sudo router "systemctl restart hermitshell-ui"
            ;;
        direct|nix)
            vm_sudo router "docker rm -f hermitshell 2>/dev/null; docker run -d --name hermitshell --restart unless-stopped --network host --read-only --cap-drop ALL --security-opt no-new-privileges -v /run/hermitshell:/run/hermitshell hermitshell:latest"
            ;;
    esac
}

# Check if web UI is reachable
deploy_check_webui() {
    # Use port 8443 directly — nftables 443->8443 redirect only applies to LAN-sourced traffic
    vm_exec router "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/" 2>/dev/null | grep -q '200\|30[0-9]'
}

# Get agent log output
deploy_get_agent_log() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "docker logs hermitshell-aio 2>&1"
            ;;
        install|direct|deb)
            vm_sudo router "journalctl -u hermitshell-agent --no-pager -n 500"
            ;;
        nix)
            vm_sudo router "tail -500 /var/log/hermitshell-agent.log 2>/dev/null || true"
            ;;
    esac
}
