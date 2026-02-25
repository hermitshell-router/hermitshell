#!/bin/bash
# Deployment-mode abstractions for test infrastructure.
# Sourced by helpers.sh. Requires HERMIT_MODE=docker|install|direct (default: direct).

HERMIT_MODE="${HERMIT_MODE:-direct}"

# Build artifacts on the host
deploy_build() {
    (cd "$TESTS_DIR/.." && bash scripts/build-agent.sh)
    if [ "$HERMIT_MODE" = "docker" ]; then
        (cd "$TESTS_DIR/.." && bash scripts/build-docker-local.sh)
        docker save hermitshell:latest -o "$TESTS_DIR/../target/release/hermitshell-aio.tar"
        echo "Docker image saved: target/release/hermitshell-aio.tar"
    fi
}

# Rsync to router VM
deploy_send() {
    (cd "$TESTS_DIR" && vagrant rsync router)
}

# Stop all hermitshell processes/containers
deploy_stop_all() {
    if [ "$HERMIT_MODE" = "docker" ]; then
        vm_sudo router "docker stop hermitshell-aio 2>/dev/null; docker rm -f hermitshell-aio 2>/dev/null; true"
        # Also stop any leftover native processes
        vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; killall hermitshell-age hermitshell-dhc blocky 2>/dev/null; true"
        # Stop old web-UI container too
        vm_sudo router "docker stop hermitshell 2>/dev/null; docker rm -f hermitshell 2>/dev/null; true"
    else
        vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; systemctl stop hermitshell-ui 2>/dev/null; killall hermitshell-age hermitshell-dhc blocky 2>/dev/null; true"
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
                --privileged \
                --network host \
                -e WAN_IFACE=eth1 \
                -e LAN_IFACE=eth2 \
                -v /data/hermitshell:/data/hermitshell \
                -v /run/hermitshell:/run/hermitshell \
                -v /var/lib/dhcp:/var/lib/dhcp:ro \
                hermitshell:latest"
            ;;
        install)
            vm_sudo router "bash /opt/hermitshell/install.sh --wan eth1 --lan eth2 --local /opt/hermitshell/hermitshell-local.tar.gz"
            ;;
        direct)
            vm_sudo router "rm -f /run/hermitshell/*.sock && cp /opt/hermitshell/hermitshell-agent.service /etc/systemd/system/ && systemctl daemon-reload && systemctl restart hermitshell-agent"
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
        install|direct)
            vm_sudo router "systemctl stop hermitshell-agent 2>/dev/null; killall hermitshell-age hermitshell-dhc blocky 2>/dev/null; true"
            ;;
    esac
}

# Start agent after stop (for restart tests)
deploy_start_agent() {
    case "$HERMIT_MODE" in
        docker)
            vm_sudo router "rm -f /run/hermitshell/*.sock && docker start hermitshell-aio"
            ;;
        install)
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
        install|direct)
            ! vm_exec router "pgrep -x hermitshell-age" 2>/dev/null | grep -q '[0-9]'
            ;;
    esac
}

# Check if agent child processes are running (for restart tests)
deploy_check_blocky_running() {
    case "$HERMIT_MODE" in
        docker)
            vm_exec router "docker exec hermitshell-aio pgrep blocky" 2>/dev/null | grep -q '[0-9]'
            ;;
        install|direct)
            vm_exec router "pgrep blocky" 2>/dev/null | grep -q '[0-9]'
            ;;
    esac
}

deploy_check_dhcp_running() {
    case "$HERMIT_MODE" in
        docker)
            vm_exec router "docker exec hermitshell-aio pgrep -x hermitshell-dhc" 2>/dev/null | grep -q '[0-9]'
            ;;
        install|direct)
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
        install)
            vm_sudo router "systemctl restart hermitshell-ui"
            ;;
        direct)
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
        install|direct)
            vm_sudo router "journalctl -u hermitshell-agent --no-pager -n 500"
            ;;
    esac
}
