#!/bin/bash
set -e
cd "$(dirname "$0")"

# Parse arguments
HERMIT_MODE="${HERMIT_MODE:-direct}"
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) HERMIT_MODE="$2"; shift 2 ;;
        *) echo "Usage: $0 [--mode docker|install|direct]"; exit 1 ;;
    esac
done
export HERMIT_MODE

# Clear stale SSH config cache from prior VM sessions
rm -rf /tmp/hermit-ssh-cache

source lib/helpers.sh

SUITE_START=$SECONDS

echo "=== HermitShell Integration Tests (mode: $HERMIT_MODE) ==="
echo

# Build artifacts
echo "Building ($HERMIT_MODE mode)..."
build_start=$SECONDS
deploy_build
build_time=$((SECONDS - build_start))
echo "Build: ${build_time}s"
echo

# Ensure WAN VM NAT rules are present (non-persistent across reboots)
vm_sudo wan "nft list table ip nat 2>/dev/null | grep -q masquerade || { nft add table ip nat; nft add chain ip nat postrouting '{ type nat hook postrouting priority 100 ; }'; nft add rule ip nat postrouting oifname eth0 masquerade; }" || true

# Deploy fresh binaries to router and start services
echo "Deploying to router ($HERMIT_MODE)..."
deploy_timer=$SECONDS
deploy_send
deploy_stop_all || true
sleep 2
vm_sudo router "rm -f /run/hermitshell/*.sock" || true
deploy_start || true

# Deploy dhclient hook so DHCP renewals set the default route via hermitshell router
cat lib/rfc3442-classless-routes | vm_sudo lan "tee /etc/dhcp/dhclient-exit-hooks.d/rfc3442-classless-routes > /dev/null" || true
# Renew DHCP lease so the new hook takes effect and sets the default route
vm_sudo lan "dhclient -r eth1 2>/dev/null; dhclient eth1 2>/dev/null" || true

# Batch readiness polling: check all services in parallel per iteration
echo "Waiting for services..."
agent_sock=false; agent_ok=false; blocky_ok=false; docker_ok=false; lan_ok=false
for i in $(seq 1 45); do
    if ! $agent_sock; then
        if vm_exec router "test -S /run/hermitshell/agent.sock" 2>/dev/null; then
            agent_sock=true
            vm_sudo router "chmod 666 /run/hermitshell/agent.sock" || true
        fi
    fi
    if $agent_sock && ! $agent_ok; then
        result=$(vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' 2>/dev/null || true)
        if echo "$result" | grep -q '"ok":true'; then
            agent_ok=true
        fi
    fi
    if ! $blocky_ok; then
        if vm_exec router "dig +short +time=1 +tries=1 @10.0.0.1 example.com" 2>/dev/null | grep -q '[0-9]'; then
            blocky_ok=true
        fi
    fi
    if ! $docker_ok; then
        if deploy_check_webui 2>/dev/null; then
            docker_ok=true
        fi
    fi
    if ! $lan_ok; then
        if vm_exec lan "ip -4 addr show eth1 | grep -q '10\.0\.'" 2>/dev/null; then
            lan_ok=true
        fi
    fi
    if $agent_sock && $agent_ok && $blocky_ok && $docker_ok && $lan_ok; then
        echo "All services ready."
        break
    fi
    sleep 1
done
deploy_time=$((SECONDS - deploy_timer))
echo "Deploy+wait: ${deploy_time}s"
echo

# Reset all devices to quarantine so tests start with clean state
vm_exec router 'for mac in $(echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock 2>/dev/null | grep -oP "\"mac\":\"[^\"]+\"" | grep -oP "[0-9a-f:]+"); do echo "{\"method\":\"set_device_group\",\"mac\":\"$mac\",\"group\":\"quarantine\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock >/dev/null 2>&1; done' || true

# Disable QoS if left enabled from a prior run
vm_exec router 'echo "{\"method\":\"set_qos_config\",\"enabled\":false}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' || true

# Check VMs are running
echo "Checking VM status..."
vagrant status --machine-readable | grep -q "state,running" || {
    echo "VMs not running. Start with: vagrant up"
    exit 1
}

# --- Parallel test runner with timing ---

# Accumulated test results: "name duration status" per line
TEST_RESULTS_FILE=$(mktemp /tmp/hermit-results-XXXXXX)
test_start_time=$SECONDS

# Run a group of tests serially, capturing output to a temp file.
# Writes fail count to ${tmpfile}.rc, timing to ${tmpfile}.times
run_group() {
    local tmpfile=$(mktemp /tmp/hermit-test-XXXXXX)
    local group_failed=0
    for test in "$@"; do
        [ -f "$test" ] || continue
        local tname=$(basename "$test" .sh)
        local t_start=$SECONDS
        echo "--- Running: $(basename "$test") ---" >> "$tmpfile"
        output=$(bash "$test" 2>&1) && rc=0 || rc=$?
        local t_elapsed=$((SECONDS - t_start))
        echo "$output" >> "$tmpfile"
        echo >> "$tmpfile"
        local status="PASS"
        if [ $rc -ne 0 ]; then
            group_failed=$((group_failed + 1))
            status="FAIL"
        elif echo "$output" | grep -q "FAIL"; then
            echo "  (assertion failure detected)" >> "$tmpfile"
            group_failed=$((group_failed + 1))
            status="FAIL"
        fi
        echo "${tname} ${t_elapsed} ${status}" >> "${tmpfile}.times"
    done
    echo "$group_failed" > "${tmpfile}.rc"
    echo "$tmpfile"
}

failed=0
TMPDIR=$(mktemp -d /tmp/hermit-tests-XXXXXX)

run_phase() {
    local phase_name="$1"; shift
    local -a group_files=()
    local -a pids=()
    local gidx=0
    local phase_start=$SECONDS

    echo "=== Phase: $phase_name ==="

    for group in "$@"; do
        local outfile="${TMPDIR}/phase-${phase_name}-g${gidx}"
        (run_group $group > "$outfile") &
        pids+=($!)
        group_files+=("$outfile")
        gidx=$((gidx + 1))
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || true
    done

    # Print output, collect failures and timing
    for gf in "${group_files[@]}"; do
        if [ -f "$gf" ]; then
            local tmpfile=$(cat "$gf")
            if [ -f "$tmpfile" ]; then
                cat "$tmpfile"
                if [ -f "${tmpfile}.rc" ]; then
                    local gfail=$(cat "${tmpfile}.rc")
                    failed=$((failed + gfail))
                fi
                if [ -f "${tmpfile}.times" ]; then
                    cat "${tmpfile}.times" >> "$TEST_RESULTS_FILE"
                fi
                rm -f "$tmpfile" "${tmpfile}.rc" "${tmpfile}.times"
            fi
        fi
        rm -f "$gf"
    done

    local phase_elapsed=$((SECONDS - phase_start))
    echo "--- Phase ${phase_name}: ${phase_elapsed}s (${gidx} group(s)) ---"
    echo
}

# Deployment-specific checks
run_phase "deploy-check" \
    "cases/34-deploy-docker.sh cases/35-deploy-install.sh"

# All tests run serially to avoid vagrant SSH contention.
# Parallel groups cause intermittent empty socat/curl responses.
run_phase "all" \
    "cases/01-wan-connectivity.sh cases/02-lan-dhcp.sh cases/03-lan-internet.sh cases/04-agent-socket.sh cases/05-device-discovery.sh cases/06-bandwidth-tracking.sh cases/10-subnet-assignment.sh cases/18-hostname-capture.sh cases/33-dhcp-hardening.sh cases/07-web-ui.sh cases/21-auth-https.sh cases/12-ad-blocking.sh cases/13-dns-redirect.sh cases/23-connection-logging.sh cases/24-dns-query-logging.sh cases/25-log-export-config.sh cases/08-device-quarantine.sh cases/09-device-approval.sh cases/11-device-block.sh cases/15-device-groups.sh cases/16-wireguard-setup.sh cases/17-wireguard-peer-traffic.sh cases/22-backup-restore.sh cases/26-config-key-protection.sh cases/27-runzero-config.sh cases/28-behavioral-analysis.sh cases/19-port-forwarding.sh cases/20-dhcp-reservation.sh cases/36-tls-management.sh cases/14-agent-restart.sh"

# Ensure socket is accessible after restart
vm_sudo router "chmod 666 /run/hermitshell/agent.sock" || true

# Wait for web UI to recover after agent restart (install mode needs this)
_webui_ready() { deploy_check_webui; }
wait_for 30 "Web UI ready after restart" _webui_ready || true

# QoS runs after restart since it does its own agent restart internally
run_phase "qos" \
    "cases/29-qos.sh"

# Ensure socket is accessible after QoS restart
vm_sudo router "chmod 666 /run/hermitshell/agent.sock" || true

# Wait for web UI to recover after QoS agent restart
wait_for 30 "Web UI ready after QoS restart" _webui_ready || true

# Rate limiting runs last (leaves rate limit state dirty, needs clean agent)
run_phase "rate-limit" \
    "cases/30-login-rate-limiting.sh"

# Session TTL — restart web UI to clear rate limit state
deploy_restart_webui || true
vm_sudo router "chmod 666 /run/hermitshell/agent.sock" || true
wait_for 30 "Web UI ready after restart" _webui_ready || true
run_phase "session-ttl" \
    "cases/31-session-ttl.sh"

run_phase "csrf" \
    "cases/32-csrf-protection.sh"

test_time=$((SECONDS - test_start_time))

# Cleanup
rm -rf "$TMPDIR"

# --- Summary ---
suite_time=$((SECONDS - SUITE_START))

echo "=== Timing ==="
printf "%-30s %5s %s\n" "TEST" "TIME" "STATUS"
printf "%-30s %5s %s\n" "----" "----" "------"
while read -r name duration status; do
    printf "%-30s %4ss %s\n" "$name" "$duration" "$status"
done < "$TEST_RESULTS_FILE"
echo
printf "%-30s %4ss\n" "Build" "$build_time"
printf "%-30s %4ss\n" "Deploy+wait" "$deploy_time"
printf "%-30s %4ss\n" "Tests" "$test_time"
printf "%-30s %4ss\n" "Total" "$suite_time"

rm -f "$TEST_RESULTS_FILE"

echo
echo "=== Results ==="
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}All tests passed${NC} in ${suite_time}s"
    exit 0
else
    echo -e "${RED}$failed test(s) failed${NC} in ${suite_time}s"
    exit 1
fi
