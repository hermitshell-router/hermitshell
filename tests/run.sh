#!/bin/bash
set -e
cd "$(dirname "$0")"

source lib/helpers.sh

echo "=== HermitShell Integration Tests ==="
echo

# Build binaries before testing
echo "Building binaries..."
(cd .. && bash scripts/build-agent.sh)
echo

# Deploy fresh binaries to router and restart agent
echo "Deploying to router..."
vagrant rsync router
vagrant ssh router -c "sudo systemctl stop hermitshell-agent 2>/dev/null; sudo killall hermitshell-age hermitshell-dhc blocky 2>/dev/null; true" 2>/dev/null || true
sleep 2
vagrant ssh router -c "sudo rm -f /run/hermitshell/*.sock && sudo cp /opt/hermitshell/hermitshell-agent.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl restart hermitshell-agent" 2>&1 || true
# Wait for agent socket to appear
for i in $(seq 1 30); do
    if vagrant ssh router -c "test -S /run/hermitshell/agent.sock" 2>/dev/null; then
        break
    fi
    sleep 1
done
vagrant ssh router -c "sudo chmod 666 /run/hermitshell/agent.sock" 2>/dev/null || true
# Verify agent responds before running tests
for i in $(seq 1 10); do
    result=$(vagrant ssh router -c 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' 2>/dev/null || true)
    if echo "$result" | grep -q '"ok":true'; then
        break
    fi
    sleep 1
done

# Reload web UI container if image tar exists
vagrant ssh router -c "sudo bash -c 'if [ -f /opt/hermitshell/hermitshell-container.tar ]; then docker load -i /opt/hermitshell/hermitshell-container.tar; docker rm -f hermitshell 2>/dev/null; docker run -d --name hermitshell --network host -v /run/hermitshell:/run/hermitshell hermitshell:latest; fi'" 2>/dev/null || true
# Wait for container to be running
for i in $(seq 1 15); do
    if vagrant ssh router -c "docker inspect -f '{{.State.Running}}' hermitshell 2>/dev/null" 2>/dev/null | grep -q true; then
        break
    fi
    sleep 1
done
echo

# Check VMs are running
echo "Checking VM status..."
vagrant status --machine-readable | grep -q "state,running" || {
    echo "VMs not running. Start with: vagrant up"
    exit 1
}

# Run test cases, detect both script failures and individual assertion failures
failed=0
for test in cases/*.sh; do
    [ -f "$test" ] || continue
    echo "--- Running: $(basename "$test") ---"
    output=$(bash "$test" 2>&1) && rc=0 || rc=$?
    echo "$output"
    echo

    if [ $rc -ne 0 ]; then
        failed=$((failed + 1))
    elif echo "$output" | grep -q "FAIL"; then
        echo "  (assertion failure detected)"
        failed=$((failed + 1))
    fi
done

echo "=== Results ==="
if [ $failed -eq 0 ]; then
    echo -e "${GREEN}All tests passed${NC}"
    exit 0
else
    echo -e "${RED}$failed test(s) failed${NC}"
    exit 1
fi
