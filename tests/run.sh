#!/bin/bash
set -e
cd "$(dirname "$0")"

source lib/helpers.sh

echo "=== HermitShell Integration Tests ==="
echo

# Check VMs are running
echo "Checking VM status..."
vagrant status --machine-readable | grep -q "state,running" || {
    echo "VMs not running. Start with: vagrant up"
    exit 1
}

# Run test cases
failed=0
for test in cases/*.sh; do
    [ -f "$test" ] || continue
    echo "--- Running: $(basename "$test") ---"
    if bash "$test"; then
        echo
    else
        failed=$((failed + 1))
        echo
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
