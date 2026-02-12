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

# Run test cases, detect both script failures and individual assertion failures
failed=0
for test in cases/*.sh; do
    [ -f "$test" ] || continue
    echo "--- Running: $(basename "$test") ---"
    output=$(bash "$test" 2>&1)
    rc=$?
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
