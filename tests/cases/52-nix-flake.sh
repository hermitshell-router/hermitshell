#!/bin/bash
# Test: Nix flake builds and NixOS module evaluates
# Requires: NixOS router VM (HERMIT_DISTRO=nixos)
source "$(dirname "$0")/../lib/helpers.sh"

echo "=== Test: Nix flake ==="

# Skip on non-NixOS distros
if [ "${HERMIT_DISTRO:-debian12}" != "nixos" ]; then
    pass "Skipped (not NixOS)"
    exit 0
fi

# Verify nix is available
assert_success "nix command available" vm_exec router "nix --version"

# Verify flakes are enabled
assert_success "flakes enabled" vm_exec router "nix flake --help"

# Verify source tree was rsynced
assert_success "flake.nix present" vm_exec router "test -f /hermitshell-src/flake.nix"

# Check the flake is valid (fast — just parses the nix expressions)
result=$(vm_exec router "cd /hermitshell-src && nix flake show 2>&1" || true)
assert_match "$result" "packages" "flake show lists packages"

# Evaluate the NixOS module (fast — just checks nix expression validity)
result=$(vm_exec router "cd /hermitshell-src && nix eval .#nixosModules.default 2>&1" || true)
assert_match "$result" "lambda|«lambda»|<LAMBDA>" "NixOS module evaluates"

# Full nix build (slow — compiles Rust from source, ~10-30 min)
# Only run if HERMIT_NIX_BUILD=1 is set (too slow for normal test runs)
if [ "${HERMIT_NIX_BUILD:-0}" = "1" ]; then
    echo "Building flake (this will take a while)..."
    build_result=$(vm_exec router "cd /hermitshell-src && nix build --no-link --print-out-paths 2>&1" || true)
    assert_match "$build_result" "/nix/store/" "nix build produces store path"

    # Verify all three binaries exist in the build output
    store_path=$(echo "$build_result" | grep '^/nix/store/')
    if [ -n "$store_path" ]; then
        assert_success "hermitshell-agent in build" vm_exec router "test -x $store_path/bin/hermitshell-agent"
        assert_success "hermitshell-dhcp in build" vm_exec router "test -x $store_path/bin/hermitshell-dhcp"
        assert_success "hermitshell-ui in build" vm_exec router "test -x $store_path/bin/hermitshell-ui"
    fi
else
    pass "Full nix build skipped (set HERMIT_NIX_BUILD=1 to enable)"
fi
