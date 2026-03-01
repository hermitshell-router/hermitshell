#!/bin/bash
# Run the full integration test suite across multiple distros.
# Each distro gets a fresh vagrant destroy/up cycle.
#
# Usage:
#   sudo -E ./sweep.sh                          # default distros, direct mode
#   sudo -E ./sweep.sh --mode install            # default distros, install mode
#   sudo -E ./sweep.sh --distro debian12 debian13 # subset of distros
cd "$(dirname "$0")"

# Ubuntu boxes boot but fail to get a DHCP lease on the vagrant-libvirt
# management network — omitted from default sweep until resolved.
ALL_DISTROS="debian12 debian13 nixos"
DISTROS=""
MODE_ARGS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --distro)
            shift
            while [ $# -gt 0 ] && [[ "$1" != --* ]]; do
                DISTROS="$DISTROS $1"
                shift
            done
            ;;
        --mode)
            MODE_ARGS="--mode $2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--mode docker|install|deb|direct|nix] [--distro debian12|debian13|ubuntu2204|ubuntu2404|nixos]"
            exit 1
            ;;
    esac
done

DISTROS="${DISTROS:-$ALL_DISTROS}"
DISTROS=$(echo $DISTROS)  # trim leading whitespace

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "=== Multi-Distro Sweep ==="
echo "Distros: $DISTROS"
echo "Mode args: ${MODE_ARGS:-direct (default)}"
echo

clean_vagrant() {
    # Destroy VMs via vagrant first (handles the clean case)
    vagrant destroy -f 2>/dev/null || true
    # Kill any lingering vagrant ruby processes that may hold machine locks
    if pgrep -f "ruby /opt/vagrant" >/dev/null 2>&1; then
        echo "Killing stale vagrant processes..."
        pkill -f "ruby /opt/vagrant" 2>/dev/null || true
        sleep 2
        pkill -9 -f "ruby /opt/vagrant" 2>/dev/null || true
        sleep 1
    fi
    # Clean up orphaned libvirt domains left behind by killed vagrant processes
    for vm in tests_wan tests_router tests_lan; do
        virsh destroy "$vm" 2>/dev/null || true
        virsh undefine "$vm" --remove-all-storage 2>/dev/null || true
    done
    # Nuke all vagrant machine state so next 'vagrant up' starts fresh
    rm -rf .vagrant
    # Close stale SSH ControlMaster sockets from prior VMs
    rm -rf /tmp/hermit-ssh-cache
    rm -f "$HOME/.ssh/sockets/vagrant@"*
}

SWEEP_START=$SECONDS
declare -A RESULTS
declare -A TIMES
any_failed=0

for distro in $DISTROS; do
    echo "============================================"
    echo "=== Distro: $distro ==="
    echo "============================================"
    distro_start=$SECONDS

    export HERMIT_DISTRO="$distro"

    echo "Destroying VMs..."
    clean_vagrant

    echo "Starting VMs (box: $distro)..."
    if [ "$distro" = "nixos" ]; then
        # NixOS: boot without provisioning, then provision via SSH to avoid
        # vagrant's SSH timeout during nixos-rebuild package downloads.
        if ! vagrant up --no-provision; then
            echo "vagrant up failed for $distro"
            RESULTS[$distro]="FAIL"
            TIMES[$distro]=$((SECONDS - distro_start))
            any_failed=1
            continue
        fi
        echo "Provisioning NixOS router (nixos-rebuild boot)..."
        vagrant ssh router -- -o ServerAliveInterval=15 "sudo bash -s" < provision/router-nixos.sh
        echo "Rebooting router for interface name changes..."
        vagrant ssh router -- "sudo reboot" || true
        echo "Waiting for reboot..."
        sleep 25
        # Wait for SSH to come back
        for i in $(seq 1 30); do
            if vagrant ssh router -- "true" 2>/dev/null; then break; fi
            sleep 5
        done
        echo "Running post-reboot provisioner..."
        vagrant ssh router -- "sudo bash -s" < provision/router-nixos-agent.sh
    else
        if ! vagrant up; then
            echo "vagrant up failed for $distro"
            RESULTS[$distro]="FAIL"
            TIMES[$distro]=$((SECONDS - distro_start))
            any_failed=1
            continue
        fi
    fi

    # NixOS uses nix deploy mode unless overridden
    run_mode="$MODE_ARGS"
    if [ "$distro" = "nixos" ] && [ -z "$MODE_ARGS" ]; then
        run_mode="--mode nix"
    fi

    if ./run.sh --distro "$distro" $run_mode; then
        RESULTS[$distro]="PASS"
    else
        RESULTS[$distro]="FAIL"
        any_failed=1
    fi

    TIMES[$distro]=$((SECONDS - distro_start))
    echo
done

# Final cleanup
echo "Destroying VMs..."
clean_vagrant

sweep_time=$((SECONDS - SWEEP_START))

echo
echo "=== Sweep Summary ==="
printf "%-15s %8s %s\n" "DISTRO" "TIME" "STATUS"
printf "%-15s %8s %s\n" "------" "----" "------"
for distro in $DISTROS; do
    elapsed="${TIMES[$distro]:-0}"
    status="${RESULTS[$distro]:-SKIP}"
    if [ "$status" = "PASS" ]; then
        printf "%-15s %7ss ${GREEN}%s${NC}\n" "$distro" "$elapsed" "$status"
    else
        printf "%-15s %7ss ${RED}%s${NC}\n" "$distro" "$elapsed" "$status"
    fi
done
printf "%-15s %7ss\n" "Total" "$sweep_time"

echo
if [ $any_failed -eq 0 ]; then
    echo -e "${GREEN}All distros passed${NC}"
    exit 0
else
    echo -e "${RED}One or more distros failed${NC}"
    exit 1
fi
