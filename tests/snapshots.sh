#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "=== Building and snapshotting VMs ==="

# Destroy any existing VMs
vagrant destroy -f 2>/dev/null || true

# Bring up all VMs
vagrant up

# Wait for all VMs to be running
for vm in wan router lan; do
    for i in $(seq 1 30); do
        vagrant status "$vm" --machine-readable 2>/dev/null | grep -q "state,running" && break
    done
done

# Take snapshots
for vm in wan router lan; do
    echo "Snapshotting $vm..."
    vagrant snapshot save "$vm" clean --force
done

echo "=== Snapshots complete ==="
echo "Run tests with: ./run.sh"
echo "Restore clean state with: vagrant snapshot restore <vm> clean"
