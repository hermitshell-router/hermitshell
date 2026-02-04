#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "=== Building and snapshotting VMs ==="

# Destroy any existing VMs
vagrant destroy -f 2>/dev/null || true

# Bring up all VMs
vagrant up

# Wait for provisioning to settle
sleep 5

# Take snapshots
for vm in wan router lan; do
    echo "Snapshotting $vm..."
    vagrant snapshot save "$vm" clean --force
done

echo "=== Snapshots complete ==="
echo "Run tests with: ./run.sh"
echo "Restore clean state with: vagrant snapshot restore <vm> clean"
