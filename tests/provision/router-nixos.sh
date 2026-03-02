#!/usr/bin/env bash
# Provision a NixOS router VM — Phase 1: system configuration.
# Installs packages, sets kernel params for legacy interface names,
# and stages the config for next boot using nixos-rebuild boot.
#
# After this runs, the VM needs a reboot for all changes to take effect.
# Phase 2 (router-nixos-agent.sh) starts the agent after reboot.
set -e

# Write the HermitShell test configuration as a standalone NixOS module
cat > /etc/nixos/hermitshell-test.nix <<'NIX'
{ pkgs, lib, ... }:
{
  # Use legacy interface names (eth0, eth1, eth2) to match other test distros
  networking.usePredictableInterfaceNames = lib.mkForce false;
  boot.kernelParams = [ "net.ifnames=0" "biosdevname=0" ];

  # Enable flakes
  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  # System packages needed by the agent
  environment.systemPackages = with pkgs; [
    nftables
    conntrack-tools
    wireguard-tools
    iproute2
    unbound
    dig
    curl
    socat
    kmod
    git
    rsync
    python3
    openssl
    binutils    # provides 'strings' for binary inspection tests
    bind.host   # 'host' command for DNS lookups in tests
  ];

  # Kernel parameters
  boot.kernel.sysctl = {
    "net.ipv4.ip_forward" = 1;
    "net.ipv6.conf.all.forwarding" = 1;
    "net.netfilter.nf_conntrack_acct" = 1;
  };
  boot.kernelModules = [ "ifb" "8021q" ];

  # Disable NixOS firewall (HermitShell manages nftables)
  networking.firewall.enable = lib.mkForce false;
  networking.nftables.enable = lib.mkForce false;

  # Don't let systemd-networkd manage WAN/LAN interfaces — the agent handles them.
  # Also disable system-wide DHCP so it doesn't race with the agent's DHCP client.
  networking.useDHCP = lib.mkForce false;
  networking.interfaces.eth0.useDHCP = true;   # Keep management NIC on DHCP

  # Disable system unbound — agent manages its own instance
  services.unbound.enable = lib.mkForce false;

  # Create directories for the agent
  systemd.tmpfiles.rules = [
    "d /var/lib/hermitshell 0755 root root -"
    "d /var/lib/hermitshell/unbound 0755 root root -"
    "d /var/lib/hermitshell/unbound/blocklists 0755 root root -"
    "d /run/hermitshell 0755 root root -"
    "d /opt/hermitshell 0755 root root -"
  ];

  # Docker for web UI container tests
  virtualisation.docker.enable = true;
  users.users.vagrant.extraGroups = [ "docker" ];
}
NIX

# Add our module to the imports in configuration.nix (idempotent).
# The nixbox image uses a multi-line imports format:
#   imports =
#     [ # Include the results of the hardware scan.
#       ./hardware-configuration.nix
# We find the first line containing "[" inside the imports block and append after it.
if ! grep -q 'hermitshell-test.nix' /etc/nixos/configuration.nix; then
    # Match the line with "[" inside the imports block and append our module after it
    sed -i '/imports/,/];/{/\[/a\      ./hermitshell-test.nix
}' /etc/nixos/configuration.nix
fi

# Verify the import was added
if ! grep -q 'hermitshell-test.nix' /etc/nixos/configuration.nix; then
    echo "ERROR: Failed to add hermitshell-test.nix to imports"
    cat /etc/nixos/configuration.nix
    exit 1
fi

# Use nixos-rebuild boot (not switch!) to stage the config for next boot.
# 'switch' would apply changes immediately, breaking the management network
# because interface rename (net.ifnames=0) needs a reboot.
#
# Print dots during the build to keep SSH alive (Vagrant kills idle sessions).
echo "Running nixos-rebuild boot (this takes several minutes)..."
nixos-rebuild boot 2>&1 &
REBUILD_PID=$!

# Print a dot every 15 seconds to keep the SSH connection alive
while kill -0 "$REBUILD_PID" 2>/dev/null; do
    printf "."
    sleep 15
done

# Collect the exit code
wait "$REBUILD_PID"
RC=$?
echo ""
if [ "$RC" -ne 0 ]; then
    echo "nixos-rebuild boot failed with exit code $RC"
    exit $RC
fi
echo "NixOS configuration staged. Reboot required."
