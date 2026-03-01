flake:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.hermitshell;
  pkg = flake.packages.${pkgs.stdenv.hostPlatform.system}.default;
in
{
  options.services.hermitshell = {
    enable = lib.mkEnableOption "HermitShell router platform";

    wanInterface = lib.mkOption {
      type = lib.types.str;
      description = "WAN (upstream) network interface name.";
    };

    lanInterface = lib.mkOption {
      type = lib.types.str;
      description = "LAN (downstream) network interface name.";
    };

    logLevel = lib.mkOption {
      type = lib.types.str;
      default = "info";
      description = "Rust tracing log level (trace, debug, info, warn, error).";
    };
  };

  config = lib.mkIf cfg.enable {

    assertions = [
      {
        assertion = !config.networking.firewall.enable;
        message = "HermitShell manages nftables directly — set networking.firewall.enable = false";
      }
    ];

    # Disable conflicting NixOS networking
    networking.firewall.enable = lib.mkForce false;
    networking.nftables.enable = lib.mkForce false;

    # Kernel parameters required by the agent
    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
      "net.netfilter.nf_conntrack_acct" = 1;
    };

    # QoS needs the ifb kernel module
    boot.kernelModules = [ "ifb" ];

    # Web UI user
    users.users.hermitshell = {
      isSystemUser = true;
      group = "hermitshell";
      home = "/var/lib/hermitshell";
      description = "HermitShell web UI";
    };
    users.groups.hermitshell = {};

    # Data and runtime directories
    systemd.tmpfiles.rules = [
      "d /var/lib/hermitshell 0750 root hermitshell -"
      "d /var/lib/hermitshell/unbound 0755 root root -"
      "d /var/lib/hermitshell/unbound/blocklists 0755 root root -"
      "d /run/hermitshell 0755 root hermitshell -"
    ];

    # Router agent (runs as root with restricted capabilities)
    systemd.services.hermitshell-agent = {
      description = "HermitShell Router Agent";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        WAN_IFACE = cfg.wanInterface;
        LAN_IFACE = cfg.lanInterface;
        RUST_LOG = cfg.logLevel;

        # Binary paths (nix store)
        HERMITSHELL_NFT_PATH = "${pkgs.nftables}/bin/nft";
        HERMITSHELL_IP_PATH = "${pkgs.iproute2}/bin/ip";
        HERMITSHELL_WG_PATH = "${pkgs.wireguard-tools}/bin/wg";
        HERMITSHELL_TC_PATH = "${pkgs.iproute2}/bin/tc";
        HERMITSHELL_MODPROBE_PATH = "${pkgs.kmod}/bin/modprobe";
        HERMITSHELL_CONNTRACK_PATH = "${pkgs.conntrack-tools}/bin/conntrack";
        HERMITSHELL_DHCP_BIN = "${pkg}/bin/hermitshell-dhcp";

        # Disable built-in update checker (use nix flake update instead)
        HERMITSHELL_UPDATES_DISABLED = "1";
      };

      # Bare-name binaries the agent spawns (unbound, dig, curl)
      path = with pkgs; [ unbound dig curl ];

      serviceConfig = {
        ExecStart = "${pkg}/bin/hermitshell-agent";
        Restart = "on-failure";
        RestartSec = 5;

        # Hardening (matching upstream systemd unit)
        ProtectHome = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ "/var/lib/hermitshell" "/run/hermitshell" ];
        PrivateTmp = true;
        NoNewPrivileges = true;
        PrivateDevices = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" "AF_PACKET" ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictSUIDSGID = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        RestrictRealtime = true;
        ProtectProc = "invisible";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_NET_RAW" "CAP_NET_BIND_SERVICE" ];
        SystemCallFilter = [ "~@mount" "~@reboot" "~@swap" "~@debug" "~@module" "~@cpu-emulation" ];
      };
    };

    # Web UI (runs as hermitshell user)
    systemd.services.hermitshell-ui = {
      description = "HermitShell Web UI";
      after = [ "hermitshell-agent.service" ];
      bindsTo = [ "hermitshell-agent.service" ];
      partOf = [ "hermitshell-agent.service" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        LEPTOS_OUTPUT_NAME = "hermitshell";
        HERMITSHELL_RUN_DIR = "/run/hermitshell";
      };

      serviceConfig = {
        ExecStart = "${pkg}/bin/hermitshell-ui";
        User = "hermitshell";
        Group = "hermitshell";
        Restart = "on-failure";
        RestartSec = 5;
        ProtectHome = true;
        ProtectSystem = "strict";
        PrivateTmp = true;
        NoNewPrivileges = true;
      };
    };
  };
}
