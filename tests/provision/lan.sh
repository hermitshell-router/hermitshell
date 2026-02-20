#!/bin/bash
set -e

apt-get update
apt-get install -y dnsutils wireguard-tools

# eth1 = LAN (gets IP from router via DHCP)

# Configure LAN interface to use DHCP from router
cat > /etc/network/interfaces.d/lan <<EOF
auto eth1
iface eth1 inet dhcp
EOF

ifup eth1 || true

# Override the default classless routes hook to use 'ip route replace' instead
# of 'ip route add', so the default route via the hermitshell router wins over
# the vagrant management route on eth0.
cat > /etc/dhcp/dhclient-exit-hooks.d/rfc3442-classless-routes <<'HOOK'
RUN="yes"

if [ "$RUN" = "yes" ]; then
    if [ -n "$new_rfc3442_classless_static_routes" ]; then
        if [ "$reason" = "BOUND" ] || [ "$reason" = "REBOOT" ] || [ "$reason" = "RENEW" ] || [ "$reason" = "REBIND" ]; then
            set -- $new_rfc3442_classless_static_routes

            while [ $# -gt 0 ]; do
                net_length=$1
                via_arg=''

                case $net_length in
                    32|31|30|29|28|27|26|25)
                        if [ $# -lt 9 ]; then return 1; fi
                        net_address="${2}.${3}.${4}.${5}"
                        gateway="${6}.${7}.${8}.${9}"
                        shift 9
                        ;;
                    24|23|22|21|20|19|18|17)
                        if [ $# -lt 8 ]; then return 1; fi
                        net_address="${2}.${3}.${4}.0"
                        gateway="${5}.${6}.${7}.${8}"
                        shift 8
                        ;;
                    16|15|14|13|12|11|10|9)
                        if [ $# -lt 7 ]; then return 1; fi
                        net_address="${2}.${3}.0.0"
                        gateway="${4}.${5}.${6}.${7}"
                        shift 7
                        ;;
                    8|7|6|5|4|3|2|1)
                        if [ $# -lt 6 ]; then return 1; fi
                        net_address="${2}.0.0.0"
                        gateway="${3}.${4}.${5}.${6}"
                        shift 6
                        ;;
                    0)
                        if [ $# -lt 5 ]; then return 1; fi
                        net_address="0.0.0.0"
                        gateway="${2}.${3}.${4}.${5}"
                        shift 5
                        ;;
                    *)  return 1 ;;
                esac

                if [ "${gateway}" != '0.0.0.0' ]; then
                    via_arg="via ${gateway}"
                fi

                ip -4 route replace "${net_address}/${net_length}" \
                    ${via_arg} dev "${interface}" >/dev/null 2>&1
            done
        fi
    fi
fi
HOOK

# Apply the fix now for the current session
ip route del default via 192.168.121.1 dev eth0 2>/dev/null || true
gateway=$(grep -oP 'option routers \K[0-9.]+' /var/lib/dhcp/dhclient.eth1.leases 2>/dev/null | tail -1)
if [ -n "$gateway" ]; then
    ip route replace default via "$gateway" dev eth1 2>/dev/null || true
fi
