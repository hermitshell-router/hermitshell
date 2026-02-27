#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

require_agent
require_lan_ip
require_nftables

echo "=== Test 43: UPnP/NAT-PMP port mapping ==="

# Get LAN device info
LAN_MAC=$(vm_exec lan 'cat /sys/class/net/eth1/address')
device_ip=$(vm_exec lan "ip -4 addr show eth1 | grep inet | awk '{print \$2}' | cut -d/ -f1")

# Ensure LAN device is in trusted group
vm_exec router "echo '{\"method\":\"set_device_group\",\"mac\":\"$LAN_MAC\",\"group\":\"trusted\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

# Enable UPnP
vm_exec router "echo '{\"method\":\"set_upnp_config\",\"value\":\"true\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

# Restart agent to pick up UPnP enabled state
vm_sudo router "pkill -f hermitshell-agent"
_check_ready() {
    vm_exec router 'echo "{\"method\":\"get_status\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock' 2>/dev/null | grep -q '"ok":true'
}
wait_for 15 "agent restart" _check_ready
vm_sudo router "chmod 666 /run/hermitshell/agent.sock"

# Verify nftables has UPnP input rules
rules=$(vm_nft "list chain inet filter input")
assert_contains "$rules" "udp dport 1900" "nftables allows SSDP port 1900"
assert_contains "$rules" "tcp dport 5000" "nftables allows UPnP HTTP port 5000"
assert_contains "$rules" "udp dport 5351" "nftables allows NAT-PMP port 5351"

# ---- Task 10: SSDP and SOAP tests ----

# SSDP M-SEARCH from LAN VM (trusted device)
SSDP_RESULT=$(vm_exec lan "echo -e 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n' | socat -T2 - UDP4-DATAGRAM:239.255.255.250:1900" || echo "")
assert_contains "$SSDP_RESULT" "InternetGatewayDevice" "SSDP response contains IGD"
assert_contains "$SSDP_RESULT" "LOCATION" "SSDP response has LOCATION header"

# Fetch device description XML
DESC=$(vm_exec lan "curl -s http://10.0.0.1:5000/rootDesc.xml" || echo "")
assert_contains "$DESC" "InternetGatewayDevice" "Device description XML is valid"
assert_contains "$DESC" "WANIPConnection" "Description includes WANIPConnection service"

# SOAP: GetExternalIPAddress
SOAP_BODY='<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:GetExternalIPAddress></s:Body></s:Envelope>'
EXT_IP=$(vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"' -d '$SOAP_BODY' http://10.0.0.1:5000/ctl/WANIPConn" || echo "")
assert_contains "$EXT_IP" "NewExternalIPAddress" "GetExternalIPAddress returns external IP"

# SOAP: AddPortMapping
ADD_BODY="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>27015</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>27015</NewInternalPort><NewInternalClient>${device_ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Game Server</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
ADD_RESULT=$(vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"' -d '$ADD_BODY' http://10.0.0.1:5000/ctl/WANIPConn" || echo "")
if echo "$ADD_RESULT" | grep -q "UPnPError"; then
    echo -e "${RED}FAIL${NC}: AddPortMapping returned error: $ADD_RESULT"
else
    echo -e "${GREEN}PASS${NC}: AddPortMapping succeeded"
fi

# Verify nftables DNAT rule
nat_rules=$(vm_nft "list chain ip nat prerouting" || echo "")
assert_contains "$nat_rules" "udp dport 27015 dnat to ${device_ip}:27015" "UPnP DNAT rule in nftables"

# Verify mapping appears in port forward list with source=upnp
FORWARDS=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_contains "$FORWARDS" '"source":"upnp"' "Port forward has source=upnp"
assert_contains "$FORWARDS" '"external_port_start":27015' "Port forward has correct external port"

# SOAP: GetGenericPortMappingEntry (index 0 should find it)
ENUM_BODY='<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewPortMappingIndex>0</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>'
ENUM_RESULT=$(vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry\"' -d '$ENUM_BODY' http://10.0.0.1:5000/ctl/WANIPConn" || echo "")
assert_contains "$ENUM_RESULT" "27015" "GetGenericPortMappingEntry returns port 27015"

# Secure mode: try adding mapping for a different internal IP — should fail
SECURE_BODY="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>27016</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>27016</NewInternalPort><NewInternalClient>10.0.1.99</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Spoofed</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
SECURE_RESULT=$(vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"' -d '$SECURE_BODY' http://10.0.0.1:5000/ctl/WANIPConn" || echo "")
assert_contains "$SECURE_RESULT" "UPnPError" "Secure mode rejects mismatched internal IP"

# SOAP: DeletePortMapping
DEL_BODY='<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>27015</NewExternalPort><NewProtocol>UDP</NewProtocol></u:DeletePortMapping></s:Body></s:Envelope>'
DEL_RESULT=$(vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping\"' -d '$DEL_BODY' http://10.0.0.1:5000/ctl/WANIPConn" || echo "")
if echo "$DEL_RESULT" | grep -q "UPnPError"; then
    echo -e "${RED}FAIL${NC}: DeletePortMapping returned error"
else
    echo -e "${GREEN}PASS${NC}: DeletePortMapping succeeded"
fi

# Verify nftables rule removed
nat_after=$(vm_nft "list chain ip nat prerouting" || echo "")
if echo "$nat_after" | grep -q "dport 27015"; then
    echo -e "${RED}FAIL${NC}: UPnP DNAT rule still present after delete"
else
    echo -e "${GREEN}PASS${NC}: UPnP DNAT rule removed"
fi

# ---- Task 11: NAT-PMP tests ----

# NAT-PMP: Get external address (opcode 0)
NATPMP_RESP=$(vm_exec lan "python3 -c \"
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(struct.pack('!BB', 0, 0), ('10.0.0.1', 5351))
data, _ = s.recvfrom(16)
ver, op, result, epoch = struct.unpack('!BBHI', data[:8]) if len(data) >= 8 else (0,0,99,0)
ip_bytes = data[8:12] if len(data) >= 12 else b'\\x00\\x00\\x00\\x00'
import ipaddress
print(f'result={result} ip={ipaddress.IPv4Address(ip_bytes)}')
\"" || echo "result=99")
assert_contains "$NATPMP_RESP" "result=0" "NAT-PMP external address returns success"

# NAT-PMP: Request UDP port mapping (opcode 1)
NATPMP_MAP=$(vm_exec lan "python3 -c \"
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
# version=0, opcode=1(UDP), reserved=0, internal_port=25565, external_port=25565, lifetime=3600
req = struct.pack('!BBH HH I', 0, 1, 0, 25565, 25565, 3600)
s.sendto(req, ('10.0.0.1', 5351))
data, _ = s.recvfrom(16)
ver, op, result, epoch, iport, eport, lifetime = struct.unpack('!BBHI HH I', data)
print(f'result={result} iport={iport} eport={eport} lifetime={lifetime}')
\"" || echo "result=99")
assert_contains "$NATPMP_MAP" "result=0" "NAT-PMP mapping returns success"
assert_contains "$NATPMP_MAP" "eport=25565" "NAT-PMP mapped correct external port"

# Verify nftables rule
nat_rules2=$(vm_nft "list chain ip nat prerouting" || echo "")
assert_contains "$nat_rules2" "udp dport 25565 dnat to ${device_ip}:25565" "NAT-PMP DNAT rule in nftables"

# NAT-PMP: Delete mapping (lifetime=0)
vm_exec lan "python3 -c \"
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
req = struct.pack('!BBH HH I', 0, 1, 0, 25565, 25565, 0)
s.sendto(req, ('10.0.0.1', 5351))
data, _ = s.recvfrom(16)
\"" >/dev/null 2>&1

# Verify nftables rule removed
nat_after2=$(vm_nft "list chain ip nat prerouting" || echo "")
if echo "$nat_after2" | grep -q "dport 25565"; then
    echo -e "${RED}FAIL${NC}: NAT-PMP DNAT rule still present after delete"
else
    echo -e "${GREEN}PASS${NC}: NAT-PMP DNAT rule removed after delete"
fi

# ---- Task 12: Disable clears mappings ----

# Add a mapping via SOAP, then disable UPnP — verify it's cleared
ADD_BODY2="<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>30000</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>30000</NewInternalPort><NewInternalClient>${device_ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>Temp</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
vm_exec lan "curl -s -X POST -H 'Content-Type: text/xml' -H 'SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"' -d '$ADD_BODY2' http://10.0.0.1:5000/ctl/WANIPConn" >/dev/null

# Disable UPnP
vm_exec router "echo '{\"method\":\"set_upnp_config\",\"value\":\"false\"}' | socat - UNIX-CONNECT:/run/hermitshell/agent.sock" >/dev/null

# Verify automatic mappings are cleared
FORWARDS2=$(vm_exec router 'echo "{\"method\":\"list_port_forwards\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
if echo "$FORWARDS2" | grep -q '"source":"upnp"'; then
    echo -e "${RED}FAIL${NC}: UPnP mappings still present after disable"
else
    echo -e "${GREEN}PASS${NC}: UPnP mappings cleared on disable"
fi

echo "=== Test 43 complete ==="
