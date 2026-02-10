#!/bin/bash
source "$(dirname "$0")/../lib/helpers.sh"

# Wait for LAN VM to appear in device list
sleep 5

devices=$(vm_exec router 'echo "{\"method\":\"list_devices\"}" | socat - UNIX-CONNECT:/run/hermitshell/agent.sock')
assert_match "$devices" '"ok":true' "list_devices succeeds"
assert_match "$devices" '10\.0\.0\.' "LAN device appears in list"
