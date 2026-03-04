# Troubleshooting

## Web UI won't load

**Symptom:** Browser shows "connection refused" or times out at `https://<IP>`.

1. Check that both services are running:
   ```bash
   sudo systemctl status hermitshell-agent hermitshell-ui
   ```
2. If the agent is running but the UI isn't, the UI may not be able to reach the agent socket. Check its logs:
   ```bash
   sudo journalctl -u hermitshell-ui -n 30
   ```
3. If neither is running, check that your interface names are correct in `/etc/default/hermitshell` (APT/deb install) or in the systemd unit environment (install script). The agent won't start if the WAN or LAN interface doesn't exist:
   ```bash
   ip link show   # List available interfaces
   ```
4. For Docker installs, verify the container is running and check its logs:
   ```bash
   docker ps
   docker logs hermitshell
   ```

## Self-signed certificate warning

This is expected on first visit. The agent generates a self-signed TLS certificate at startup. You can:

- Accept the warning and proceed (fine for a LAN-only router)
- Switch to a real certificate in Settings > TLS (options: custom cert, Tailscale, or ACME DNS-01 via Cloudflare)

## Forgot admin password

There is no password reset through the web UI. To reset:

1. Stop the agent: `sudo systemctl stop hermitshell-agent hermitshell-ui`
2. Clear the password from the database:
   ```bash
   sudo sqlite3 /var/lib/hermitshell/hermitshell.db \
     "DELETE FROM config WHERE key = 'admin_password_hash';"
   ```
3. Restart: `sudo systemctl start hermitshell-agent hermitshell-ui`
4. The setup wizard will prompt you to set a new password.

## Devices not getting IP addresses

1. Verify the DHCP server is running. It's a child process of the agent — check the agent logs:
   ```bash
   sudo journalctl -u hermitshell-agent | grep -i dhcp
   ```
2. Check that the LAN interface is up and has the expected IP (default `10.0.0.1`):
   ```bash
   ip addr show <lan-iface>
   ```
3. Check that no other DHCP server is running on the same interface:
   ```bash
   sudo ss -ulnp | grep :67
   ```
4. If the LAN interface name is wrong, the DHCP server will bind to the wrong interface. Verify the name matches what's configured.

## DNS not resolving / ad blocking not working

HermitShell runs Unbound as its DNS resolver on port 5354, with nftables redirecting DNS traffic.

1. Test DNS from the router itself:
   ```bash
   dig @127.0.0.1 -p 5354 google.com
   ```
2. If that fails, Unbound may not have started. Check the logs:
   ```bash
   sudo journalctl -u hermitshell-agent | grep -i unbound
   ```
3. If DNS works but ad blocking doesn't, verify blocklists are enabled in Settings > DNS and that the blocklist files exist:
   ```bash
   ls -la /var/lib/hermitshell/unbound/blocklists/
   ```

## WiFi AP not connecting (UniFi or TP-Link EAP)

1. Check the WiFi provider status on the **WiFi** page. The provider will show "online" or "error" with details.
2. Common causes:
   - **Wrong credentials** — re-enter the controller/AP password
   - **Controller unreachable** — verify the controller URL is accessible from the router: `curl -k https://<controller-ip>:8443`
   - **Self-signed controller cert** — on first connection, HermitShell uses TOFU (trust on first use) to pin the certificate. If the controller's cert changed, delete and re-add the provider.
3. For UniFi, ensure you're using the correct controller type:
   - **UniFi OS** (UDM, UDR, Cloud Key Gen2+) — uses `/api/auth/login`
   - **Legacy controller** (software install, Cloud Key Gen1) — uses `/api/login`
   - HermitShell auto-detects which type during connection.

## WireGuard peers can't connect

1. Check that the WireGuard interface is up:
   ```bash
   sudo wg show
   ```
2. Verify the listen port is open on the WAN. By default it's 51820. Check nftables:
   ```bash
   sudo nft list chain inet filter input | grep 51820
   ```
3. If peers connect but can't reach the LAN, check that IP forwarding is enabled:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward   # Should be 1
   ```

## Docker container won't start

The all-in-one container needs `--privileged` and `--network host` because it manages nftables, WireGuard, and DHCP directly on the host.

Required volume mounts:
- `/var/lib/hermitshell:/var/lib/hermitshell` — database and config (must persist)
- `/run/hermitshell:/run/hermitshell` — agent socket (directory mount, not file mount)

A missing volume mount is the most common Docker issue. Verify:
```bash
docker inspect hermitshell | grep -A 5 Mounts
```

## Upgrade failed or agent won't start after update

HermitShell has automatic rollback — if the agent crashes after an update, the previous binaries are restored from `/opt/hermitshell/rollback/`.

If automatic rollback didn't trigger:
1. Check what happened:
   ```bash
   sudo journalctl -u hermitshell-agent -n 50
   ```
2. Manually restore from rollback:
   ```bash
   sudo systemctl stop hermitshell-agent hermitshell-ui
   sudo cp /opt/hermitshell/rollback/* /opt/hermitshell/
   sudo systemctl start hermitshell-agent hermitshell-ui
   ```
3. For APT installs, downgrade with:
   ```bash
   sudo apt install hermitshell=<previous-version>
   ```

## Setup wizard locked — can't change interfaces

Once the admin password is set, the setup wizard locks interface selection. This prevents accidental reconfiguration of a running router.

If you need to change interfaces after initial setup, edit the environment directly:

- **APT/deb:** Edit `/etc/default/hermitshell`, then `sudo systemctl restart hermitshell-agent`
- **Install script:** Edit the `Environment=WAN_IFACE=` and `Environment=LAN_IFACE=` lines in `/etc/systemd/system/hermitshell-agent.service`, then `sudo systemctl daemon-reload && sudo systemctl restart hermitshell-agent`
- **Docker:** Recreate the container with new `-e WAN_IFACE=` and `-e LAN_IFACE=` values

## Diagnostic commands

```bash
# Service status
sudo systemctl status hermitshell-agent hermitshell-ui

# Agent logs (last 50 lines)
sudo journalctl -u hermitshell-agent -n 50 --no-pager

# Web UI logs
sudo journalctl -u hermitshell-ui -n 50 --no-pager

# Test agent socket
curl -s --unix-socket /run/hermitshell/agent.sock http://localhost/status

# Network interfaces and IPs
ip addr show

# Firewall rules
sudo nft list tables

# DNS test
dig @10.0.0.1 google.com

# WireGuard status
sudo wg show

# Disk space (database lives here)
df -h /var/lib/hermitshell
```
