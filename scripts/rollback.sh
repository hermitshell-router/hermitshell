#!/bin/bash
# HermitShell update rollback — runs as ExecStopPost when agent exits.
# Only acts if an update was in progress and the agent crashed.

MARKER="/run/hermitshell/update-pending"
ROLLBACK_DIR="/opt/hermitshell/rollback"
INSTALL_DIR="/opt/hermitshell"
BINARIES="hermitshell-agent hermitshell-dhcp hermitshell blocky"

# If no marker, this was a normal stop — do nothing.
[ -f "$MARKER" ] || exit 0

# If the service result is "success", the agent exited cleanly for a restart.
if [ "${SERVICE_RESULT:-}" = "success" ]; then
    exit 0
fi

# Marker exists and agent crashed — roll back.
if [ -d "$ROLLBACK_DIR" ]; then
    logger -t hermitshell "rolling back update: restoring previous binaries"
    for bin in $BINARIES; do
        if [ -f "$ROLLBACK_DIR/$bin" ]; then
            cp "$ROLLBACK_DIR/$bin" "$INSTALL_DIR/$bin"
            chmod +x "$INSTALL_DIR/$bin"
        fi
    done
    rm -f "$MARKER"
    logger -t hermitshell "rollback complete"
else
    logger -t hermitshell "rollback dir missing, cannot restore"
    rm -f "$MARKER"
fi
