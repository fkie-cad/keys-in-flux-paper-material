#!/bin/bash
# Simple manual SSH rekey test
#
# This script demonstrates client-side rekey using OpenSSH escape sequence ~R
# Run this from the host machine to manually verify rekey works

set -e

SERVER=${1:-openssh_server}
PORT=22
KEYLOG="data/keylogs/manual_rekey_${SERVER}.log"

echo "======================================================================"
echo "  Manual SSH Rekey Test"
echo "======================================================================"
echo ""
echo "Server: $SERVER:$PORT"
echo "Keylog: $KEYLOG"
echo ""
echo "This test will:"
echo "  1. Connect to SSH server"
echo "  2. Run initial command (keys extracted automatically)"
echo "  3. Wait 3 seconds"
echo "  4. Send rekey request (~R escape)"
echo "  5. Wait 3 seconds"
echo "  6. Run another command"
echo "  7. Disconnect"
echo ""
echo "======================================================================

"
echo ""

# Clean old keylog
rm -f "$KEYLOG"

# Export keylog path for the custom SSH
export SSHKEYLOGFILE="$PWD/$KEYLOG"

# Run docker exec to get into groundtruth container and use its SSH
echo "[TEST] Starting interactive SSH connection..."
echo "[TEST] After connecting, manually:"
echo "        1. Press Enter"
echo "        2. Type: ~R   (to trigger rekey)"
echo "        3. Wait for confirmation"
echo "        4. Press Enter"
echo "        5. Type: ~.   (to disconnect)"
echo ""

docker compose run --rm \
  --entrypoint "" \
  -e SSHKEYLOGFILE="$KEYLOG" \
  -it \
  openssh_groundtruth \
  bash -c "
    export SSHKEYLOGFILE='$KEYLOG'
    echo 'Connecting to $SERVER...'
    echo 'After prompt appears:'
    echo '  1. Press Enter'
    echo '  2. Type: ~R    (trigger rekey)'
    echo '  3. Wait 2 seconds'
    echo '  4. Press Enter'
    echo '  5. Type: ~.    (disconnect)'
    echo ''
    sshpass -p password /usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null testuser@$SERVER -p $PORT
  "

echo ""
echo "======================================================================"
echo "  Test Complete - Analyzing Keylog"
echo "======================================================================"
echo ""

if [ -f "$KEYLOG" ]; then
    echo "Keylog file found: $KEYLOG"
    echo ""

    # Count NEWKEYS entries
    NEWKEYS_COUNT=$(grep -c "NEWKEYS" "$KEYLOG" 2>/dev/null || echo "0")
    echo "NEWKEYS entries found: $NEWKEYS_COUNT"
    echo ""

    if [ "$NEWKEYS_COUNT" -eq "4" ]; then
        echo "✅ SUCCESS: Rekey worked! (4 NEWKEYS = 2 initial + 2 rekey)"
    elif [ "$NEWKEYS_COUNT" -eq "2" ]; then
        echo "⚠️  WARNING: Only initial keys found (rekey may not have been triggered)"
    else
        echo "❌ ERROR: Unexpected number of NEWKEYS entries"
    fi

    echo ""
    echo "--- Keylog Contents ---"
    cat "$KEYLOG"
    echo ""

    echo "--- Parsed Keys ---"
    python3 parse_keylog.py "$KEYLOG" --summary
else
    echo "❌ ERROR: Keylog file not found: $KEYLOG"
    exit 1
fi
