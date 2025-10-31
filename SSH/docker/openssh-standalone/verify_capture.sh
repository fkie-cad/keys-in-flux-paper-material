#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# SSH Key Export Verification Script
#
# This script verifies that SSH keys were exported correctly and that
# packet captures are available for decryption validation.
#
# Usage:
#   ./verify_capture.sh [data_dir]
#
# Example:
#   ./verify_capture.sh ./data
#   ./verify_capture.sh  (uses ./data by default)
##############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${1:-${SCRIPT_DIR}/data}"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "SSH Key Export Verification"
echo "=========================================="
echo ""

# Check if data directory exists
if [ ! -d "$DATA_DIR" ]; then
    echo -e "${RED}✗ Data directory not found: $DATA_DIR${NC}"
    echo "  Run the container first to generate data"
    exit 1
fi

echo -e "${GREEN}✓ Data directory found: $DATA_DIR${NC}"
echo ""

##############################################################################
# Check Keylog File
##############################################################################
echo "[1] Checking keylog file..."
KEYLOG_FILE="$DATA_DIR/keylogs/ssh_keylog.log"

if [ ! -f "$KEYLOG_FILE" ]; then
    echo -e "  ${RED}✗ Keylog file not found: $KEYLOG_FILE${NC}"
    echo "  Keys may not have been exported yet"
    exit 1
fi

echo -e "  ${GREEN}✓ Keylog file found${NC}"

# Count entries
KEYLOG_LINES=$(wc -l < "$KEYLOG_FILE" || echo "0")
if [ "$KEYLOG_LINES" -eq 0 ]; then
    echo -e "  ${YELLOW}⚠ Keylog file is empty${NC}"
    echo "  No keys have been exported yet"
    echo "  Run a client connection to generate keys"
    exit 1
fi

echo "  Found $KEYLOG_LINES keylog entries"

# Parse keylog entries
COOKIE_COUNT=$(grep -c "COOKIE" "$KEYLOG_FILE" || echo "0")
NEWKEYS_IN_COUNT=$(grep -c "NEWKEYS MODE IN" "$KEYLOG_FILE" || echo "0")
NEWKEYS_OUT_COUNT=$(grep -c "NEWKEYS MODE OUT" "$KEYLOG_FILE" || echo "0")
SHARED_SECRET_COUNT=$(grep -c "SHARED_SECRET" "$KEYLOG_FILE" || echo "0")

echo "  Breakdown:"
echo "    - KEX COOKIE entries: $COOKIE_COUNT"
echo "    - NEWKEYS (IN) entries: $NEWKEYS_IN_COUNT"
echo "    - NEWKEYS (OUT) entries: $NEWKEYS_OUT_COUNT"
echo "    - SHARED_SECRET entries: $SHARED_SECRET_COUNT"

# Show sample entry
echo ""
echo "  Sample keylog entry:"
echo "  $(head -1 "$KEYLOG_FILE" | cut -c 1-100)..."
echo ""

##############################################################################
# Check Capture Files
##############################################################################
echo "[2] Checking packet captures..."
CAPTURE_DIR="$DATA_DIR/captures"

if [ ! -d "$CAPTURE_DIR" ]; then
    echo -e "  ${YELLOW}⚠ Capture directory not found: $CAPTURE_DIR${NC}"
    echo "  Packet capture may be disabled (CAPTURE_TRAFFIC=false)"
    exit 0
fi

echo -e "  ${GREEN}✓ Capture directory found${NC}"

# Find all pcap files
PCAP_FILES=$(find "$CAPTURE_DIR" -name "*.pcap" -type f 2>/dev/null || echo "")

if [ -z "$PCAP_FILES" ]; then
    echo -e "  ${YELLOW}⚠ No pcap files found${NC}"
    echo "  Packet capture may be disabled or no traffic captured yet"
    exit 0
fi

PCAP_COUNT=$(echo "$PCAP_FILES" | wc -l)
echo "  Found $PCAP_COUNT pcap file(s)"
echo ""

# Analyze each pcap file
for pcap in $PCAP_FILES; do
    echo "  Analyzing: $(basename "$pcap")"

    # Check if file has content
    SIZE=$(du -h "$pcap" | cut -f1)
    echo "    Size: $SIZE"

    # Count packets (requires tshark or tcpdump)
    if command -v tcpdump >/dev/null 2>&1; then
        PACKET_COUNT=$(tcpdump -r "$pcap" 2>/dev/null | wc -l || echo "0")
        echo "    Packets: $PACKET_COUNT"

        # Show first few packets
        if [ "$PACKET_COUNT" -gt 0 ]; then
            echo "    First packets:"
            tcpdump -r "$pcap" -n -c 3 2>/dev/null | sed 's/^/      /' || true
        fi
    elif command -v tshark >/dev/null 2>&1; then
        PACKET_COUNT=$(tshark -r "$pcap" 2>/dev/null | wc -l || echo "0")
        echo "    Packets: $PACKET_COUNT"
    else
        echo "    (Install tcpdump or tshark to see packet details)"
    fi

    echo ""
done

##############################################################################
# Verification Summary
##############################################################################
echo "=========================================="
echo "Verification Summary"
echo "=========================================="
echo ""

# Calculate if we have matching data
if [ "$KEYLOG_LINES" -gt 0 ] && [ -n "$PCAP_FILES" ]; then
    echo -e "${GREEN}✓ Key Export Status: SUCCESS${NC}"
    echo "  - Keylog entries: $KEYLOG_LINES"
    echo "  - Packet captures: $PCAP_COUNT"
    echo ""
    echo -e "${GREEN}✓ Ready for decryption validation${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Use the decryption tools to validate:"
    echo "     cd ../../openSSH/research_setup/decryption"
    echo "     python3 read_llbd_keylog.py $KEYLOG_FILE /tmp/keys.json"
    echo "     python3 decrypt_ssh_pcap.py --pcap <pcap_file> --keys /tmp/keys.json --out /tmp/decrypted.pcap"
    echo ""
    echo "  2. Or view keys with ssh-admin:"
    echo "     ssh-admin keylog --count 10"
    echo ""
elif [ "$KEYLOG_LINES" -gt 0 ]; then
    echo -e "${YELLOW}⚠ Partial Success${NC}"
    echo "  - Keys exported: YES"
    echo "  - Packet captures: NO"
    echo ""
    echo "  Enable packet capture with CAPTURE_TRAFFIC=true"
elif [ -n "$PCAP_FILES" ]; then
    echo -e "${YELLOW}⚠ Partial Success${NC}"
    echo "  - Keys exported: NO"
    echo "  - Packet captures: YES"
    echo ""
    echo "  Wait for SSH connections to generate key exports"
else
    echo -e "${RED}✗ Verification Failed${NC}"
    echo "  No keys or captures found"
    echo ""
    echo "  Run an SSH session to generate data:"
    echo "    ssh -p 2222 testuser@localhost"
fi

echo ""

##############################################################################
# File Listing
##############################################################################
echo "=========================================="
echo "File Listing"
echo "=========================================="
echo ""

echo "Keylogs:"
ls -lh "$DATA_DIR/keylogs/" 2>/dev/null | tail -n +2 || echo "  (none)"
echo ""

echo "Captures:"
ls -lh "$CAPTURE_DIR/" 2>/dev/null | tail -n +2 || echo "  (none)"
echo ""

##############################################################################
# Quick Decryption Test
##############################################################################
if [ "$KEYLOG_LINES" -gt 0 ] && [ -n "$PCAP_FILES" ]; then
    echo "=========================================="
    echo "Quick Validation Test"
    echo "=========================================="
    echo ""

    # Check if we have the decryption tools
    DECRYPT_DIR="$SCRIPT_DIR/../../openSSH/research_setup/decryption"
    if [ -d "$DECRYPT_DIR" ] && [ -f "$DECRYPT_DIR/read_llbd_keylog.py" ]; then
        echo "Decryption tools found at: $DECRYPT_DIR"
        echo ""
        echo "To test decryption, run:"
        echo ""
        FIRST_PCAP=$(echo "$PCAP_FILES" | head -1)
        cat <<EOF
cd "$DECRYPT_DIR"
python3 read_llbd_keylog.py "$KEYLOG_FILE" /tmp/ssh_keys.json
python3 decrypt_ssh_pcap.py \\
    --pcap "$FIRST_PCAP" \\
    --keys /tmp/ssh_keys.json \\
    --out /tmp/ssh_decrypted.pcap
wireshark /tmp/ssh_decrypted.pcap
EOF
        echo ""
    else
        echo "Decryption tools not found in expected location"
        echo "Expected: $DECRYPT_DIR"
        echo ""
        echo "You can still use the exported keys with your own decryption tools"
    fi
fi

echo "=========================================="
echo "Verification Complete"
echo "=========================================="
