#!/bin/bash
#
# Verify SSH Rekey Tool
#
# Checks if SSH rekey actually happened during a lifecycle test.
# Provides multiple verification methods.
#

set -e

RESULT_DIR="${1:-result_test/openssh_ku}"

if [ ! -d "$RESULT_DIR" ]; then
    echo "ERROR: Result directory not found: $RESULT_DIR"
    echo "Usage: $0 <result_directory>"
    exit 1
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo "========================================================================"
echo "  SSH Rekey Verification"
echo "========================================================================"
echo ""
echo "Result directory: $RESULT_DIR"
echo ""

# Method 1: Check keylog for KEX2 entries
echo -e "${CYAN}[Method 1] Checking keylog for KEX cycles${NC}"
echo "---"

KEYLOG_FILE=$(find "$RESULT_DIR" -name "*_client_keylog.log" -o -name "openssh_client_keylog.log" | head -1)

if [ -z "$KEYLOG_FILE" ]; then
    echo -e "${RED}✗ No keylog file found${NC}"
else
    echo "Keylog: $KEYLOG_FILE"
    echo ""

    KEX1_COUNT=$(grep -c "_KEX1" "$KEYLOG_FILE" 2>/dev/null || echo "0")
    KEX2_COUNT=$(grep -c "_KEX2" "$KEYLOG_FILE" 2>/dev/null || echo "0")
    KEX3_COUNT=$(grep -c "_KEX3" "$KEYLOG_FILE" 2>/dev/null || echo "0")

    echo "KEX1 entries: $KEX1_COUNT"
    echo "KEX2 entries: $KEX2_COUNT"
    echo "KEX3 entries: $KEX3_COUNT"
    echo ""

    if [ "$KEX2_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ REKEY DETECTED - KEX2 entries found${NC}"
        echo ""
        echo "Sample KEX2 entries:"
        grep "_KEX2" "$KEYLOG_FILE" | head -3
    elif [ "$KEX1_COUNT" -gt 0 ]; then
        echo -e "${RED}✗ NO REKEY - Only KEX1 entries found${NC}"
    else
        echo -e "${RED}✗ NO KEYS EXTRACTED${NC}"
    fi
fi

echo ""
echo "---"
echo ""

# Method 2: Check PCAP for multiple NEWKEYS messages
echo -e "${CYAN}[Method 2] Checking PCAP for NEWKEYS messages${NC}"
echo "---"

PCAP_FILE=$(find "$RESULT_DIR" -name "*.pcap" | head -1)

if [ -z "$PCAP_FILE" ]; then
    echo -e "${YELLOW}⚠️  No PCAP file found - skipping${NC}"
elif ! command -v tshark &> /dev/null; then
    echo -e "${YELLOW}⚠️  tshark not installed - skipping${NC}"
    echo "Install: brew install wireshark (macOS) or apt install tshark (Linux)"
else
    echo "PCAP: $PCAP_FILE"
    echo ""

    # Count SSH NEWKEYS messages (SSH message type 21)
    NEWKEYS_COUNT=$(tshark -r "$PCAP_FILE" -Y "ssh.message_code == 21" 2>/dev/null | wc -l | tr -d ' ')

    echo "NEWKEYS messages in PCAP: $NEWKEYS_COUNT"
    echo ""

    if [ "$NEWKEYS_COUNT" -ge 4 ]; then
        echo -e "${GREEN}✓ REKEY DETECTED - Multiple NEWKEYS messages (initial + rekey)${NC}"
        echo ""
        echo "NEWKEYS packet details:"
        tshark -r "$PCAP_FILE" -Y "ssh.message_code == 21" -T fields -e frame.number -e frame.time -e ssh.message_code 2>/dev/null | head -10
    elif [ "$NEWKEYS_COUNT" -eq 2 ]; then
        echo -e "${RED}✗ NO REKEY - Only 2 NEWKEYS (initial handshake)${NC}"
    else
        echo -e "${YELLOW}⚠️  Unexpected NEWKEYS count: $NEWKEYS_COUNT${NC}"
    fi
fi

echo ""
echo "---"
echo ""

# Method 3: Check for KEXINIT messages (rekey indicator)
echo -e "${CYAN}[Method 3] Checking PCAP for KEXINIT messages${NC}"
echo "---"

if [ -n "$PCAP_FILE" ] && command -v tshark &> /dev/null; then
    # Count SSH KEXINIT messages (SSH message type 20)
    KEXINIT_COUNT=$(tshark -r "$PCAP_FILE" -Y "ssh.message_code == 20" 2>/dev/null | wc -l | tr -d ' ')

    echo "KEXINIT messages in PCAP: $KEXINIT_COUNT"
    echo ""

    if [ "$KEXINIT_COUNT" -ge 4 ]; then
        echo -e "${GREEN}✓ REKEY DETECTED - Multiple KEXINIT messages${NC}"
        echo ""
        echo "KEXINIT packet timestamps:"
        tshark -r "$PCAP_FILE" -Y "ssh.message_code == 20" -T fields -e frame.number -e frame.time 2>/dev/null | head -10
    elif [ "$KEXINIT_COUNT" -eq 2 ]; then
        echo -e "${RED}✗ NO REKEY - Only 2 KEXINIT (initial handshake)${NC}"
    else
        echo -e "${YELLOW}⚠️  Unexpected KEXINIT count: $KEXINIT_COUNT${NC}"
    fi
fi

echo ""
echo "---"
echo ""

# Method 4: Check dumps for multiple KEX event logs
echo -e "${CYAN}[Method 4] Checking event logs for KEX transitions${NC}"
echo "---"

EVENT_LOG=$(find "$RESULT_DIR" -name "ssh_events.jsonl" | head -1)

if [ -z "$EVENT_LOG" ]; then
    echo -e "${YELLOW}⚠️  No event log found - skipping${NC}"
else
    echo "Event log: $EVENT_LOG"
    echo ""

    KEX_COMPLETE_COUNT=$(grep -c "KEX_COMPLETE" "$EVENT_LOG" 2>/dev/null || echo "0")
    REKEY_START_COUNT=$(grep -c "REKEY_START" "$EVENT_LOG" 2>/dev/null || echo "0")
    REKEY_COMPLETE_COUNT=$(grep -c "REKEY_COMPLETE" "$EVENT_LOG" 2>/dev/null || echo "0")

    echo "KEX_COMPLETE events: $KEX_COMPLETE_COUNT"
    echo "REKEY_START events: $REKEY_START_COUNT"
    echo "REKEY_COMPLETE events: $REKEY_COMPLETE_COUNT"
    echo ""

    if [ "$REKEY_START_COUNT" -gt 0 ] || [ "$REKEY_COMPLETE_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✓ REKEY DETECTED - REKEY state transitions found${NC}"
    elif [ "$KEX_COMPLETE_COUNT" -gt 1 ]; then
        echo -e "${GREEN}✓ POSSIBLE REKEY - Multiple KEX_COMPLETE events${NC}"
    else
        echo -e "${RED}✗ NO REKEY - No rekey state transitions${NC}"
    fi
fi

echo ""
echo "---"
echo ""

# Method 5: Manual inspection hints
echo -e "${CYAN}[Method 5] Manual verification commands${NC}"
echo "---"
echo ""
echo "Run these commands to verify rekey manually:"
echo ""
echo "# 1. View all keylog entries by KEX cycle:"
echo "   grep '_KEX' $KEYLOG_FILE | sed 's/.*_KEX/KEX/' | sort | uniq -c"
echo ""
echo "# 2. Search for 'rekey' in keylog (case-insensitive):"
echo "   grep -i 'rekey\|kex2' $KEYLOG_FILE"
echo ""

if [ -n "$PCAP_FILE" ] && command -v tshark &> /dev/null; then
    echo "# 3. Show all SSH message types in PCAP:"
    echo "   tshark -r $PCAP_FILE -Y ssh -T fields -e frame.time -e ssh.message_code | head -20"
    echo ""
    echo "# 4. Filter for KEX-related messages (20=KEXINIT, 21=NEWKEYS, 30-34=KEXDH):"
    echo "   tshark -r $PCAP_FILE -Y 'ssh.message_code >= 20 && ssh.message_code <= 34'"
    echo ""
fi

echo "# 5. Check LLDB debug output (if you ran test interactively):"
echo "   Look for '[OPENSSH_DERIVE_EXIT] KEX2' in terminal output"
echo ""

echo "========================================================================"
echo "  SUMMARY"
echo "========================================================================"
echo ""

# Overall verdict
if [ "$KEX2_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓✓✓ REKEY CONFIRMED - KEX2 keys found in keylog${NC}"
    echo ""
    echo "Expected behavior for successful rekey:"
    echo "  - KEX1 entries: 6-7 (initial handshake)"
    echo "  - KEX2 entries: 6-7 (after rekey)"
    echo "  - NEWKEYS in PCAP: 4 (2 initial + 2 rekey)"
    echo ""
elif [ "$KEX1_COUNT" -gt 0 ]; then
    echo -e "${RED}✗✗✗ NO REKEY DETECTED - Only KEX1 entries${NC}"
    echo ""
    echo "Possible reasons:"
    echo "  1. Expect script didn't send ~R escape sequence"
    echo "  2. SSH session too short for rekey to complete"
    echo "  3. SSH server rejected rekey request"
    echo "  4. LLDB didn't capture the second KEX cycle"
    echo ""
    echo "Solutions:"
    echo "  - Check test script's SSH_CMD for --with-rekey flag"
    echo "  - Verify openssh_client_rekey.exp has ~R logic"
    echo "  - Run test manually and watch for 'Rekey request' in output"
    echo "  - Increase sleep time after ~R in Expect script"
    echo ""
else
    echo -e "${RED}✗✗✗ NO KEYS EXTRACTED - Test may have failed${NC}"
fi

echo ""
