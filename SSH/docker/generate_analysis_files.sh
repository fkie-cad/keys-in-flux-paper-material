#!/bin/bash
#
# generate_analysis_files.sh - Generate analysis files from OpenSSH groundtruth keylogs
#
# This script creates both Python decryptor and Wireshark decryption files:
#   1. keys.json - For ssh_decryptor.py (uses derived encryption keys)
#   2. ssh_wireshark.keylog - For Wireshark GUI (uses shared secret K)
#
# Usage:
#   ./generate_analysis_files.sh <keylog_file> [pcap_file]
#
# Examples:
#   # Basic usage (cookie from keylog)
#   ./generate_analysis_files.sh data/keylogs/groundtruth.log
#
#   # With PCAP for cookie extraction
#   ./generate_analysis_files.sh data/keylogs/groundtruth.log data/captures/server_*.pcap
#

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Usage
usage() {
    echo "Usage: $0 <keylog_file> [pcap_file]"
    echo ""
    echo "Generate both Python and Wireshark decryption files from OpenSSH keylog."
    echo ""
    echo "Arguments:"
    echo "  keylog_file   OpenSSH groundtruth keylog (required)"
    echo "  pcap_file     PCAP file for cookie extraction (optional)"
    echo ""
    echo "Output files (in analysis/<basename>/):"
    echo "  keys.json              - For Python decryptor (derived encryption keys)"
    echo "  ssh_wireshark.keylog   - For Wireshark (shared secret K)"
    echo ""
    echo "Examples:"
    echo "  $0 data/keylogs/groundtruth.log"
    echo "  $0 data/keylogs/groundtruth.log data/captures/server_*.pcap"
    exit 1
}

# Check arguments
if [ $# -lt 1 ]; then
    usage
fi

KEYLOG_FILE="$1"
PCAP_FILE="${2:-}"

# Validate keylog file
if [ ! -f "$KEYLOG_FILE" ]; then
    echo -e "${RED}ERROR: Keylog file not found: $KEYLOG_FILE${NC}"
    exit 1
fi

# Validate PCAP file if provided
if [ -n "$PCAP_FILE" ] && [ ! -f "$PCAP_FILE" ]; then
    echo -e "${RED}ERROR: PCAP file not found: $PCAP_FILE${NC}"
    exit 1
fi

# Determine basename from keylog filename
KEYLOG_BASENAME=$(basename "$KEYLOG_FILE" .log)
OUTPUT_DIR="analysis/${KEYLOG_BASENAME}"

echo "==================================================================="
echo "SSH Analysis Files Generator"
echo "==================================================================="
echo ""
echo "Input keylog:  $KEYLOG_FILE"
if [ -n "$PCAP_FILE" ]; then
    echo "Input PCAP:    $PCAP_FILE"
fi
echo "Output dir:    $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if keylog has required data
NEWKEYS_COUNT=$(grep -c "NEWKEYS" "$KEYLOG_FILE" || echo 0)
SHARED_SECRET_COUNT=$(grep -c "SHARED_SECRET" "$KEYLOG_FILE" || echo 0)

echo "Keylog content:"
echo "  NEWKEYS lines:      $NEWKEYS_COUNT"
echo "  SHARED_SECRET lines: $SHARED_SECRET_COUNT"
echo ""

if [ "$NEWKEYS_COUNT" -eq 0 ]; then
    echo -e "${RED}WARNING: No NEWKEYS found in keylog${NC}"
    echo "Cannot generate keys.json for Python decryptor"
fi

if [ "$SHARED_SECRET_COUNT" -eq 0 ]; then
    echo -e "${RED}WARNING: No SHARED_SECRET found in keylog${NC}"
    echo "Cannot generate Wireshark keylog"
fi

#===========================================================================
# 1. Generate keys.json for Python decryptor
#===========================================================================

if [ "$NEWKEYS_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[1/2] Generating keys.json for Python decryptor...${NC}"

    # Extract values from keylog
    TIMESTAMP=$(grep "NEWKEYS MODE OUT" "$KEYLOG_FILE" | awk '{print $1}' | head -1)
    CIPHER=$(grep "NEWKEYS MODE OUT" "$KEYLOG_FILE" | awk '{print $6}' | head -1)
    KEY_OUT=$(grep "NEWKEYS MODE OUT" "$KEYLOG_FILE" | awk '{print $8}' | head -1)
    KEY_IN=$(grep "NEWKEYS MODE IN" "$KEYLOG_FILE" | awk '{print $8}' | head -1)
    SESSION_ID=$(grep "SESSION_ID" "$KEYLOG_FILE" | awk '{print $8}' | head -1)
    COOKIE=$(grep "COOKIE" "$KEYLOG_FILE" | awk '{print $2}' | head -1)

    # Validate extracted values
    if [ -z "$TIMESTAMP" ] || [ -z "$CIPHER" ] || [ -z "$KEY_OUT" ] || [ -z "$KEY_IN" ]; then
        echo -e "${RED}ERROR: Failed to extract required values from keylog${NC}"
        exit 1
    fi

    # Create JSON file
    cat > "$OUTPUT_DIR/keys.json" << EOF
{
  "sessions": [
    {
      "timestamp": ${TIMESTAMP},
      "cipher": "${CIPHER}",
      "keys": {
        "client_to_server": {
          "encryption_key": "${KEY_OUT}",
          "iv": "unknown"
        },
        "server_to_client": {
          "encryption_key": "${KEY_IN}",
          "iv": "unknown"
        }
      },
      "session_id": "${SESSION_ID:-unknown}",
      "cookie": "${COOKIE:-unknown}"
    }
  ]
}
EOF

    echo -e "${GREEN}  ✓ Created: $OUTPUT_DIR/keys.json${NC}"
    echo "    Timestamp: $TIMESTAMP"
    echo "    Cipher:    $CIPHER"
    echo "    Key OUT:   ${KEY_OUT:0:32}... (${#KEY_OUT} chars)"
    echo "    Key IN:    ${KEY_IN:0:32}... (${#KEY_IN} chars)"
    if [ -n "$SESSION_ID" ]; then
        echo "    Session ID: ${SESSION_ID:0:32}... (${#SESSION_ID} chars)"
    fi
    if [ -n "$COOKIE" ]; then
        echo "    Cookie:    $COOKIE"
    fi
    echo ""
else
    echo -e "${YELLOW}[1/2] SKIPPED: No NEWKEYS data for keys.json${NC}"
    echo ""
fi

#===========================================================================
# 2. Generate Wireshark keylog
#===========================================================================

if [ "$SHARED_SECRET_COUNT" -gt 0 ]; then
    echo -e "${GREEN}[2/2] Generating Wireshark keylog...${NC}"

    WIRESHARK_KEYLOG="$OUTPUT_DIR/ssh_wireshark.keylog"

    # Build command
    CMD=(python3 generate_wireshark_keylog.py
         --keylog "$KEYLOG_FILE"
         --out "$WIRESHARK_KEYLOG")

    if [ -n "$PCAP_FILE" ]; then
        CMD+=(--pcap "$PCAP_FILE")
    fi

    # Run generator
    if "${CMD[@]}"; then
        echo -e "${GREEN}  ✓ Created: $WIRESHARK_KEYLOG${NC}"

        # Show file preview
        if [ -f "$WIRESHARK_KEYLOG" ]; then
            LINE_COUNT=$(wc -l < "$WIRESHARK_KEYLOG" | tr -d ' ')
            echo "    Sessions: $LINE_COUNT"
            echo ""
            echo "    Preview:"
            head -3 "$WIRESHARK_KEYLOG" | while IFS= read -r line; do
                COOKIE=$(echo "$line" | awk '{print $1}')
                SECRET=$(echo "$line" | awk '{print $3}')
                echo "      Cookie: $COOKIE"
                echo "      Secret: ${SECRET:0:32}... (${#SECRET} chars)"
                echo ""
            done
        fi
    else
        echo -e "${RED}  ✗ Failed to generate Wireshark keylog${NC}"
    fi
else
    echo -e "${YELLOW}[2/2] SKIPPED: No SHARED_SECRET data for Wireshark${NC}"
    echo ""
fi

#===========================================================================
# Summary and next steps
#===========================================================================

echo "==================================================================="
echo "SUMMARY"
echo "==================================================================="
echo ""

if [ -f "$OUTPUT_DIR/keys.json" ]; then
    echo -e "${GREEN}✓ keys.json created${NC}"
else
    echo -e "${RED}✗ keys.json NOT created${NC}"
fi

if [ -f "$OUTPUT_DIR/ssh_wireshark.keylog" ]; then
    echo -e "${GREEN}✓ ssh_wireshark.keylog created${NC}"
else
    echo -e "${RED}✗ ssh_wireshark.keylog NOT created${NC}"
fi

echo ""
echo "==================================================================="
echo "NEXT STEPS"
echo "==================================================================="
echo ""

if [ -f "$OUTPUT_DIR/keys.json" ]; then
    echo "1. Python SSH Decryptor:"
    echo ""
    echo "   python3 ../openSSH/research_setup/decryption/ssh_decryptor.py \\"
    echo "       --pcap <your_capture.pcap> \\"
    echo "       --keys $OUTPUT_DIR/keys.json \\"
    echo "       --decrypted-pcap $OUTPUT_DIR/decrypted.pcap \\"
    echo "       --debug"
    echo ""
fi

if [ -f "$OUTPUT_DIR/ssh_wireshark.keylog" ]; then
    echo "2. Wireshark GUI Decryption:"
    echo ""
    echo "   a) Open Wireshark"
    echo "   b) Edit → Preferences → Protocols → SSH"
    echo "   c) Set 'SSH key log file' to:"
    echo "      $(pwd)/$OUTPUT_DIR/ssh_wireshark.keylog"
    echo "   d) Open your PCAP - SSH traffic should be decrypted"
    echo ""
fi

echo "==================================================================="
