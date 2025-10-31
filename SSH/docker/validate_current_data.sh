#!/bin/bash

echo "=== SSH Key Lifespan Data Validation ==="
echo ""

# Create analysis directory if missing
mkdir -p analysis/{groundtruth,dropbear,lldb}

# Check keylogs
echo "📝 KEYLOGS:"
if [ -f data/keylogs/groundtruth_self_test.log ]; then
    KEYS=$(grep -c NEWKEYS data/keylogs/groundtruth_self_test.log)
    echo "  ✓ groundtruth_self_test.log: $KEYS keys"

    # Extract keys (field $8 contains the actual key hex, $7 is just the word "KEY")
    grep "MODE OUT" data/keylogs/groundtruth_self_test.log | awk '{print $8}' > analysis/groundtruth/key_out.hex 2>/dev/null
    grep "MODE IN" data/keylogs/groundtruth_self_test.log | awk '{print $8}' > analysis/groundtruth/key_in.hex 2>/dev/null

    if [ -f analysis/groundtruth/key_out.hex ]; then
        KEY_LEN=$(cat analysis/groundtruth/key_out.hex | wc -c | tr -d ' ')
        echo "    Key OUT length: $KEY_LEN characters"
    fi

    if [ -f analysis/groundtruth/key_in.hex ]; then
        KEY_LEN=$(cat analysis/groundtruth/key_in.hex | wc -c | tr -d ' ')
        echo "    Key IN length: $KEY_LEN characters"
    fi

    # Create keys.json for decryption if not exists
    if [ ! -f analysis/groundtruth/keys.json ]; then
        echo "    Creating keys.json for decryption..."

        # Extract values from keylog
        TIMESTAMP=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth_self_test.log | awk '{print $1}' | head -1)
        CIPHER=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth_self_test.log | awk '{print $6}' | head -1)
        KEY_OUT=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth_self_test.log | awk '{print $8}' | head -1)
        KEY_IN=$(grep "NEWKEYS MODE IN" data/keylogs/groundtruth_self_test.log | awk '{print $8}' | head -1)
        SESSION_ID=$(grep "SESSION_ID" data/keylogs/groundtruth_self_test.log | awk '{print $8}' | head -1)
        COOKIE=$(grep "COOKIE" data/keylogs/groundtruth_self_test.log | awk '{print $2}' | head -1)

        # Create JSON file
        cat > analysis/groundtruth/keys.json << EOF
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
      "session_id": "${SESSION_ID}",
      "cookie": "${COOKIE}"
    }
  ]
}
EOF
        echo "    ✓ keys.json created"
    else
        echo "    ✓ keys.json already exists"
    fi
else
    echo "  ✗ groundtruth_self_test.log: NOT FOUND"
fi

if [ -f data/keylogs/groundtruth.log ]; then
    KEYS=$(grep -c NEWKEYS data/keylogs/groundtruth.log 2>/dev/null || echo 0)
    echo "  ✓ groundtruth.log: $KEYS keys"

    # Extract keys (field $8 contains the actual key hex)
    grep "MODE OUT" data/keylogs/groundtruth.log | awk '{print $8}' > analysis/groundtruth/key_out_gt.hex 2>/dev/null
    grep "MODE IN" data/keylogs/groundtruth.log | awk '{print $8}' > analysis/groundtruth/key_in_gt.hex 2>/dev/null

    if [ -f analysis/groundtruth/key_out_gt.hex ]; then
        KEY_LEN=$(cat analysis/groundtruth/key_out_gt.hex | wc -c | tr -d ' ')
        echo "    Key OUT length: $KEY_LEN characters"
    fi

    if [ -f analysis/groundtruth/key_in_gt.hex ]; then
        KEY_LEN=$(cat analysis/groundtruth/key_in_gt.hex | wc -c | tr -d ' ')
        echo "    Key IN length: $KEY_LEN characters"
    fi

    # Create groundtruth-specific keys.json for decryption if not exists
    if [ ! -f analysis/groundtruth/keys_groundtruth.json ]; then
        echo "    Creating keys_groundtruth.json for decryption..."

        # Extract values from keylog
        TIMESTAMP=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth.log | awk '{print $1}' | head -1)
        CIPHER=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth.log | awk '{print $6}' | head -1)
        KEY_OUT=$(grep "NEWKEYS MODE OUT" data/keylogs/groundtruth.log | awk '{print $8}' | head -1)
        KEY_IN=$(grep "NEWKEYS MODE IN" data/keylogs/groundtruth.log | awk '{print $8}' | head -1)
        SESSION_ID=$(grep "SESSION_ID" data/keylogs/groundtruth.log | awk '{print $8}' | head -1)
        COOKIE=$(grep "COOKIE" data/keylogs/groundtruth.log | awk '{print $2}' | head -1)

        # Create JSON file
        cat > analysis/groundtruth/keys_groundtruth.json << EOF
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
      "session_id": "${SESSION_ID}",
      "cookie": "${COOKIE}"
    }
  ]
}
EOF
        echo "    ✓ keys_groundtruth.json created"
    else
        echo "    ✓ keys_groundtruth.json already exists"
    fi
else
    echo "  ✗ groundtruth.log: NOT FOUND"
fi

# Generate Wireshark keylogs if groundtruth logs exist
echo ""
echo "🔐 WIRESHARK KEYLOGS:"
for keylog in data/keylogs/groundtruth*.log; do
    if [ -f "$keylog" ]; then
        BASENAME=$(basename "$keylog" .log)
        WIRESHARK_KEYLOG="analysis/groundtruth/ssh_wireshark_${BASENAME}.keylog"

        if [ ! -f "$WIRESHARK_KEYLOG" ]; then
            echo "  Generating Wireshark keylog for $BASENAME..."
            if python3 generate_wireshark_keylog.py --keylog "$keylog" --out "$WIRESHARK_KEYLOG" > /dev/null 2>&1; then
                echo "    ✓ Created ssh_wireshark_${BASENAME}.keylog"
            else
                echo "    ⚠ Failed to generate Wireshark keylog (missing SHARED_SECRET or cookie?)"
            fi
        else
            echo "  ✓ ssh_wireshark_${BASENAME}.keylog already exists"
        fi
    fi
done

echo ""
echo "📦 PCAP FILES:"
PCAP_COUNT=0
if ls data/captures/*.pcap 1> /dev/null 2>&1; then
    for pcap in data/captures/*.pcap; do
        if [ -f "$pcap" ]; then
            SIZE=$(ls -lh "$pcap" | awk '{print $5}')
            echo "  ✓ $(basename $pcap): $SIZE"
            PCAP_COUNT=$((PCAP_COUNT + 1))
        fi
    done
fi
if [ $PCAP_COUNT -eq 0 ]; then
    echo "  ✗ No PCAP files found"
fi

echo ""
echo "🔬 LLDB RESULTS:"
LLDB_COUNT=0
if ls data/lldb_results/* 1> /dev/null 2>&1; then
    for file in data/lldb_results/*; do
        if [ -f "$file" ]; then
            SIZE=$(wc -l < "$file" | tr -d ' ')
            echo "  ✓ $(basename $file): $SIZE lines"
            LLDB_COUNT=$((LLDB_COUNT + 1))
        fi
    done
fi
if [ $LLDB_COUNT -eq 0 ]; then
    echo "  ✗ No LLDB results found"
fi

echo ""
echo "💾 DUMPS:"
if [ -d data/dumps ]; then
    DUMP_COUNT=$(find data/dumps -name "*.dump" 2>/dev/null | wc -l | tr -d ' ')
    if [ $DUMP_COUNT -gt 0 ]; then
        echo "  ✓ $DUMP_COUNT memory dump files"
        # Show first few
        find data/dumps -name "*.dump" 2>/dev/null | head -5 | while read dump; do
            SIZE=$(ls -lh "$dump" | awk '{print $5}')
            echo "    - $(basename $dump): $SIZE"
        done
        if [ $DUMP_COUNT -gt 5 ]; then
            echo "    ... and $((DUMP_COUNT - 5)) more"
        fi
    else
        echo "  ✗ No memory dumps found"
    fi
else
    echo "  ✗ dumps directory not found"
fi

echo ""
echo "=== DETAILED KEYLOG CONTENT ==="
for keylog in data/keylogs/*.log; do
    if [ -f "$keylog" ]; then
        echo ""
        echo "File: $(basename $keylog)"
        echo "────────────────────────────────────────"
        cat "$keylog" | head -10
        LINES=$(wc -l < "$keylog" | tr -d ' ')
        if [ $LINES -gt 10 ]; then
            echo "... ($((LINES - 10)) more lines)"
        fi
    fi
done

echo ""
echo "=== SUMMARY ==="
echo "Analysis directory: $([ -d analysis ] && echo '✓ Created' || echo '✗ Missing')"
echo "Keylogs available: $(ls data/keylogs/*.log 2>/dev/null | wc -l | tr -d ' ')"
echo "PCAPs available: $PCAP_COUNT"
echo "LLDB results: $LLDB_COUNT files"
echo "Memory dumps: $DUMP_COUNT files"

echo ""
echo "=== NEXT STEPS ==="
echo ""
echo "1. Review extracted keys:"
echo "   cat data/keylogs/groundtruth_self_test.log"
echo "   cat data/keylogs/groundtruth.log"
echo ""
echo "2. Parse keylog with tool:"
echo "   python3 parse_keylog.py data/keylogs/groundtruth_self_test.log --summary"
echo ""
echo "3. Validate keys match (client vs server):"
echo "   diff <(grep 'MODE OUT' data/keylogs/groundtruth_self_test.log | awk '{print \$8}') \\"
echo "        <(grep 'MODE IN' data/keylogs/groundtruth.log | awk '{print \$8}')"
echo ""
echo "4. DECRYPTION METHOD 1 - Python SSH Decryptor (uses derived encryption keys):"
echo "   # For groundtruth_self_test.log:"
echo "   python3 ../openSSH/research_setup/decryption/ssh_decryptor.py \\"
echo "       --pcap data/captures/server_*.pcap \\"
echo "       --keys analysis/groundtruth/keys.json \\"
echo "       --decrypted-pcap analysis/groundtruth/decrypted.pcap \\"
echo "       --debug"
echo ""
echo "   # For groundtruth.log:"
echo "   python3 ../openSSH/research_setup/decryption/ssh_decryptor.py \\"
echo "       --pcap data/captures/server_*.pcap \\"
echo "       --keys analysis/groundtruth/keys_groundtruth.json \\"
echo "       --decrypted-pcap analysis/groundtruth/decrypted_gt.pcap \\"
echo "       --debug"
echo ""
echo "5. DECRYPTION METHOD 2 - Wireshark (uses shared secret K):"
echo "   # Wireshark keylogs are auto-generated above"
echo "   # To manually regenerate:"
echo "   python3 generate_wireshark_keylog.py \\"
echo "       --keylog data/keylogs/groundtruth.log \\"
echo "       --out analysis/groundtruth/ssh_wireshark_groundtruth.keylog"
echo ""
echo "   # Then in Wireshark:"
echo "   #  1. Edit → Preferences → Protocols → SSH"
echo "   #  2. Set 'SSH key log file' to:"
echo "   #     $(pwd)/analysis/groundtruth/ssh_wireshark_groundtruth.keylog"
echo "   #  3. Open PCAP - SSH traffic should be decrypted"
echo ""
echo "6. Check PCAP contents (if tshark available):"
echo "   tshark -r data/captures/server_*.pcap -q -z conv,tcp"
echo ""
echo "7. View extracted key files:"
echo "   cat analysis/groundtruth/key_out.hex"
echo "   cat analysis/groundtruth/key_in.hex"
echo "   cat analysis/groundtruth/keys.json"
echo "   cat analysis/groundtruth/keys_groundtruth.json"
echo "   cat analysis/groundtruth/ssh_wireshark_*.keylog"
echo ""
