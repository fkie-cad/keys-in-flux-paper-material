#!/usr/bin/env bash
set -euo pipefail

PCAP="${1:-capture.pcapng}"
INIT_SPI="f8e9857fc7dee1f0"   # 16 hex chars
RESP_SPI="f61fa2d718397f65"   # 16 hex chars

# 224-byte blob (hex, no spaces/newlines) → 7×32-byte chunks
HEXBLOB="$(tr -d ' \n' < keys.hex)"       # or set HEXBLOB="..."
chunks=()
for i in {0..6}; do chunks+=("${HEXBLOB:$((i*64)):64}"); done

# Common algo guesses; tune these to your capture
ENC_ALGS=("AES-CBC" "AES-CTR" "AES-GCM with 16 octet ICV")
INT_ALGS=("HMAC-SHA-1-96" "HMAC-SHA-256-128" "NULL")  # use NULL for AEAD/GCM

hit() { echo "HIT: ENC=$1 INT=$2 ei=$3 er=$4 ai=$5 ar=$6"; }

# Heuristic 1: the typical IKEv2 derivation order is SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
# so try that mapping first to be fast:
try_sets=()
try_sets+=("${chunks[3]}:${chunks[4]}:${chunks[1]}:${chunks[2]}")   # ei:er:ai:ar

# Heuristic 2: also try each 4-chunk sliding window in order
for o in {0..3}; do try_sets+=("${chunks[$((o+2))]}:${chunks[$((o+3))]}:${chunks[$((o))]}:${chunks[$((o+1))]}"); done

for rec in "${try_sets[@]}"; do
  IFS=: read -r SK_EI SK_ER SK_AI SK_AR <<<"$rec"
  for ENC in "${ENC_ALGS[@]}"; do
    for INT in "${INT_ALGS[@]}"; do
      # For AEAD (e.g., AES-GCM), integrity is NULL; SK_ai/SK_ar are ignored. :contentReference[oaicite:3]{index=3}
      [[ "$ENC" == AES-GCM* ]] && INT="NULL"
      CSV="${INIT_SPI},${RESP_SPI},${SK_EI},${SK_ER},\"${ENC}\",${SK_AI},${SK_AR},\"${INT}\""
      if /Applications/Wireshark.app/Contents/MacOS/tshark -nr "$PCAP" -q \
        -o "uat:ikev2_decryption_table:${CSV}" \
        -Y 'isakmp.enc.decrypted' -c 1 >/dev/null 2>&1; then
        hit "$ENC" "$INT" "$SK_EI" "$SK_ER" "$SK_AI" "$SK_AR"
      fi
    done
  done
done

