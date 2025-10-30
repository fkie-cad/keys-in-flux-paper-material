#!/usr/bin/env bash
# capture_ipsec_http.sh — robust cleanup + graceful tcpdump + Wireshark keys (timestamped)

set -euo pipefail

# --- Config -------------------------------------------------------------------
LEFT_NS="${LEFT_NS:-left}"
RIGHT_NS="${RIGHT_NS:-right}"
LEFT_IP="${LEFT_IP:-10.0.0.1}"
RIGHT_IP="${RIGHT_IP:-10.0.0.2}"
HTTP_PORT="${HTTP_PORT:-8080}"
DOC_ROOT="${DOC_ROOT:-/tmp}"
TEST_FILE="${TEST_FILE:-plain_ipsec.txt}"

CAP_FILTER="${CAP_FILTER:-esp or udp port 4500 or udp port 500}"
CAP_DURATION="${CAP_DURATION:-12}"
TCPDUMP_IFACE="${TCPDUMP_IFACE:-any}"  # set to the veth if you prefer

# Outputs (timestamped) --------------------------------------------------------
TS="$(date +%s)"
KEYS_DIR="${KEYS_DIR:-./esp_keys}"
mkdir -p "${KEYS_DIR}"

PCAP_LEFT="${KEYS_DIR}/ipsec-esp-left_${TS}.pcap"
WS_ESP="${KEYS_DIR}/esp_sa_${TS}.csv"

# --- State --------------------------------------------------------------------
TCPDUMP_PID=""
HTTPD_PID=""

log()      { printf '%s\n' "$*"; }
log_i()    { printf '[*] %s\n' "$*"; }
log_ok()   { printf '[OK] %s\n' "$*"; }
log_err()  { printf '[ERROR] %s\n' "$*" >&2; }

ns_exec()  { local ns="$1"; shift; ip netns exec "$ns" bash -lc "$*"; }

cleanup() {
  # Stop HTTP server
  if [[ -n "${HTTPD_PID}" ]] && kill -0 "${HTTPD_PID}" 2>/dev/null; then
    log_i "Stopping HTTP server in '${RIGHT_NS}' netns..."
    kill -TERM "${HTTPD_PID}" 2>/dev/null || true
    wait "${HTTPD_PID}" 2>/dev/null || true
  fi
  # Stop tcpdump gracefully (flush trailer)
  if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
    kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
    wait "${TCPDUMP_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

# --- Sanity -------------------------------------------------------------------
command -v ip >/dev/null || { log_err "ip(8) not found"; exit 1; }
for bin in tcpdump python3 curl; do
  command -v "$bin" >/dev/null || { log_err "$bin not found"; exit 1; }
done

echo "=== IPsec capture helper (inside netns) ==="
echo "PCAP will be saved to: ${PCAP_LEFT}"
echo "Capture filter: ${CAP_FILTER}"
echo

# --- Preflight cleanup to avoid stale state -----------------------------------
log_i "Preflight cleanup of stale processes/files..."

# 1) Kill any previous tcpdump in LEFT that writes to our pcap OR runs with our filter
ns_exec "${LEFT_NS}" '
  if command -v lsof >/dev/null 2>&1; then
    PIDS=$(lsof -t -- '"${PCAP_LEFT@Q}"' 2>/dev/null || true)
    if [ -n "$PIDS" ]; then kill -INT $PIDS 2>/dev/null || true; sleep 0.2; kill -KILL $PIDS 2>/dev/null || true; fi
  fi
  PIDS=$(pgrep -f "tcpdump .* -w *'"${PCAP_LEFT//\//\\/}"'" 2>/dev/null || true)
  if [ -n "$PIDS" ]; then kill -INT $PIDS 2>/dev/null || true; sleep 0.2; kill -KILL $PIDS 2>/dev/null || true; fi
'

# 2) Ensure the pcap path is writable and not locked
ns_exec "${LEFT_NS}" '
  rm -f '"${PCAP_LEFT@Q}"' 2>/dev/null || true
  umask 000
  : > '"${PCAP_LEFT@Q}"'
  chmod 666 '"${PCAP_LEFT@Q}"' || true
'

# 3) Free the HTTP port in RIGHT for RIGHT_IP:HTTP_PORT (no awk-escape warnings)
ip netns exec "${RIGHT_NS}" bash -lc '
  if command -v ss >/dev/null 2>&1; then
    ip_addr="'"${RIGHT_IP}"'"
    port="'"${HTTP_PORT}"'"
    PIDS=$(ss -ltnp 2>/dev/null | awk -v ip="$ip_addr" -v port="$port" '"'"'
      $4 ~ ("(^|,)" ip ":" port "($|,)") {
        if (match($NF, /pid=([0-9]+)/, m)) print m[1];
      }
    '"'"' | sort -u)
    if [ -n "$PIDS" ]; then
      kill -TERM $PIDS 2>/dev/null || true
      sleep 0.3
      kill -KILL $PIDS 2>/dev/null || true
    fi
  elif command -v fuser >/dev/null 2>&1; then
    fuser -k -n tcp '"${HTTP_PORT}"' 2>/dev/null || true
  fi
'

# 4) Make sure doc root exists and test file is present (RIGHT)
ns_exec "${RIGHT_NS}" "mkdir -p '${DOC_ROOT}' && printf '%s\n' 'THIS IS A PLAINTEXT MESSAGE FROM RIGHT' > '${DOC_ROOT}/${TEST_FILE}'"

# --- Start tcpdump (host controls child PID; no interactive wait) -------------
log_i "Starting tcpdump in '${LEFT_NS}' netns for ${CAP_DURATION}s..."
# Run tcpdump fully detached (no tty), capture its host PID, and manage it here.
ip netns exec "${LEFT_NS}" bash -lc "exec tcpdump -i '${TCPDUMP_IFACE}' -s 0 -U -w '${PCAP_LEFT}' ${CAP_FILTER@Q}" \
  >/dev/null 2>&1 &
TCPDUMP_PID=$!

# --- Start HTTP server --------------------------------------------------------
log_i "Starting HTTP server in '${RIGHT_NS}' netns on ${RIGHT_IP}:${HTTP_PORT} (serving ${DOC_ROOT})..."
ns_exec "${RIGHT_NS}" "cd '${DOC_ROOT}' && python3 -m http.server '${HTTP_PORT}' --bind '${RIGHT_IP}'" &
HTTPD_PID=$!
sleep 0.6
log "HTTP server started, pid: ${HTTPD_PID}"

# --- Generate traffic ---------------------------------------------------------
URL="http://${RIGHT_IP}:${HTTP_PORT}/${TEST_FILE}"
log_i "Fetching from '${LEFT_NS}' -> ${URL} ..."
if ns_exec "${LEFT_NS}" "curl -sS --fail-with-body --max-time 8 '${URL}'"; then
  log_ok "curl succeeded. Response:"
  echo "-----"
  ns_exec "${LEFT_NS}" "curl -s '${URL}'"; echo; echo "-----"
else
  log_err "curl failed (see above)."
fi

# Keep window open the full duration (simple, predictable)
sleep "${CAP_DURATION}"

# --- Shutdown & verify --------------------------------------------------------
log_i "Stopping HTTP server and tcpdump..."
if [[ -n "${HTTPD_PID}" ]] && kill -0 "${HTTPD_PID}" 2>/dev/null; then
  kill -TERM "${HTTPD_PID}" 2>/dev/null || true
  wait "${HTTPD_PID}" 2>/dev/null || true
fi

if [[ -n "${TCPDUMP_PID}" ]] && kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  kill -INT "${TCPDUMP_PID}" 2>/dev/null || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
fi

# pcap ready?
if ns_exec "${LEFT_NS}" "[ -s '${PCAP_LEFT}' ]"; then
  log_ok "PCAP captured: ${PCAP_LEFT}"
else
  log_err "PCAP empty or not found at ${PCAP_LEFT} (inside ${LEFT_NS} netns)."
  echo "Hint: increase CAP_DURATION or trigger multiple requests."
  ns_exec "${LEFT_NS}" "command -v lsof >/dev/null && lsof -nP '${PCAP_LEFT}' || true"
  exit 1
fi

echo
log_i "Quick tcpdump summary (reading pcap):"
tcpdump -r "${PCAP_LEFT}" -q -n 2>/dev/null | sed -e 's/^/  /'

echo
log_i "Searching for save-keys output if its available (esp_sa, ikev2_decryption_table)..."
grep -RIl --null -e 'esp_sa' -e 'ikev2_decryption_table' /tmp 2>/dev/null | xargs -0 -r ls -l || true
echo

# -------------------------------------------------------------
# Print swanctl/xfrm and write Wireshark esp_sa (timestamped)
# -------------------------------------------------------------
echo "[LEFT] SAs:"
ip netns exec "${LEFT_NS}"  /usr/sbin/swanctl --list-sas --uri unix:///run/left.charon.vici || true
echo
echo "[RIGHT] SAs:"
ip netns exec "${RIGHT_NS}" /usr/sbin/swanctl --list-sas --uri unix:///run/right.charon.vici || true
echo
echo "[LEFT] XFRM:"
ip netns exec "${LEFT_NS}"  bash -lc 'ip xfrm state; echo; ip xfrm policy' || true
echo
echo "[RIGHT] XFRM:"
ip netns exec "${RIGHT_NS}" bash -lc 'ip xfrm state; echo; ip xfrm policy' || true
echo

# --- Generate a Wireshark esp_sa from ip xfrm state ---------------------------
TMP_LEFT="$(mktemp)"; TMP_RIGHT="$(mktemp)"
ip netns exec "${LEFT_NS}"  bash -lc 'ip xfrm state'  > "$TMP_LEFT"  2>/dev/null || true
ip netns exec "${RIGHT_NS}" bash -lc 'ip xfrm state'  > "$TMP_RIGHT" 2>/dev/null || true

# Prefer secShark.pl if available; else use the built-in awk parser
if command -v perl >/dev/null 2>&1 && [ -f /usr/local/bin/secShark.pl ]; then
  /usr/local/bin/secShark.pl "$TMP_LEFT"  > "$WS_ESP"  2>/dev/null || true
  /usr/local/bin/secShark.pl "$TMP_RIGHT" >> "$WS_ESP"  2>/dev/null || true
else
{
  printf '%s\n' '# Generated esp_sa (xfrm simple parser); prefer save-keys/secShark for full coverage'
  for TMP in "$TMP_LEFT" "$TMP_RIGHT"; do
    awk '
      BEGIN { FS = "\n"; RS = "" }  # one paragraph per SA
      {
        block = $0
        src = dst = spi = enc_algo = enc_key = auth_algo = auth_key = tbits = ""

        # src/dst
        if (match(block, /src[[:space:]]+([0-9a-fA-F:.]+)[[:space:]]+dst[[:space:]]+([0-9a-fA-F:.]+)/, m)) {
          src = m[1]; dst = m[2]
        } else { next }

        # spi (hex or dec)
        if (match(block, /spi[[:space:]]+0x([0-9a-fA-F]+)/, m)) {
          spi = "0x" tolower(m[1])
        } else if (match(block, /spi[[:space:]]+([0-9]+)/, m)) {
          spi = sprintf("0x%x", m[1] + 0)
        }

        # AEAD first (e.g., aead rfc4106(gcm(aes)) 0xKEY 128)
        if (match(block, /(^|\n)[[:space:]]*aead[[:space:]]+([^[:space:]]+)[[:space:]]+(0x[0-9A-Fa-f]+)([[:space:]]+([0-9]+))?/, mA)) {
          enc_algo = mA[2]
          enc_key  = tolower(mA[3])     # KEEP 0x
          # mA[5] is optional ICV bits; leave auth fields empty for AEAD
        } else {
          # enc + auth (non-AEAD)
          if (match(block, /(^|\n)[[:space:]]*enc[[:space:]]+([^[:space:]]+)[[:space:]]+(0x[0-9A-Fa-f]+)/, mE)) {
            enc_algo = mE[2]
            enc_key  = tolower(mE[3])   # KEEP 0x
          }
          # NOTE: no (?:...) — POSIX awk. Capture groups shift accordingly:
          # mH[1] optional "-trunc"
          # mH[3] algorithm name (e.g., hmac(sha256))
          # mH[4] key with 0x prefix
          # mH[6] optional trunc bits
          if (match(block, /(^|\n)[[:space:]]*auth(-trunc)?[[:space:]]+([[:alnum:]_()\/-]+)[[:space:]]+(0x[0-9A-Fa-f]+)([[:space:]]+([0-9]+))?/, mH)) {
            auth_algo = mH[3]
            auth_key  = tolower(mH[4])  # KEEP 0x
            tbits     = (mH[6] ? mH[6] : "")
          }
        }

        # clean up algo strings and append trunc length if present
        gsub(/"/, "", enc_algo); gsub(/"/, "", auth_algo)
        if (auth_algo != "" && tbits != "") auth_algo = auth_algo " " tbits

        if (spi != "" && enc_algo != "") {
          printf "\"ESP\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
                 src, dst, spi, enc_algo, enc_key, auth_algo, auth_key
        }
      }
    ' "$TMP"
  done
} > "$WS_ESP"
fi

echo "[INFO] Wrote Wireshark esp_sa file to: $WS_ESP"
echo "[INFO] PCAP saved to: $PCAP_LEFT"
echo "[INFO] (Both files share the timestamp: ${TS})"
rm -f "$TMP_LEFT" "$TMP_RIGHT"

echo
echo "Done."