#!/usr/bin/env bash
#
# inject_keylog.sh - Inject SSH keylogging code into OpenSSH source
# This script directly modifies kex.c and packet.c to add SSHKEYLOGFILE support
#

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <openssh-source-dir>"
    exit 1
fi

SRC_DIR="$1"
KEX_FILE="$SRC_DIR/kex.c"
PACKET_FILE="$SRC_DIR/packet.c"

echo "[+] Injecting keylog code into OpenSSH source..."

##############################################################################
# 1. Modify kex.c
##############################################################################

echo "[+] Modifying $KEX_FILE..."

# Add includes after the existing poll.h include
sed -i.bak '/^#include <poll.h>/a\
\
#include <sys/file.h>\
#include <time.h>\
#include <pthread.h>
' "$KEX_FILE"

# Find the line with "static int kex_input_newkeys" and add our functions before it
awk '/^static int kex_input_newkeys/ {
    print "static void kex_log_keys(struct ssh *);"
    print ""
    print "/* Mutex for thread-safe keylog file writing */"
    print "static pthread_mutex_t keylog_mutex = PTHREAD_MUTEX_INITIALIZER;"
    print ""
    print "/* Helper: convert binary data to hex string */"
    print "static char *"
    print "bin2hex(const u_char *data, size_t len)"
    print "{"
    print "\tstatic const char hex[] = \"0123456789abcdef\";"
    print "\tchar *out;"
    print "\tsize_t i;"
    print ""
    print "\tif (len == 0 || len > 1024*1024)"
    print "\t\treturn NULL;"
    print ""
    print "\tout = malloc(len * 2 + 1);"
    print "\tif (out == NULL)"
    print "\t\treturn NULL;"
    print ""
    print "\tfor (i = 0; i < len; i++) {"
    print "\t\tout[i * 2] = hex[(data[i] >> 4) & 0x0f];"
    print "\t\tout[i * 2 + 1] = hex[data[i] & 0x0f];"
    print "\t}"
    print "\tout[len * 2] = 0;"
    print "\treturn out;"
    print "}"
    print ""
    print "/* Write keylog entry to SSHKEYLOGFILE and stderr */"
    print "static void"
    print "kex_log_keys(struct ssh *ssh)"
    print "{"
    print "\tstruct kex *kex = ssh->kex;"
    print "\tconst char *keylog_file;"
    print "\tFILE *fp = NULL;"
    print "\tchar *cookie_hex = NULL;"
    print "\tchar *session_id_hex = NULL;"
    print "\ttime_t now;"
    print "\tconst char *enc_name_in = \"unknown\";"
    print "\tconst char *enc_name_out = \"unknown\";"
    print "\tconst u_char *cookie_ptr;"
    print "\tsize_t cookie_len;"
    print ""
    print "\t/* Use SSHKEYLOGFILE env var, or fallback to hardcoded path */"
    print "\tkeylog_file = getenv(\"SSHKEYLOGFILE\");"
    print "\tif (keylog_file == NULL)"
    print "\t\tkeylog_file = \"/tmp/groundtruth.log\";  /* Hardcoded fallback - /tmp avoids FUSE mount issues */"
    print ""
    print "\t/* Check kex structure */"
    print "\tif (kex == NULL || kex->session_id == NULL || kex->peer == NULL)"
    print "\t\treturn;"
    print ""
    print "\t/* Get encryption cipher names from kex->newkeys */"
    print "\tif (kex->newkeys[MODE_IN] && kex->newkeys[MODE_IN]->enc.name)"
    print "\t\tenc_name_in = (char *)kex->newkeys[MODE_IN]->enc.name;"
    print "\tif (kex->newkeys[MODE_OUT] && kex->newkeys[MODE_OUT]->enc.name)"
    print "\t\tenc_name_out = (char *)kex->newkeys[MODE_OUT]->enc.name;"
    print ""
    print "\t/* Extract cookie from peer buffer (skip packet type, first 16 bytes are cookie) */"
    print "\tcookie_ptr = sshbuf_ptr(kex->peer);"
    print "\tcookie_len = sshbuf_len(kex->peer) > 16 ? 16 : sshbuf_len(kex->peer);"
    print "\tif (cookie_ptr != NULL && cookie_len > 0)"
    print "\t\tcookie_hex = bin2hex(cookie_ptr, cookie_len);"
    print ""
    print "\t/* Note: shared_secret K will be logged separately in kex_derive_keys() */"
    print "\t/* where it is available as a parameter before being cleared */"
    print ""
    print "\t/* Thread-safe file writing */"
    print "\tpthread_mutex_lock(&keylog_mutex);"
    print ""
    print "\tfp = fopen(keylog_file, \"a\");"
    print "\tif (fp != NULL) {"
    print "\t\tnow = time(NULL);"
    print "\t\t/* Write COOKIE and SESSION_ID info */"
    print "\t\tfprintf(fp, \"%ld COOKIE %s CIPHER_IN %s CIPHER_OUT %s SESSION_ID \","
    print "\t\t\tnow,"
    print "\t\t\tcookie_hex ? cookie_hex : \"unknown\","
    print "\t\t\tenc_name_in, enc_name_out);"
    print "\t\t/* Write session_id hex */"
    print "\t\tsession_id_hex = bin2hex(sshbuf_ptr(kex->session_id), sshbuf_len(kex->session_id));"
    print "\t\tfprintf(fp, \"%s\\n\", session_id_hex ? session_id_hex : \"unknown\");"
    print "\t\tfclose(fp);"
    print "\t\tfprintf(stderr, \"[SSHKEYLOG] Wrote KEX info to %s\\n\", keylog_file);"
    print "\t\tif (session_id_hex) free(session_id_hex);"
    print "\t}"
    print ""
    print "\tpthread_mutex_unlock(&keylog_mutex);"
    print ""
    print "\tif (cookie_hex) free(cookie_hex);"
    print "}"
    print ""
    print "/* Log shared secret K (must be called during kex_derive_keys before K is cleared) */"
    print "static void"
    print "log_shared_secret(struct sshbuf *shared_secret)"
    print "{"
    print "\tconst char *keylog_file;"
    print "\tFILE *fp = NULL;"
    print "\tchar *K_hex = NULL;"
    print "\ttime_t now;"
    print ""
    print "\t/* Use SSHKEYLOGFILE env var, or fallback to hardcoded path */"
    print "\tkeylog_file = getenv(\"SSHKEYLOGFILE\");"
    print "\tif (keylog_file == NULL)"
    print "\t\tkeylog_file = \"/tmp/groundtruth.log\";  /* Hardcoded fallback - /tmp avoids FUSE mount issues */"
    print ""
    print "\t/* Extract shared secret K (skip 4-byte SSH wire format length prefix) */"
    print "\tif (shared_secret == NULL || sshbuf_len(shared_secret) <= 4)"
    print "\t\treturn;"
    print ""
    print "\t/* SSH stores mpint as: [4 bytes length][N bytes value] */"
    print "\t/* We need just the value for Wireshark, not the length prefix */"
    print "\t{"
    print "\t\tconst u_char *K_ptr = sshbuf_ptr(shared_secret);"
    print "\t\tsize_t K_len = sshbuf_len(shared_secret);"
    print "\t\t/* Skip first 4 bytes (length prefix) */"
    print "\t\tK_hex = bin2hex(K_ptr + 4, K_len - 4);"
    print "\t}"
    print "\tif (K_hex == NULL)"
    print "\t\treturn;"
    print ""
    print "\t/* Thread-safe file writing */"
    print "\tpthread_mutex_lock(&keylog_mutex);"
    print ""
    print "\tfp = fopen(keylog_file, \"a\");"
    print "\tif (fp != NULL) {"
    print "\t\tnow = time(NULL);"
    print "\t\tfprintf(fp, \"%ld SHARED_SECRET %s\\n\", now, K_hex);"
    print "\t\tfclose(fp);"
    print "\t\tfprintf(stderr, \"[SSHKEYLOG] Wrote SHARED_SECRET to %s\\n\", keylog_file);"
    print "\t}"
    print ""
    print "\tpthread_mutex_unlock(&keylog_mutex);"
    print "\tfree(K_hex);"
    print "}"
    print ""
}
{ print }
' "$KEX_FILE" > "$KEX_FILE.tmp" && mv "$KEX_FILE.tmp" "$KEX_FILE"

# Add the call to kex_log_keys inside kex_input_newkeys function
# IMPORTANT: Must be called BEFORE sshbuf_reset(kex->peer) to access the cookie
# Insert right after ssh_set_newkeys and before kex->done = 1
sed -i.bak2 '/^kex_input_newkeys/,/^}/ {
    /kex->done = 1;/i\
	/* Log keys to SSHKEYLOGFILE if set (before peer buffer is reset) */\
	kex_log_keys(ssh);
}' "$KEX_FILE"

# Add the call to log_shared_secret inside kex_derive_keys function
# IMPORTANT: Must be called at the very START before shared_secret is used/cleared
# The function signature is: int kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen, const struct sshbuf *shared_secret)
sed -i.bak3 '/^kex_derive_keys/,/^{/ {
    /^{/a\
	/* Log shared secret K for Wireshark decryption (must be done before any use/clearing) */\
	log_shared_secret((struct sshbuf *)shared_secret);
}' "$KEX_FILE"

##############################################################################
# 2. Modify packet.c
##############################################################################

echo "[+] Modifying $PACKET_FILE..."

# Add includes
sed -i.bak '/^#include <poll.h>/a\
\
#include <sys/file.h>\
#include <pthread.h>
' "$PACKET_FILE"

# Add keylog functions before ssh_set_newkeys
awk '/^int$/{getline; if (/^ssh_set_newkeys/) {
    print "/* Mutex for thread-safe keylog writing from packet layer */"
    print "static pthread_mutex_t pkt_keylog_mutex = PTHREAD_MUTEX_INITIALIZER;"
    print ""
    print "/* Helper: convert binary to hex (duplicate from kex.c for packet.c) */"
    print "static char *"
    print "pkt_bin2hex(const u_char *data, size_t len)"
    print "{"
    print "\tstatic const char hex[] = \"0123456789abcdef\";"
    print "\tchar *out;"
    print "\tsize_t i;"
    print ""
    print "\tif (len == 0 || len > 1024*1024)"
    print "\t\treturn NULL;"
    print ""
    print "\tout = malloc(len * 2 + 1);"
    print "\tif (out == NULL)"
    print "\t\treturn NULL;"
    print ""
    print "\tfor (i = 0; i < len; i++) {"
    print "\t\tout[i * 2] = hex[(data[i] >> 4) & 0x0f];"
    print "\t\tout[i * 2 + 1] = hex[data[i] & 0x0f];"
    print "\t}"
    print "\tout[len * 2] = 0;"
    print "\treturn out;"
    print "}"
    print ""
    print "/* Log derived keys to SSHKEYLOGFILE */"
    print "static void"
    print "log_newkeys_info(struct ssh *ssh, int mode)"
    print "{"
    print "\tstruct session_state *state = ssh->state;"
    print "\tstruct newkeys *newkeys;"
    print "\tconst char *keylog_file;"
    print "\tFILE *fp = NULL;"
    print "\tchar *key_hex = NULL;"
    print "\tchar *iv_hex = NULL;"
    print "\ttime_t now;"
    print "\tconst char *mode_str = (mode == MODE_IN) ? \"IN\" : \"OUT\";"
    print ""
    print "\tkeylog_file = getenv(\"SSHKEYLOGFILE\");"
    print "\tif (keylog_file == NULL)"
    print "\t\tkeylog_file = \"/tmp/groundtruth.log\";  /* Hardcoded fallback - /tmp avoids FUSE mount issues */"
    print ""
    print "\tif (state == NULL || state->newkeys[mode] == NULL)"
    print "\t\treturn;"
    print ""
    print "\tnewkeys = state->newkeys[mode];"
    print ""
    print "\t/* Extract key and IV from newkeys structure */"
    print "\tif (newkeys->enc.key != NULL && newkeys->enc.key_len > 0) {"
    print "\t\tkey_hex = pkt_bin2hex(newkeys->enc.key, newkeys->enc.key_len);"
    print "\t}"
    print "\tif (newkeys->enc.iv != NULL && newkeys->enc.iv_len > 0) {"
    print "\t\tiv_hex = pkt_bin2hex(newkeys->enc.iv, newkeys->enc.iv_len);"
    print "\t}"
    print ""
    print "\tpthread_mutex_lock(&pkt_keylog_mutex);"
    print ""
    print "\tfp = fopen(keylog_file, \"a\");"
    print "\tif (fp != NULL) {"
    print "\t\tnow = time(NULL);"
    print "\t\tfprintf(fp, \"%ld NEWKEYS MODE %s CIPHER %s KEY %s IV %s\\n\","
    print "\t\t\tnow,"
    print "\t\t\tmode_str,"
    print "\t\t\tnewkeys->enc.name ? newkeys->enc.name : \"unknown\","
    print "\t\t\tkey_hex ? key_hex : \"unknown\","
    print "\t\t\tiv_hex ? iv_hex : \"unknown\");"
    print "\t\tfclose(fp);"
    print "\t\tfprintf(stderr, \"[SSHKEYLOG] Wrote NEWKEYS %s to %s\\n\", mode_str, keylog_file);"
    print "\t}"
    print ""
    print "\tpthread_mutex_unlock(&pkt_keylog_mutex);"
    print ""
    print "\tif (key_hex) free(key_hex);"
    print "\tif (iv_hex) free(iv_hex);"
    print "}"
    print ""
    print "int"
    print $0
    next
}}
{ print }
' "$PACKET_FILE" > "$PACKET_FILE.tmp" && mv "$PACKET_FILE.tmp" "$PACKET_FILE"

# Add call to log_newkeys_info at the end of ssh_set_newkeys, before the final return 0
sed -i.bak2 '/^ssh_set_newkeys/,/^}/ {
    /return 0;/i\
	/* Log the new keys to SSHKEYLOGFILE if set */\
	log_newkeys_info(ssh, mode);
}' "$PACKET_FILE"

echo "[+] Keylog code injection complete!"
echo "[+] Modified files:"
echo "    - $KEX_FILE"
echo "    - $PACKET_FILE"
