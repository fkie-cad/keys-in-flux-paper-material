#!/bin/bash

echo "Starting TLS server with GnuTLS..."

# Default to TLS 1.3, abort=1, keyUpdate=1 if not provided
tls_version="${1:-13}"
abort="${2:-1}"
keyUpdate="${3:-1}"

usage() {
    echo "Usage: $0 <tls_version (12|13)> <abort (0|1)> <keyUpdate (0|1)>"
    exit 1
}

# Validate input
case "$tls_version" in
    13|12) ;;
    *) echo "Invalid tls_version: $tls_version"; usage ;;
esac
case "$abort" in
    0|1) ;;
    *) echo "abort must be 0 or 1"; usage ;;
esac
case "$keyUpdate" in
    0|1) ;;
    *) echo "keyUpdate must be 0 or 1"; usage ;;
esac

echo "Using TLS ${tls_version}, abort=${abort}, keyUpdate=${keyUpdate}"

# Make sure libraries are available and have correct permissions
chmod +x ./gnutls/compiled_clients/libs/*.so*
chmod +x ./gnutls/compiled_clients/test_server_${tls_version}_gnutls_key_export_dl

# Make sure shared_data directory exists
mkdir -p /shared_data/run_data
echo "Created /shared_data/run_data/"

ln -s /app/certs /certs

export LD_LIBRARY_PATH=./gnutls/compiled_clients/libs/
./gnutls/compiled_clients/test_server_${tls_version}_gnutls_key_export_dl ${abort} ${keyUpdate}

echo "Server process finished. Checking for keylog.csv..."
if [ -f "keylog.csv" ]; then
    echo "Found keylog.csv, copying to /shared_data/"
    cp -v keylog.csv /shared_data/keylog.csv
    echo "Keylog copied successfully"
    ls -la /shared_data/
else
    echo "ERROR: keylog.csv not found in current directory"
    ls -la
fi

# Sleep long, the container will be terminted if the client is done
sleep 3