#!/bin/bash

tls_version="${1:-13}"
library="${2:-boringssl}"

# Path mapping
declare -A path_map
path_map["boringssl"]="./boringssl/compiled_clients/"
path_map["botanssl"]="./botanssl/compiled_clients/"
path_map["gnutls"]="./gnutls/compiled_clients/"
path_map["gotls"]="./gotls/compiled_clients/"
path_map["libressl"]="./libressl/libressl/compiled_clients/"
path_map["libretls"]="./libressl/libretls/compiled_clients/"
path_map["matrixssl"]="./matrixssl/compiled_clients/"
path_map["mbedtls"]="./mbedtls/compiled_clients/"
path_map["nss"]="./nss/compiled_clients/"
path_map["openssl"]="./openssl/compiled_clients/"
path_map["rustls"]="./rustls/compiled_clients/"
path_map["s2ntls"]="./s2n_tls/compiled_clients/"
path_map["wolfssl"]="./wolfssl/compiled_clients/"

declare -A client_map
client_map["boringssl"]="${path_map[boringssl]}test_client_${tls_version}_boringssl_dl"
client_map["botanssl"]="${path_map[botanssl]}test_client_${tls_version}_botanssl_dl"
client_map["gnutls"]="${path_map[gnutls]}test_client_${tls_version}_gnutls_dl"
client_map["gotls"]="${path_map[gotls]}test_client_${tls_version}_gotls_dl"
client_map["libressl"]="${path_map[libressl]}test_client_${tls_version}_libressl_dl"
client_map["libretls"]="${path_map[libretls]}test_client_${tls_version}_libretls_dl"
client_map["matrixssl"]="${path_map[matrixssl]}test_client_${tls_version}_matrixssl_dl"
client_map["mbedtls"]="${path_map[mbedtls]}test_client_${tls_version}_mbedtls_dl"
client_map["nss"]="${path_map[nss]}test_client_${tls_version}_nss_dl"
client_map["openssl"]="${path_map[openssl]}test_client_${tls_version}_openssl_dl"
client_map["rustls"]="${path_map[rustls]}test_client_${tls_version}_rustls"
client_map["s2ntls"]="${path_map[s2ntls]}test_client_${tls_version}_s2ntls_dl"
client_map["wolfssl"]="${path_map[wolfssl]}test_client_${tls_version}_wolfssl_dl"

LIBRARIES="${path_map[$library]}libs/"

# Version string mapping
declare -A tls_version_string
tls_version_string[13]="tls1.3"
tls_version_string[12]="tls1.2"

echo "Starting TLS client..."

sleep 5 # wait for server to start

# Ensure shared_data directory structure exists
mkdir -p /shared_data/run_data

# Export variables for the Python script to use
export LLDB_LIBRARY="$library"
export LLDB_BINARY="${client_map[$library]}"
export LLDB_LIB_PATH="$LIBRARIES"
export LLDB_PROTOCOL_VERSION="${tls_version_string[$tls_version]}"

# Add the script's directory to Python's path so LLDB can import it
export PYTHONPATH=$(pwd)/lldb:$PYTHONPATH

echo "Running LLDB with monitoring.py..."
# Use --batch to wait for the process to finish
lldb -o "script exec(open('./lldb/monitoring.py').read())"

LLDB_EXIT_CODE=$?
echo "LLDB finished with exit code: $LLDB_EXIT_CODE"

# Give filesystem a moment to sync
sync
sleep 1

echo "Copying files from /tmp/$library/ to /shared_data/ ..."
# Copy all files from temp directory to shared_data
if [ -d "/tmp/$library" ] && [ "$(ls -A /tmp/$library)" ]; then
    echo "Files to copy:"
    ls -lah /tmp/$library/
    
    # Copy with verbose output and preserve attributes
    cp -av /tmp/$library/* /shared_data/
    COPY_EXIT=$?
    
    if [ $COPY_EXIT -eq 0 ]; then
        echo "Files copied successfully"
    else
        echo "ERROR: Copy failed with exit code $COPY_EXIT"
    fi
    
else
    echo "Warning: /tmp/$library directory is empty or does not exist"
fi

# Final sync before exit
sync

echo "Client finished."

echo "Waiting a few seconds to ensure all file operations are complete..."
sleep 3

exit 0