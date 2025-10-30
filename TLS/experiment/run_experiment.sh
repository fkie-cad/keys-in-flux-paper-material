#!/bin/bash

# Read from command line, with defaults
tls_version="${1:-13}"
library="${2:-boringssl}"
abort_mode="${3:-1}"
key_update_mode="${4:-1}"
data_storage_path="${5:-./shared_data}"
NUM_ITERATIONS=100

echo "Starting experiment with TLS ${tls_version} and library ${library}..."

# Create library-specific base directory
LIBRARY_DIR="${data_storage_path}/${library}"
mkdir -p "$LIBRARY_DIR"

for i in $(seq 1 $NUM_ITERATIONS)
do
  echo "--- Starting Iteration $i ---"

  RUN_DIR="${LIBRARY_DIR}/${library}_run_${tls_version}_${i}"
  mkdir -p "$RUN_DIR/run_data"
  
  # Set permissions so containers can write (they run as root)
  chmod -R 777 "$RUN_DIR"

  # Export variables to be used by docker-compose
  export TLS_VERSION=$tls_version
  export LIBRARY=$library
  export ABORT=${abort_mode:-1}
  export KEY_UPDATE=${key_update_mode:-1}
  export RUN_DIR="$RUN_DIR"
  export UID=$(id -u)
  export GID=$(id -g)

  echo "Starting containers..."
  docker compose up --build --abort-on-container-exit

  echo "Waiting for containers to finalize file operations..."
  sleep 5

  echo "Iteration $i finished. Tearing down environment."

  docker compose down -v

  echo "--- Iteration $i Complete ---"
  sleep 1
done

echo "Experiment finished."