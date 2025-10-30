#!/bin/bash

echo "🚀 Starting network capture..."

# Ensure the directory exists with proper permissions
mkdir -p /shared_data/run_data

echo "Starting tshark on eth0..."
# Run tshark in the background WITHOUT a timeout
tshark -i eth0 -w /shared_data/run_data/traffic.pcap -f "tcp port 4433 or tcp port 4432" &

TSHARK_PID=$!
echo "tshark started with PID: $TSHARK_PID"

# Function to gracefully stop tshark and flush buffers
cleanup() {
    echo "Stopping tshark gracefully..."
    kill -TERM $TSHARK_PID 2>/dev/null || true
    
    # Wait for tshark to finish writing
    wait $TSHARK_PID 2>/dev/null || true
    
    # Additional buffer flush time
    echo "Flushing buffers..."
    sleep 2
    sync
    
    # Fix permissions on the PCAP file so host user can read it
    chmod 644 /shared_data/run_data/traffic.pcap 2>/dev/null || true
    chown ${HOST_UID:-1000}:${HOST_GID:-1000} /shared_data/run_data/traffic.pcap 2>/dev/null || true
    
    echo "Network capture stopped."
}

# Set up trap to handle termination signals from Docker
trap cleanup SIGTERM SIGINT EXIT

# Keep the script running until it receives a signal
echo "Capture running. Waiting for termination signal..."
wait $TSHARK_PID