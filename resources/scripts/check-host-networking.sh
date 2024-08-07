#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to check if a command succeeded
check_command() {
    if [ $? -eq 0 ]; then
        echo "PASS: $1"
        return 0
    else
        echo "FAIL: $1"
        return 1
    fi
}

# Function to check interface state
check_interface_state() {
    local interface=$1
    local state=$(ip -br link show dev $interface | awk '{print $2}')
    if [ "$state" = "UP" ]; then
        echo "PASS: $interface is UP"
        return 0
    else
        echo "FAIL: $interface is $state"
        return 1
    fi
}

# Variables
BR_NAME="br0"
BR_IP="10.20.1.1/24"
SUBNET="10.20.1.0/24"
HOST_DEFAULT_NETWORK_INTERFACE=$(ip r | grep default | awk '{print $5}')
FAIL_COUNT=0

echo "Starting diagnostics..."

# Check if iptables-save command exists
if command -v iptables-save &> /dev/null; then
    check_command "iptables-save command exists" || ((FAIL_COUNT++))
else
    echo "FAIL: iptables-save command not found"
    ((FAIL_COUNT++))
fi

# Check if bridge exists
if ip link show ${BR_NAME} &> /dev/null; then
    check_command "Bridge ${BR_NAME} exists" || ((FAIL_COUNT++))
else
    echo "FAIL: Bridge ${BR_NAME} does not exist"
    ((FAIL_COUNT++))
fi

# Check if bridge is up
check_interface_state ${BR_NAME} || ((FAIL_COUNT++))

# Check if bridge has the correct IP
if ip addr show ${BR_NAME} | grep -q ${BR_IP}; then
    check_command "Bridge ${BR_NAME} has correct IP ${BR_IP}" || ((FAIL_COUNT++))
else
    echo "FAIL: Bridge ${BR_NAME} does not have correct IP ${BR_IP}"
    ((FAIL_COUNT++))
fi

# Check NAT rule
if iptables -t nat -C POSTROUTING -s ${SUBNET} -o ${HOST_DEFAULT_NETWORK_INTERFACE} -j MASQUERADE &> /dev/null; then
    check_command "NAT rule exists" || ((FAIL_COUNT++))
else
    echo "FAIL: NAT rule does not exist"
    ((FAIL_COUNT++))
fi

# Check IP forwarding
if sysctl net.ipv4.conf.${HOST_DEFAULT_NETWORK_INTERFACE}.forwarding | grep -q "= 1"; then
    check_command "IP forwarding enabled on ${HOST_DEFAULT_NETWORK_INTERFACE}" || ((FAIL_COUNT++))
else
    echo "FAIL: IP forwarding not enabled on ${HOST_DEFAULT_NETWORK_INTERFACE}"
    ((FAIL_COUNT++))
fi

if sysctl net.ipv4.conf.${BR_NAME}.forwarding | grep -q "= 1"; then
    check_command "IP forwarding enabled on ${BR_NAME}" || ((FAIL_COUNT++))
else
    echo "FAIL: IP forwarding not enabled on ${BR_NAME}"
    ((FAIL_COUNT++))
fi

# Check tap0 interface
if ip link show tap0 &> /dev/null; then
    check_command "tap0 interface exists" || ((FAIL_COUNT++))
else
    echo "FAIL: tap0 interface does not exist"
    ((FAIL_COUNT++))
fi

# Check if tap0 is part of the bridge
if ip link show tap0 | grep -q "master ${BR_NAME}"; then
    check_command "tap0 is part of bridge ${BR_NAME}" || ((FAIL_COUNT++))
else
    echo "FAIL: tap0 is not part of bridge ${BR_NAME}"
    ((FAIL_COUNT++))
fi

# Check if tap0 is up
check_interface_state tap0 || ((FAIL_COUNT++))

# Check FORWARD rules
if iptables -C FORWARD -s ${SUBNET} -j ACCEPT &> /dev/null; then
    check_command "FORWARD rule for source ${SUBNET} exists" || ((FAIL_COUNT++))
else
    echo "FAIL: FORWARD rule for source ${SUBNET} does not exist"
    ((FAIL_COUNT++))
fi

if iptables -C FORWARD -d ${SUBNET} -j ACCEPT &> /dev/null; then
    check_command "FORWARD rule for destination ${SUBNET} exists" || ((FAIL_COUNT++))
else
    echo "FAIL: FORWARD rule for destination ${SUBNET} does not exist"
    ((FAIL_COUNT++))
fi

# Overall result
echo "------------------------"
if [ ${FAIL_COUNT} -eq 0 ]; then
    echo "Overall: PASS"
else
    echo "Overall: FAIL (${FAIL_COUNT} checks failed)"
fi
