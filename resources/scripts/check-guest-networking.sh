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

# Variables
GUEST_IP="10.20.1.2/24"
GATEWAY_IP="10.20.1.1"
IFNAME="eth0"
NAMESERVER="8.8.8.8"
FAIL_COUNT=0

echo "Starting guest network diagnostics..."

# Check if busybox exists
if [ -f ./busybox ]; then
    check_command "busybox exists" || ((FAIL_COUNT++))
else
    echo "FAIL: busybox not found in the current directory"
    ((FAIL_COUNT++))
fi

# Check if the interface exists
if ./busybox ip link show ${IFNAME} &> /dev/null; then
    check_command "Interface ${IFNAME} exists" || ((FAIL_COUNT++))
else
    echo "FAIL: Interface ${IFNAME} does not exist"
    ((FAIL_COUNT++))
fi

# Check if the IP address is correctly set
if ./busybox ip addr show ${IFNAME} | ./busybox grep -q ${GUEST_IP}; then
    check_command "IP address ${GUEST_IP} is set on ${IFNAME}" || ((FAIL_COUNT++))
else
    echo "FAIL: IP address ${GUEST_IP} is not set on ${IFNAME}"
    ((FAIL_COUNT++))
fi

# Check if the interface is up
if ./busybox ip link show ${IFNAME} | ./busybox grep -q "UP"; then
    check_command "Interface ${IFNAME} is UP" || ((FAIL_COUNT++))
else
    echo "FAIL: Interface ${IFNAME} is not UP"
    ((FAIL_COUNT++))
fi

# Check if the default route is set correctly
if ./busybox ip route | ./busybox grep -q "default via ${GATEWAY_IP} dev ${IFNAME}"; then
    check_command "Default route is set correctly" || ((FAIL_COUNT++))
else
    echo "FAIL: Default route is not set correctly"
    ((FAIL_COUNT++))
fi

# Check if /etc/resolv.conf has the correct nameserver entry
if ./busybox grep -q "nameserver ${NAMESERVER}" /etc/resolv.conf; then
    check_command "Nameserver ${NAMESERVER} is set in /etc/resolv.conf" || ((FAIL_COUNT++))
else
    echo "FAIL: Nameserver ${NAMESERVER} is not set in /etc/resolv.conf"
    ((FAIL_COUNT++))
fi

# Overall result
echo "------------------------"
if [ ${FAIL_COUNT} -eq 0 ]; then
    echo "Overall: PASS"
else
    echo "Overall: FAIL (${FAIL_COUNT} checks failed)"
fi
