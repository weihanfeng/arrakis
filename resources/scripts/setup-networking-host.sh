#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Save iptables rules
iptables-save > iptables-backup-$(date +%Y%m%d%H%M%S).rules

# Set variables
BR_NAME="br0"
BR_IP="10.20.1.1/24"
SUBNET="10.20.1.0/24"
HOST_DEFAULT_NETWORK_INTERFACE=$(ip r | grep default | awk '{print $5}')

# Setup bridge and firewall rules.
ip l add ${BR_NAME} type bridge
ip l set ${BR_NAME} up
ip a add ${BR_IP} dev ${BR_NAME} scope host
iptables -t nat -A POSTROUTING -s ${SUBNET} -o ${HOST_DEFAULT_NETWORK_INTERFACE} -j MASQUERADE
sysctl -w net.ipv4.conf.${HOST_DEFAULT_NETWORK_INTERFACE}.forwarding=1
sysctl -w net.ipv4.conf.${BR_NAME}.forwarding=1
ip tuntap add dev tap0 mode tap
ip l set dev tap0 master ${BR_NAME}
ip l set tap0 up
iptables -t filter -I FORWARD -s ${SUBNET} -j ACCEPT
iptables -t filter -I FORWARD -d ${SUBNET} -j ACCEPT
