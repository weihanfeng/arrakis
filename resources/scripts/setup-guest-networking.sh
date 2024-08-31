#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -eu

GUEST_IP=10.20.1.2/24
GATEWAY_IP=10.20.1.1
IFNAME=eth0
./busybox ip a add ${GUEST_IP} dev ${IFNAME}
./busybox ip l set ${IFNAME} up
./busybox ip r add default via ${GATEWAY_IP} dev ${IFNAME}

echo "nameserver 8.8.8.8" >> /etc/resolv.conf
