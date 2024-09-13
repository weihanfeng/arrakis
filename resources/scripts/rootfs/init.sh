#!/bin/bash

mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
trap "exit" INT TERM
trap "kill 0" EXIT

./opt/custom_scripts/setup-guest-networking.sh
./opt/custom_scripts/check-guest-networking.sh
exec /usr/bin/tini -- /bin/bash
