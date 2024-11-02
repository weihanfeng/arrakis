#!/bin/bash

set -euo pipefail

# Variables
OUTPUT_FOLDER="out"
DOCKER_FILE="resources/scripts/rootfs/Dockerfile"
DOCKER_IMAGE_NAME="ubuntu-firecracker"
DOCKER_CONTAINER_NAME="temp-ubuntu-firecracker"
ROOTFS_TAR=${OUTPUT_FOLDER}/"ubuntu-rootfs.tar"
ROOTFS_DIR=${OUTPUT_FOLDER}/"rootfs"
ROOTFS_EXT4_IMAGE=${OUTPUT_FOLDER}/"ubuntu-ext4.img"
MOUNT_DIR="/tmp/mnt"
DISK_SIZE_IN_MB=2048

# Cleanup function
cleanup() {
    echo "Cleaning up..."
        
    # Remove directories
    rm -rf ${ROOTFS_DIR} ${MOUNT_DIR}
    
    # Remove intermediate files
    rm -f ${ROOTFS_TAR}
}

# Set trap to call cleanup function on error or exit
trap cleanup EXIT ERR
mkdir -p ${OUTPUT_FOLDER}

# Main script
docker build -f ${DOCKER_FILE} -t ${DOCKER_IMAGE_NAME} .

docker create --name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE_NAME}
docker export --output=${ROOTFS_TAR} ${DOCKER_CONTAINER_NAME}
docker rm ${DOCKER_CONTAINER_NAME}

dd if=/dev/zero of=${ROOTFS_EXT4_IMAGE} bs=1M count=${DISK_SIZE_IN_MB}
mkfs.ext4 ${ROOTFS_EXT4_IMAGE}
mkdir -p ${MOUNT_DIR}
# TODO: This requires root. Can be done without root mkfs.ext4 -D but that doesn't preserve
# /usr/bin/sudo permissions.
mount -o loop ${ROOTFS_EXT4_IMAGE} ${MOUNT_DIR}
tar -xvf "${ROOTFS_TAR}" -C ${MOUNT_DIR}
umount ${MOUNT_DIR}
