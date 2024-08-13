#!/bin/bash

set -euo pipefail

# Variables
OUTPUT_FOLDER="out"
DOCKER_IMAGE_NAME="ubuntu-firecracker"
DOCKER_CONTAINER_NAME="temp-ubuntu-firecracker"
ROOTFS_TAR=${OUTPUT_FOLDER}/"ubuntu-rootfs.tar.gz"
ROOTFS_DIR=${OUTPUT_FOLDER}/"rootfs"
ROOTFS_EXT4_IMAGE=${OUTPUT_FOLDER}/"ubuntu-ext4.img"
MOUNT_DIR=${OUTPUT_FOLDER}/"mnt"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
    
    # Unmount if mounted
    if mountpoint -q ${MOUNT_DIR} 2>/dev/null; then
        umount ${MOUNT_DIR}
    fi
    
    # Remove directories
    rm -rf ${ROOTFS_DIR} ${MOUNT_DIR}
    
    # Remove ext4 image
    rm -f ${ROOTFS_TAR}
    
    # Remove Docker image and container
    docker rm -f ${DOCKER_CONTAINER_NAME} 2>/dev/null || true
    docker rmi ${DOCKER_IMAGE_NAME} 2>/dev/null || true
    
    echo "Rootfs at ${ROOTFS_EXT4_IMAGE} created."
}

# Set trap to call cleanup function on error or exit
trap cleanup EXIT ERR
mkdir ${OUTPUT_FOLDER}

# Main script
docker build -t ${DOCKER_IMAGE_NAME} .

docker create --name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE_NAME}
docker export ${DOCKER_CONTAINER_NAME} | gzip > "${ROOTFS_TAR}"
docker rm ${DOCKER_CONTAINER_NAME}

mkdir -p ${ROOTFS_DIR}
tar -xzvf "${ROOTFS_TAR}" -C ${ROOTFS_DIR}

dd if=/dev/zero of=${ROOTFS_EXT4_IMAGE} bs=1M count=1024
mkfs.ext4 ${ROOTFS_EXT4_IMAGE}
mkdir -p ${MOUNT_DIR}
mount ${ROOTFS_EXT4_IMAGE} ${MOUNT_DIR}

cp -r ${ROOTFS_DIR}/* ${MOUNT_DIR}/

umount ${MOUNT_DIR}
