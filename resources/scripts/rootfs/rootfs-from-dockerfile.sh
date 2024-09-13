#!/bin/bash

set -euo pipefail

# Variables
OUTPUT_FOLDER="out"
DOCKER_FILE="resources/scripts/rootfs/Dockerfile"
DOCKER_IMAGE_NAME="ubuntu-firecracker"
DOCKER_CONTAINER_NAME="temp-ubuntu-firecracker"
ROOTFS_TAR=${OUTPUT_FOLDER}/"ubuntu-rootfs.tar.gz"
ROOTFS_DIR=${OUTPUT_FOLDER}/"rootfs"
ROOTFS_EXT4_IMAGE=${OUTPUT_FOLDER}/"ubuntu-ext4.img"
MOUNT_DIR=${OUTPUT_FOLDER}/"mnt"

# Cleanup function
cleanup() {
    echo "Cleaning up..."
        
    # Remove directories
    rm -rf ${ROOTFS_DIR} ${MOUNT_DIR}
    
    # Remove ext4 image
    rm -f ${ROOTFS_TAR}

    # We don't clean up docker images since caching the layers will help future builds.    
    #echo "Rootfs at ${ROOTFS_EXT4_IMAGE} created."
    if [ $? -ne 0 ]; then
        echo "Error occurred. Rootfs at ${ROOTFS_EXT4_IMAGE} may be incomplete or corrupted."
    fi
}

# Set trap to call cleanup function on error or exit
trap cleanup EXIT ERR
mkdir -p ${OUTPUT_FOLDER}

# Main script
docker build -f ${DOCKER_FILE} -t ${DOCKER_IMAGE_NAME} .

docker create --name ${DOCKER_CONTAINER_NAME} ${DOCKER_IMAGE_NAME}
docker export ${DOCKER_CONTAINER_NAME} | gzip > "${ROOTFS_TAR}"
docker rm ${DOCKER_CONTAINER_NAME}

mkdir -p ${ROOTFS_DIR}
tar -xzvf "${ROOTFS_TAR}" -C ${ROOTFS_DIR}
dd if=/dev/zero of=${ROOTFS_EXT4_IMAGE} bs=1M count=1024
mkfs.ext4 -d ${ROOTFS_DIR} ${ROOTFS_EXT4_IMAGE}
