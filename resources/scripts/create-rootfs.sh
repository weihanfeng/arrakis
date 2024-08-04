#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Variables
INPUT_TAR="latest.tar"
OUTPUT_IMG="ext4.img"
MOUNT_DIR="/mnt/ext4_tmp"
IMG_SIZE_MB=300  # Replace with the desired size in MB

# Create an empty file for the ext4 image
dd if=/dev/zero of=$OUTPUT_IMG bs=1M count=$IMG_SIZE_MB

# Format the file as ext4
mkfs.ext4 $OUTPUT_IMG

# Create a temporary mount point
mkdir -p $MOUNT_DIR

# Mount the ext4 image
sudo mount -o loop $OUTPUT_IMG $MOUNT_DIR

# Extract the tar archive into the mounted directory
sudo tar -xf $INPUT_TAR -C $MOUNT_DIR

# Unmount the directory
sudo umount $MOUNT_DIR

# Remove the temporary mount point
rmdir $MOUNT_DIR
