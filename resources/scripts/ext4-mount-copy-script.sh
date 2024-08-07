#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Treat unset variables as an error when substituting.
set -u

# Function to clean up mount point
cleanup() {
    if mountpoint -q "$mount_point"; then
        sudo umount "$mount_point"
    fi
    rmdir "$mount_point"
}

# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <ext4_image_path> <source_file_path> <destination_file_path>" >&2
    exit 1
fi

# Assign arguments to variables
ext4_image="$1"
source_file="$2"
destination_file="$3"

# Create a temporary mount point
mount_point=$(mktemp -d)

# Ensure cleanup happens on script exit
trap cleanup EXIT

# Mount the ext4 image
sudo mount -o loop "$ext4_image" "$mount_point"

# Copy the file
sudo cp "$source_file" "$mount_point/$destination_file"

echo "File copied successfully."
