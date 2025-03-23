#!/usr/bin/env bash
set -euo pipefail

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Define variables
ARRAKIS_DIR="./arrakis-prebuilt"
LATEST_RELEASE_URL="https://github.com/abshkbh/arrakis/releases/latest"
RESOURCES_DIR="$ARRAKIS_DIR/resources"
OUT_DIR="$RESOURCES_DIR/bin"
CONFIG_FILE="$ARRAKIS_DIR/config.yaml"
INSTALL_IMAGES_SCRIPT="$ARRAKIS_DIR/install-images.py"

# Print colored message
print_message() {
  echo -e "${GREEN}[Arrakis Setup]${NC} $1"
}

print_warning() {
  echo -e "${YELLOW}[Warning]${NC} $1"
}

# Function to download a file
download_file() {
  local url="$1"
  local destination="$2"
  local description="$3"

  print_message "Downloading $description from $url..."
  curl -L -o "$destination" "$url"

  if [ $? -eq 0 ]; then
    print_message "$description downloaded successfully to $destination"
  else
    print_warning "Failed to download $description. Please check the URL and try again."
    exit 1
  fi
}

# Function to make a file executable
make_executable() {
  local file="$1"
  chmod +x "$file"
  print_message "Made $file executable"
}

# Create arrakis-prebuilt directory
print_message "Creating Arrakis directory structure..."
mkdir -p "$ARRAKIS_DIR"
mkdir -p "$RESOURCES_DIR"
mkdir -p "$OUT_DIR"


# Get the latest release URL
print_message "Determining latest release..."
RELEASE_TAG=$(curl -s -L $LATEST_RELEASE_URL | grep -o "tag/release-[0-9]*" | head -1 | cut -d'/' -f2)

if [ -z "$RELEASE_TAG" ]; then
  print_warning "Could not determine latest release tag. Using 'release-6' as default."
  RELEASE_TAG="release-6"
fi

print_message "Latest release tag: $RELEASE_TAG"
RELEASE_URL="https://github.com/abshkbh/arrakis/releases/download/$RELEASE_TAG"

# Download arrakis-restserver
download_file "$RELEASE_URL/arrakis-restserver" "$ARRAKIS_DIR/arrakis-restserver" "Arrakis REST Server"
make_executable "$ARRAKIS_DIR/arrakis-restserver"

# Download arrakis-client
download_file "$RELEASE_URL/arrakis-client" "$ARRAKIS_DIR/arrakis-client" "Arrakis Client"
make_executable "$ARRAKIS_DIR/arrakis-client"

# Download config.yaml
download_file "$RELEASE_URL/config.yaml" "$CONFIG_FILE" "Configuration file"


# Download install-images.py
print_message "Downloading install-images.py script..."
curl -L -o "$INSTALL_IMAGES_SCRIPT" "https://raw.githubusercontent.com/abshkbh/arrakis/main/setup/install-images.py"
chmod +x "$INSTALL_IMAGES_SCRIPT"

# Run install-images.py to download required images
print_message "Running install-images.py to download required images..."
cd "$ARRAKIS_DIR" && ./$(basename "$INSTALL_IMAGES_SCRIPT")

print_message "Setup completed successfully!"
print_message "You can now run the Arrakis REST server with:"
print_message "cd "$ARRAKIS_DIR" && ./arrakis-restserver"
print_message "And use the client with:"
print_message "cd "$ARRAKIS_DIR" && ./arrakis-client"
