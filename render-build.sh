#!/usr/bin/env bash
set -e

echo "🔽 Installing Nuclei..."

NUCLEI_VERSION="3.7.0"
BIN_DIR="bin"

mkdir -p $BIN_DIR
cd $BIN_DIR

# Download Linux binary (Render runs Linux)
curl -L -o nuclei.zip \
  https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_3.7.0_linux_amd64.zip

# Extract
unzip nuclei.zip
rm nuclei.zip

# Make executable
chmod +x nuclei

echo "✅ Nuclei installed at $(pwd)/nuclei"

# Optional: download templates once
echo "📦 Downloading Nuclei templates..."
./nuclei -update-templates

echo "🚀 Build complete"
