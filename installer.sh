#!/bin/bash
set -e

echo "[*] Installing Stego-Darshan..."

# Install dependencies via apt
sudo apt update
sudo apt install -y python3-pil python3-cryptography

# Copy script to /usr/bin
sudo cp stego-darshan.py /usr/bin/stego-darshan
sudo chmod +x /usr/bin/stego-darshan

echo "[+] Installation complete!"
echo "Now you can run the tool from anywhere with:"
echo "    stego-darshan --help"
echo "Follow me on instagram @indgaming_262"
