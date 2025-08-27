#!/bin/bash
set -e

echo "[*] Installing Stego-Darshan..."


sudo apt update
sudo apt install -y python3-pil python3-cryptography


sudo cp stego-darshan.py /usr/bin/stego-darshan
sudo chmod +x /usr/bin/stego-darshan
sudo chmod +x uninstaller.sh


echo "[+] Installation complete!"
echo "Now you can run the tool from anywhere with:"
echo "    stego-darshan --help"
echo "Follow me on instagram @indgaming_262"
