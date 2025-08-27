#!/bin/bash
set -e

echo "[*] Uninstalling Stego-Darshan..."

# Remove installed binary
if [ -f /usr/bin/stego-darshan ]; then
    sudo rm /usr/bin/stego-darshan
    echo "[+] Removed /usr/bin/stego-darshan"
else
    echo "[!] stego-darshan not found in /usr/bin"
fi

echo "[+] Uninstallation complete!"
echo "Follow me on instagram @indgaming_262"