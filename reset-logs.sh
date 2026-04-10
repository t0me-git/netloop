#!/usr/bin/env bash

set -euo pipefail

echo "This will remove:"
echo "  - /root/.local/share/hashcat/hashcat.potfile"
echo "  - /usr/share/responder/Responder.db"
echo "  - /usr/share/responder/logs/*"
read -r -p "Enter Y to continue: " confirm

if [[ "${confirm}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

rm /root/.local/share/hashcat/hashcat.potfile
rm /usr/share/responder/Responder.db
rm -rf /usr/share/responder/logs/*

echo "Reset complete."
