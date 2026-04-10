#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "This will remove:"
echo "  - /root/.local/share/hashcat/hashcat.potfile"
echo "  - /usr/share/responder/Responder.db"
echo "  - /usr/share/responder/logs/*"
echo "  - ${SCRIPT_DIR}/netloop_runs/"
echo "  - ${SCRIPT_DIR}/.netloop_config.json"
read -r -p "Enter Y to continue: " confirm

if [[ "${confirm}" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

rm -f /root/.local/share/hashcat/hashcat.potfile
rm -f /usr/share/responder/Responder.db
rm -rf /usr/share/responder/logs/*
rm -rf "${SCRIPT_DIR}/netloop_runs"
rm -f "${SCRIPT_DIR}/.netloop_config.json"

echo "Reset complete."
