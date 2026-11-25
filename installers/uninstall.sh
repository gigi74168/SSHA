#!/usr/bin/env bash
set -euo pipefail

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

REMOVED=0
for candidate in "/usr/local/bin/ssha" "$HOME/.local/bin/ssha"; do
    if [ -f "$candidate" ]; then
        rm -f "$candidate"
        printf '\033[1;32m[✓]\033[0m Removed: %s\n' "$candidate"
        REMOVED=1
    fi
done

if [ "$REMOVED" -eq 0 ]; then
    printf '\033[1;33m[!]\033[0m No ssha installation found in /usr/local/bin or ~/.local/bin.\n'
fi

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ssha"
if [ "$PURGE" -eq 1 ] && [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    printf '\033[1;32m[✓]\033[0m Vault removed: %s\n' "$CONFIG_DIR"
elif [ -d "$CONFIG_DIR" ]; then
    printf '\033[1;36m[i]\033[0m Your encrypted vault was kept in: %s\n' "$CONFIG_DIR"
    printf '    Run again with --purge to also delete the saved connections.\n'
fi
