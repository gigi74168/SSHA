#!/usr/bin/env bash
set -euo pipefail

PURGE=0
if [ "${1:-}" = "--purge" ]; then
    PURGE=1
fi

REMOVED=0
for candidate in "/usr/local/bin/ssh-a" "$HOME/.local/bin/ssh-a"; do
    if [ -f "$candidate" ]; then
        rm -f "$candidate"
        printf '\033[1;32m[✓]\033[0m Supprimé : %s\n' "$candidate"
        REMOVED=1
    fi
done

if [ "$REMOVED" -eq 0 ]; then
    printf '\033[1;33m[!]\033[0m Aucune installation de ssh-a trouvée dans /usr/local/bin ou ~/.local/bin.\n'
fi

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/ssh-a"
if [ "$PURGE" -eq 1 ] && [ -d "$CONFIG_DIR" ]; then
    rm -rf "$CONFIG_DIR"
    printf '\033[1;32m[✓]\033[0m Coffre-fort supprimé : %s\n' "$CONFIG_DIR"
elif [ -d "$CONFIG_DIR" ]; then
    printf '\033[1;36m[i]\033[0m Ton coffre-fort chiffré a été conservé dans : %s\n' "$CONFIG_DIR"
    printf '    Relance avec --purge pour supprimer aussi les connexions enregistrées.\n'
fi
