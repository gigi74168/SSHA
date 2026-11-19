#!/usr/bin/env bash
set -euo pipefail

REPO="gigi74168/SSHA"
BIN_NAME="ssha"

info()  { printf '\033[1;36m[ssha]\033[0m %s\n' "$*"; }
ok()    { printf '\033[1;32m[✓]\033[0m %s\n' "$*"; }
warn()  { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[✗]\033[0m %s\n' "$*" >&2; exit 1; }

# Determine install destination
if [ -n "${SSHA_INSTALL_DIR:-}" ]; then
    INSTALL_DIR="$SSHA_INSTALL_DIR"
elif [ "$(id -u)" -eq 0 ] || [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
fi

mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/$BIN_NAME"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
REPO_ROOT=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/../Cargo.toml" ]; then
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [ -f "./Cargo.toml" ] && grep -q 'name = "ssha"' ./Cargo.toml 2>/dev/null; then
    REPO_ROOT="$(pwd)"
fi

install_from_local_build() {
    command -v cargo >/dev/null 2>&1 || error "Rust/Cargo n'est pas installé. Installe-le via https://rustup.rs puis relance ce script."
    info "Compilation de ssha en mode release depuis $REPO_ROOT..."
    (cd "$REPO_ROOT" && cargo build --release)
    cp "$REPO_ROOT/target/release/$BIN_NAME" "$DEST"
    chmod 755 "$DEST"
}

install_from_release() {
    ARCH="$(uname -m)"
    case "$ARCH" in
        x86_64|amd64) ASSET="ssha-linux-x86_64" ;;
        aarch64|arm64) ASSET="ssha-linux-aarch64" ;;
        *) error "Architecture non supportée pour les binaires précompilés : $ARCH. Compile depuis les sources avec cargo." ;;
    esac

    URL="https://github.com/$REPO/releases/latest/download/$ASSET"
    info "Téléchargement de $ASSET depuis GitHub Releases..."
    TMP_FILE="$(mktemp)"
    trap 'rm -f "$TMP_FILE"' EXIT

    if command -v curl >/dev/null 2>&1; then
        if ! curl -fsSL "$URL" -o "$TMP_FILE"; then
            return 1
        fi
    elif command -v wget >/dev/null 2>&1; then
        if ! wget -qO "$TMP_FILE" "$URL"; then
            return 1
        fi
    else
        error "curl ou wget est requis pour télécharger le binaire."
    fi

    mv "$TMP_FILE" "$DEST"
    chmod 755 "$DEST"
    trap - EXIT
    return 0
}

if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/target/release/$BIN_NAME" ] && [ "${SSHA_REBUILD:-0}" != "1" ]; then
    info "Installation du binaire déjà compilé ($REPO_ROOT/target/release/$BIN_NAME)..."
    cp "$REPO_ROOT/target/release/$BIN_NAME" "$DEST"
    chmod 755 "$DEST"
elif [ -n "$REPO_ROOT" ] && command -v cargo >/dev/null 2>&1; then
    install_from_local_build
else
    if ! install_from_release; then
        if [ -n "$REPO_ROOT" ]; then
            warn "Aucune release précompilée trouvée, compilation locale..."
            install_from_local_build
        else
            error "Aucune release précompilée disponible pour l'instant. Clone le dépôt https://github.com/$REPO et lance ./installers/install.sh avec Cargo installé."
        fi
    fi
fi

# Ensure INSTALL_DIR is in PATH for future shells
add_to_path_file() {
    local rc_file="$1"
    local line="$2"
    if [ -f "$rc_file" ] && ! grep -Fq "$INSTALL_DIR" "$rc_file"; then
        printf '\n# Ajouté par l'\''installateur ssha\n%s\n' "$line" >> "$rc_file"
        info "PATH mis à jour dans $rc_file"
    fi
}

case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        add_to_path_file "$HOME/.bashrc" "export PATH=\"$INSTALL_DIR:\$PATH\""
        add_to_path_file "$HOME/.zshrc" "export PATH=\"$INSTALL_DIR:\$PATH\""
        if [ -d "$HOME/.config/fish" ]; then
            FISH_CFG="$HOME/.config/fish/config.fish"
            touch "$FISH_CFG"
            add_to_path_file "$FISH_CFG" "fish_add_path $INSTALL_DIR"
        fi
        warn "Ouvre un nouveau terminal (ou exécute: export PATH=\"$INSTALL_DIR:\$PATH\") pour utiliser 'ssha' partout."
        ;;
esac

ok "ssha est installé dans : $DEST"
ok "Tu peux maintenant lancer simplement : ssha"
