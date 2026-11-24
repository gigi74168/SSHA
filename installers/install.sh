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
    command -v cargo >/dev/null 2>&1 || error "Rust/Cargo is not installed. Install it from https://rustup.rs then run this script again."
    info "Compilation de ssha en mode release depuis $REPO_ROOT..."
    (cd "$REPO_ROOT" && cargo build --release)
    cp "$REPO_ROOT/target/release/$BIN_NAME" "$DEST"
    chmod 755 "$DEST"
}

install_from_release() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"
    case "$OS" in
        Linux)
            case "$ARCH" in
                x86_64|amd64) ASSET="ssha-linux-x86_64" ;;
                aarch64|arm64) ASSET="ssha-linux-aarch64" ;;
                *) error "Unsupported Linux architecture: $ARCH. Build from source with cargo." ;;
            esac
            ;;
        Darwin)
            case "$ARCH" in
                arm64|aarch64) ASSET="ssha-macos-aarch64" ;;
                x86_64) ASSET="ssha-macos-x86_64" ;;
                *) error "Unsupported macOS architecture: $ARCH. Build from source with cargo." ;;
            esac
            ;;
        *) error "System not supported by this script: $OS." ;;
    esac

    URL="https://github.com/$REPO/releases/latest/download/$ASSET"
    info "Downloading $ASSET from GitHub Releases..."
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
        error "curl or wget is required to download the binary."
    fi

    mv "$TMP_FILE" "$DEST"
    chmod 755 "$DEST"
    trap - EXIT
    return 0
}

if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/target/release/$BIN_NAME" ] && [ "${SSHA_REBUILD:-0}" != "1" ]; then
    info "Installing the already built binary ($REPO_ROOT/target/release/$BIN_NAME)..."
    cp "$REPO_ROOT/target/release/$BIN_NAME" "$DEST"
    chmod 755 "$DEST"
elif [ -n "$REPO_ROOT" ] && command -v cargo >/dev/null 2>&1; then
    install_from_local_build
else
    if ! install_from_release; then
        if [ -n "$REPO_ROOT" ]; then
            warn "No prebuilt release found, building locally..."
            install_from_local_build
        else
            error "No prebuilt release available yet. Clone https://github.com/$REPO and run ./installers/install.sh with Cargo installed."
        fi
    fi
fi

# Ensure INSTALL_DIR is in PATH for future shells
add_to_path_file() {
    local rc_file="$1"
    local line="$2"
    if [ -f "$rc_file" ] && ! grep -Fq "$INSTALL_DIR" "$rc_file"; then
        printf '\n# Added by the ssha installer\n%s\n' "$line" >> "$rc_file"
        info "PATH updated in $rc_file"
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
        warn "Open a new terminal (or run: export PATH=\"$INSTALL_DIR:\$PATH\") to use 'ssha' everywhere."
        ;;
esac

ok "ssha is installed in: $DEST"
ok "You can now simply run: ssha"
