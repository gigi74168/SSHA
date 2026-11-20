# Contribuer à `ssha`

Merci pour ton intérêt pour **`ssha`** ! Toute contribution (correction de bug, nouvelle fonctionnalité, amélioration de la documentation ou tests) est la bienvenue.

## Prérequis

- **Rust** stable (`rustup` : https://rustup.rs)
- **Git**

## Démarrer en local

```bash
git clone https://github.com/gigi74168/SSHA.git
cd SSHA
cargo test
cargo run
```

Pour éviter de toucher à ton coffre-fort personnel pendant le développement, utilise un dossier temporaire :

```bash
SSHA_CONFIG_DIR=/tmp/ssha-dev SSHA_NO_UPDATE_CHECK=1 cargo run
```

## Architecture du code

| Fichier | Rôle |
|---|---|
| `src/main.rs` | Point d'entrée, dispatch CLI / TUI, boucle principale |
| `src/cli.rs` | Sous-commandes directes (`new`, `list`, `files`, `get`, `put`, `export`, `import`, `import-ssh`, `security`, `update`, `info`) |
| `src/tui.rs` | Interface interactive principale (`ratatui`), recherche live, autocomplétion `Tab`, statut `UP`/`DOWN` |
| `src/files_tui.rs` | Explorateur de fichiers distant SFTP 100 % CLI |
| `src/ssh.rs` | Client SSH natif (`russh`), ProxyJump, LocalForward, PTY, TOFU |
| `src/sftp.rs` | Client SFTP natif (`russh-sftp`), transferts récursifs, installation auto de SFTP |
| `src/ssh_config.rs` | Parseur et importateur `~/.ssh/config` (OpenSSH) |
| `src/crypto.rs` | Chiffrement AES-256-GCM (clé auto DPAPI/`0600` + mot de passe maître Argon2id optionnel) |
| `src/storage.rs` | Persistance atomique `vault.enc`, export/import portable, `known_hosts.json` |
| `src/picker.rs` | Boîtes de dialogue natives (Windows PowerShell Forms, macOS `osascript`, Linux `zenity`/`kdialog`) |
| `src/updater.rs` | Détection des releases GitHub et mise à jour atomique (`self-replace`) |

## Bonnes pratiques avant d'ouvrir une Pull Request

1. Vérifie que le code compile sans avertissement :
   ```bash
   cargo check --all-targets
   ```
2. Lance l'ensemble des tests unitaires et d'intégration :
   ```bash
   cargo test
   ```
3. Formate le code avec `cargo fmt`.
4. Assure-toi que les modifications restent compatibles **Windows 10/11**, **Linux** et **macOS** (la CI vérifie automatiquement les 3 OS).
5. Décris clairement le changement et le cas d'usage dans ta Pull Request.

## Signaler un bug ou proposer une idée

Ouvre une [Issue GitHub](https://github.com/gigi74168/SSHA/issues) en précisant ton OS, ta version (`ssha --version`) et les étapes pour reproduire le problème.
