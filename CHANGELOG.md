# Changelog

All notable changes to **`ssha`** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

Translations: [Français](CHANGELOG.fr.md) · [Русский](CHANGELOG.ru.md) · [Українська](CHANGELOG.uk.md) · [Español](CHANGELOG.es.md) · [Italiano](CHANGELOG.it.md)

## [0.10.0] — 2026-11-24
### Added
- **Live CPU/RAM monitoring** next to each machine in the list (`CPU 34% · RAM 71% (2.8/4 GB)`, refreshed every 2 s, green / yellow / red depending on load).
  - Enabled per machine: `Monitor CPU/RAM` checkbox in the form, `Ctrl+P` or `/monitor [name]` in the interface, `ssha new --monitor` on the command line.
  - Linux machines (reads `/proc`); other systems show `n/a`. `SSHA_NO_MONITOR=1` turns it off globally.
- **6 interface languages**: English, Français, Русский, Українська, Español, Italiano.
  - Language picker on first start, pre-selected on the system language.
  - Change it any time with `/lang`, `ssha lang <code>` or the `SSHA_LANG` environment variable.
  - `ssha --help` is translated too.
- **Release notes in the updater**: the update prompt now lists the new features ✨ and fixes 🐛 of every version you are about to get, in your language.
- **"What's new" screen** shown once on the first launch after an update, plus `ssha changelog` and `/changelog` to see it again.
### Fixed
- Background SSH connections can no longer print text or ask questions on top of the interface (silent host key check; a changed key is refused and shown as `⚠ key`).
### Changed
- Repository, documentation and installers are now in English; the changelog is available in the 6 languages.
- GitHub releases now use the matching `CHANGELOG.md` section as their description.

## [0.9.0] — 2026-11-20
### Added
- **Full macOS support** (Apple Silicon `aarch64` & Intel `x86_64`): prebuilt binaries in GitHub Releases, automatic detection in `install.sh`, Mach-O auto-updater, native Finder dialogs (`osascript`), and CI on `macos-latest`.
- **OpenSSH import from `~/.ssh/config`**: new `ssha import-ssh [path]` command and `/import-ssh` in the interface (handles `Host`, `HostName`, `Port`, `User`, multiple `IdentityFile`, `ProxyJump`, `LocalForward`, `ForwardAgent`).
- **Advanced SSH options**:
  - **ProxyJump / Bastion** (`-J` / `--proxy-jump` or imported from `~/.ssh/config`) with chained jumps.
  - **Local port forwarding** (`-L local_port:remote_host:remote_port`, repeatable).
  - **Multi-key fallback** (multiple `IdentityFile`).
- **Optional master password mode** (`ssha security enable-master-password` / `disable-master-password` / `status`) based on **Argon2id + AES-256-GCM** for a 100% portable `vault.enc` between machines, while keeping the password-less automatic key mode by default.
- **Documentation & community**: `CHANGELOG.md`, `CONTRIBUTING.md`, GitHub/CI/Release/License badges in `README.md`, GitHub description and topics.

## [0.8.0] — 2026-11-20
### Added
- **Machine name autocompletion**: suggestion popup above the input bar as soon as you type the first letters (and after `/files `, `/connect `, `/edit `, `/del `, `/test `), completion with **`Tab`**, `↑`/`↓` navigation and greyed inline preview.

## [0.7.0] — 2026-11-20
### Added
- **Full configuration import / export** (`ssha export` / `ssha import` and `/export` / `/import`) including IPs, ports, users, passwords, keys, groups and notes.
- **Native file and folder picker windows** (Windows Explorer, Linux `zenity`/`kdialog`, CLI fallback when headless) to upload and download files and folders recursively in both directions.

## [0.6.0] — 2026-11-20
### Added
- **Automatic SFTP detection and installation** on remote Linux machines on the first SFTP connection (`apt`, `pacman`, `dnf`, `yum`, `apk`, `zypper`, `opkg` + enabling `Subsystem sftp internal-sftp` and reloading `sshd`).

## [0.5.0] — 2026-11-20
### Added
- **Real-time `UP` / `DOWN` status** next to each IP + green / red **`●`** indicator on the far right (non-blocking parallel TCP check at startup, refreshed every 15 s or with `Ctrl+R` / `F5` / `/refresh`), also available in `ssha list`.

## [0.4.0] — 2026-11-20
### Added
- **Automatic GitHub update detection** at startup with an in-terminal prompt (`[Y/n]`) and atomic replacement of the executable via `self-replace` (Windows & Linux), plus the `ssha update` command.

## [0.3.1] — 2026-11-19
### Fixed
- Support for **AltGr** keys (`\`, `~`, `@`, `[`, `]`) on Windows AZERTY keyboards in the SFTP dialogs.
- Automatic cleanup of quotes copied from Windows Explorer (`"C:\..."`) and of the PowerShell `& '...'` prefix.
- `~` expansion on remote SFTP paths and full display of error causes.

## [0.3.0] — 2026-11-19
### Added
- **Built-in remote SFTP file manager** (`Ctrl+F`, `/files`, `ssha files`): browsing, scrollable text preview, recursive download (`Ctrl+D` / `ssha get`), recursive upload (`Ctrl+U` / `ssha put`), folder creation, renaming and recursive deletion.

## [0.2.0] — 2026-11-19
### Changed
- Renamed the command and package from `ssh-a` to **`ssha`**.

## [0.1.0] — 2026-11-19
### Added
- First public release: 100% CLI/TUI interface in Rust (`ratatui`), native SSH client (`russh`), automatic AES-256-GCM encrypted vault (Windows DPAPI / Linux `0600`), Windows & Linux installers, GitHub Actions CI/CD.
